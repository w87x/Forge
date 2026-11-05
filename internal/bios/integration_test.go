package bios_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"forge/internal/auth"
	"forge/internal/bios"
	"forge/internal/compliance"
	"forge/internal/inspection"
	"forge/internal/inventory"
	"forge/internal/jobs"
	"forge/internal/netbox"
	"forge/internal/profiles"
	"forge/internal/redfish"
	"forge/internal/secrets"
	"forge/internal/store/sqlite"
)

func TestInspectionToPublishedBIOSProfile(t *testing.T) {
	var bmcCalls atomic.Int32
	bmc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bmcCalls.Add(1)
		if r.Method != "GET" {
			t.Errorf("unexpected BMC mutation: %s", r.Method)
			w.WriteHeader(405)
			return
		}
		u, p, ok := r.BasicAuth()
		if !ok || u != "admin" || p != "password" {
			w.WriteHeader(401)
			return
		}
		var body string
		switch r.URL.Path {
		case "/redfish/v1/":
			body = `{"Systems":{"@odata.id":"/redfish/v1/Systems"},"Registries":{"@odata.id":"/redfish/v1/Registries"}}`
		case "/redfish/v1/Systems":
			body = `{"Members":[{"@odata.id":"/redfish/v1/Systems/host"}]}`
		case "/redfish/v1/Systems/host":
			body = `{"Manufacturer":"Vendor","Model":"Model","SerialNumber":"SERIAL","BiosVersion":"1.0","Bios":{"@odata.id":"/redfish/v1/Systems/host/Bios"}}`
		case "/redfish/v1/Systems/host/Bios":
			body = `{"AttributeRegistry":"reg","Attributes":{"Virtualization":"Enabled"}}`
		case "/redfish/v1/Registries":
			body = `{"Members":[{"@odata.id":"/redfish/v1/Registries/reg"}]}`
		case "/redfish/v1/Registries/reg":
			body = `{"Id":"reg","Location":[{"Language":"en","Uri":"/redfish/v1/Registries/reg/file"}]}`
		case "/redfish/v1/Registries/reg/file":
			body = `{"Id":"reg","RegistryEntries":{"Attributes":[{"AttributeName":"Virtualization","Type":"Enumeration"}]}}`
		default:
			w.WriteHeader(404)
			return
		}
		fmt.Fprint(w, body)
	}))
	defer bmc.Close()
	nbServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("unexpected NetBox mutation: %s", r.Method)
		}
		fmt.Fprint(w, `{"count":1,"next":null,"results":[{"id":1,"name":"host","serial":"SERIAL"}]}`)
	}))
	defer nbServer.Close()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a := &auth.Service{DB: db.DB, BootstrapToken: strings.Repeat("x", 32)}
	owner, _, err := a.Bootstrap(ctx, strings.Repeat("x", 32), "owner")
	if err != nil {
		t.Fatal(err)
	}
	env, err := a.CreateEnvironment(ctx, owner, "lab")
	if err != nil {
		t.Fatal(err)
	}
	vault, err := secrets.New(db.DB, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32))))
	if err != nil {
		t.Fatal(err)
	}
	host, _, _ := net.SplitHostPort(nbServer.Listener.Addr().String())
	nb := &netbox.Service{DB: db.DB, Auth: a, Vault: vault, AllowHTTP: true, AllowedHosts: []string{host}, ConnectionsEnabled: true}
	instance, err := nb.CreateInstance(ctx, owner, env.ID, "test", nbServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = nb.SaveCredential(ctx, owner, instance.ID, "netbox-key"); err != nil {
		t.Fatal(err)
	}
	inv := &inventory.Service{DB: db.DB, NetBox: nb}
	snapshot, err := inv.Refresh(ctx, owner, instance.ID, netbox.DeviceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	selection, err := inv.Select(ctx, owner, snapshot.ID, []int64{1})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := vault.Put(ctx, owner, secrets.Scope{EnvironmentID: env.ID}, "bmc", "static", []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	_, portString, _ := net.SplitHostPort(bmc.Listener.Addr().String())
	port, _ := strconv.Atoi(portString)
	ps := &profiles.Service{DB: db.DB, Auth: a, Vault: vault}
	p, err := ps.Create(ctx, owner, auth.SharedWorkspaceID, "connection", profiles.Connection{Driver: "redfish.generic", AddressSource: "explicit", Username: "admin", Port: port, PasswordMode: "static", StaticSecretID: secret.ID})
	if err != nil {
		t.Fatal(err)
	}
	rev, err := ps.Publish(ctx, owner, p.ID, p.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(bmc.Certificate())
	rf := &redfish.Client{Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Roots: pool}
	js := &jobs.Store{DB: db.DB}
	is := &inspection.Service{DB: db.DB, Auth: a, Inventory: inv, NetBox: nb, Profiles: ps, Vault: vault, Jobs: js, Redfish: rf, Enabled: true}
	job, _, err := is.Submit(ctx, owner, "key", inspection.Request{SelectionID: selection.ID, DeviceID: 1, ProfileID: p.ID, Revision: rev.Number, BMCIP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := js.ClaimKind(ctx, "worker", time.Minute, "redfish.inspect")
	if err != nil {
		t.Fatal(err)
	}
	if err = is.RunJob(ctx, claimed, "worker"); err != nil {
		t.Fatal(err)
	}
	if err = js.Complete(ctx, job.ID, "worker", claimed.Generation); err != nil {
		t.Fatal(err)
	}
	service := &bios.Service{DB: db.DB, Auth: a, Inspections: is}
	baseline, err := service.Create(ctx, owner, "reference", job.ID, []string{"Virtualization"})
	if err != nil {
		t.Fatal(err)
	}
	published, err := service.Publish(ctx, owner, baseline.ID, baseline.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := service.CompareJob(ctx, owner, baseline.ID, published.Number, job.ID)
	if err != nil || comparison.Status != "pass" {
		t.Fatalf("comparison: %+v %v", comparison, err)
	}
	hs := &compliance.Service{DB: db.DB, Inspections: is, Inventory: inv}
	hardware, err := hs.Create(ctx, owner, "serial check", compliance.Hardware{RequireSerial: true})
	if err != nil {
		t.Fatal(err)
	}
	hardwareRevision, err := hs.Publish(ctx, owner, hardware.ID, hardware.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	hardwareResult, err := hs.Preview(ctx, owner, hardware.ID, hardwareRevision.Number, job.ID)
	if err != nil || hardwareResult.Status != "pass" {
		t.Fatalf("hardware compliance: %+v %v", hardwareResult, err)
	}
	before := bmcCalls.Load()
	audit, err := hs.RunAudit(ctx, owner, hardware.ID, hardwareRevision.Number, job.ID)
	if err != nil || audit.Result.Status != "pass" {
		t.Fatalf("save audit: %+v %v", audit, err)
	}
	stored, err := hs.GetAudit(ctx, owner, audit.ID)
	if err != nil || stored.Result.Status != "pass" || stored.Revision != hardwareRevision.Number {
		t.Fatalf("read audit: %+v %v", stored, err)
	}
	if bmcCalls.Load() != before {
		t.Fatal("cached audit reconnected to BMC")
	}
	reader, _, err := a.CreateUser(ctx, owner, "reader", auth.Readonly)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = hs.GetAudit(ctx, reader, audit.ID); err == nil {
		t.Fatal("another user read the audit")
	}
	if _, err = nb.SaveCredential(ctx, owner, instance.ID, "new-netbox-key"); err != nil {
		t.Fatal(err)
	}
	if _, err = hs.GetAudit(ctx, owner, audit.ID); err == nil {
		t.Fatal("revoked visibility still read the audit")
	}
}

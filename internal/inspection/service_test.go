package inspection

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
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
	"forge/internal/inventory"
	"forge/internal/jobs"
	"forge/internal/netbox"
	"forge/internal/profiles"
	"forge/internal/redfish"
	"forge/internal/secrets"
	"forge/internal/store/sqlite"
)

func TestInspectionUsesSelectedIdentityAndCachesEvidence(t *testing.T) {
	var calls atomic.Int32
	bmc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		u, p, ok := r.BasicAuth()
		if !ok || u != "admin" || p != "P1S" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/redfish/v1/":
			fmt.Fprint(w, `{"Systems":{"@odata.id":"/redfish/v1/Systems"}}`)
		case "/redfish/v1/Systems":
			fmt.Fprint(w, `{"Members":[{"@odata.id":"/redfish/v1/Systems/actual"}]}`)
		case "/redfish/v1/Systems/actual":
			fmt.Fprint(w, `{"SerialNumber":"actual-other","Model":"lab"}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer bmc.Close()
	var deny atomic.Bool
	nbServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/dcim/devices/101/" {
			if deny.Load() {
				w.WriteHeader(403)
				return
			}
			fmt.Fprint(w, `{"id":101}`)
			return
		}
		fmt.Fprint(w, `{"count":1,"next":null,"results":[{"id":101,"name":"host1","serial":"declared"}]}`)
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
	now := time.Now()
	inv := &inventory.Service{DB: db.DB, NetBox: nb, Now: func() time.Time { return now }}
	snapshot, err := inv.Refresh(ctx, owner, instance.ID, netbox.DeviceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	selection, err := inv.Select(ctx, owner, snapshot.ID, []int64{101})
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := vault.Put(ctx, owner, secrets.Scope{EnvironmentID: env.ID}, "bmc", "prefix", []byte("P"))
	if err != nil {
		t.Fatal(err)
	}
	suffix, err := vault.Put(ctx, owner, secrets.Scope{EnvironmentID: env.ID}, "bmc", "suffix", []byte("S"))
	if err != nil {
		t.Fatal(err)
	}
	_, portStr, _ := net.SplitHostPort(bmc.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	ps := &profiles.Service{DB: db.DB, Auth: a, Vault: vault}
	p, err := ps.Create(ctx, owner, env.ID, "server", profiles.Connection{Driver: "redfish.generic", AddressSource: "explicit", Username: "admin", Port: port, PasswordMode: "ipv4_octet", PrefixSecretID: prefix.ID, SuffixSecretID: suffix.ID})
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
	jobStore := &jobs.Store{DB: db.DB}
	svc := Service{DB: db.DB, Auth: a, Inventory: inv, NetBox: nb, Profiles: ps, Vault: vault, Jobs: jobStore, Redfish: rf, Enabled: true}
	req := Request{SelectionID: selection.ID, DeviceID: 101, ProfileID: p.ID, Revision: rev.Number, BMCIP: "127.0.0.1"}
	job, created, err := svc.Submit(ctx, owner, "request-1", req)
	if err != nil || !created {
		t.Fatalf("submit: %v", err)
	}
	again, created, err := svc.Submit(ctx, owner, "request-1", req)
	if err != nil || created || again.ID != job.ID {
		t.Fatalf("idempotency: %+v %v", again, err)
	}
	claimed, err := jobStore.ClaimKind(ctx, "test-worker", time.Minute, "redfish.inspect")
	if err != nil {
		t.Fatal(err)
	}
	if err = svc.RunJob(ctx, claimed, "test-worker"); err != nil {
		t.Fatal(err)
	}
	if err = jobStore.Complete(ctx, job.ID, "test-worker", claimed.Generation); err != nil {
		t.Fatal(err)
	}
	record, err := svc.Get(ctx, owner, job.ID)
	if err != nil || record.IdentityStatus != "mismatch" || record.Observed.Serial != "actual-other" || record.Observed.NICCoverage != "unknown" {
		t.Fatalf("record %+v %v", record, err)
	}
	var raw string
	if err = db.DB.QueryRow(`SELECT content_json FROM job_inputs WHERE job_id=?`, job.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "P1S") || strings.Contains(raw, "netbox-key") {
		t.Fatal("credential leaked to job input")
	}
	job2, _, err := svc.Submit(ctx, owner, "request-2", req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = vault.Replace(ctx, owner, prefix.ID, []byte("changed")); err != nil {
		t.Fatal(err)
	}
	claimed, err = jobStore.ClaimKind(ctx, "test-worker", time.Minute, "redfish.inspect")
	if err != nil {
		t.Fatal(err)
	}
	before := calls.Load()
	if err = svc.RunJob(ctx, claimed, "test-worker"); !errors.Is(err, inventory.ErrStale) {
		t.Fatalf("changed secret not rejected: %v", err)
	}
	if calls.Load() != before {
		t.Fatal("stale job connected to BMC")
	}
	if claimed.ID != job2.ID {
		t.Fatal("wrong job claimed")
	}
	now = now.Add(6 * time.Minute)
	before = calls.Load()
	if cached, err := svc.Get(ctx, owner, job.ID); err != nil || cached.ID != record.ID {
		t.Fatalf("cached result after snapshot expiry: %v", err)
	}
	if calls.Load() != before {
		t.Fatal("reading cached evidence contacted BMC")
	}
	deny.Store(true)
	if _, err := svc.Get(ctx, owner, job.ID); !errors.Is(err, netbox.ErrForbidden) {
		t.Fatalf("revoked visibility: %v", err)
	}
}

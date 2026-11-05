package inventory

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"forge/internal/auth"
	"forge/internal/netbox"
	"forge/internal/secrets"
	"forge/internal/store/sqlite"
)

func TestSnapshotsSelectionsAndCredentialScope(t *testing.T) {
	var seenAuth atomic.Value
	var maliciousNext atomic.Bool
	var wrongDevice atomic.Bool
	var interfaceCalls atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/dcim/interfaces/" {
			interfaceCalls.Add(1)
			if r.URL.Query().Get("device_id") != "101" {
				t.Errorf("unexpected interface filter: %s", r.URL.String())
			}
			if wrongDevice.Load() {
				fmt.Fprint(w, `{"count":1,"next":null,"results":[{"id":11,"name":"other","device":{"id":102}}]}`)
				return
			}
			fmt.Fprint(w, `{"count":1,"next":null,"results":[{"id":11,"name":"eth0","device":{"id":101},"type":{"value":"1000base-t"},"primary_mac_address":{"mac_address":"00:11:22:33:44:55"},"lag":{"id":12},"tagged_vlans":[{"id":15}],"cable":{"id":19}}]}`)
			return
		}
		if r.URL.Path != "/api/dcim/devices/" || r.URL.Query().Get("limit") != "50" || r.URL.Query().Get("q") != "host" {
			t.Errorf("unexpected URL %s", r.URL.String())
		}
		seenAuth.Store(r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		if maliciousNext.Load() {
			fmt.Fprint(w, `{"count":2,"next":"https://attacker.invalid/api/dcim/devices/?offset=50","results":[{"id":102,"name":"other"}]}`)
			return
		}
		fmt.Fprint(w, `{"count":1,"next":null,"results":[{"id":101,"name":"host1","serial":"A","site":{"id":7,"name":"DC"},"rack":{"id":8,"name":"R8"},"role":{"name":"compute"},"device_type":{"model":"R1","manufacturer":{"name":"Vendor"}},"status":{"value":"active"}}]}`)
	}))
	defer remote.Close()
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
	reader, _, err := a.CreateUser(ctx, owner, "reader", auth.Readonly)
	if err != nil {
		t.Fatal(err)
	}
	env, err := a.CreateEnvironment(ctx, owner, "lab")
	if err != nil {
		t.Fatal(err)
	}
	if err = a.AddEnvironmentMember(ctx, owner, env.ID, reader.ID); err != nil {
		t.Fatal(err)
	}
	vault, err := secrets.New(db.DB, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32))))
	if err != nil {
		t.Fatal(err)
	}
	host, _, _ := net.SplitHostPort(remote.Listener.Addr().String())
	nb := &netbox.Service{DB: db.DB, Auth: a, Vault: vault, AllowHTTP: true, AllowedHosts: []string{host}, ConnectionsEnabled: true}
	instance, err := nb.CreateInstance(ctx, owner, env.ID, "test", remote.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = nb.SaveCredential(ctx, owner, instance.ID, "owner-key"); err != nil {
		t.Fatal(err)
	}
	if _, err = nb.SaveCredential(ctx, reader, instance.ID, "reader-key"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	svc := Service{DB: db.DB, NetBox: nb, Now: func() time.Time { return now }}
	snap, err := svc.Refresh(ctx, owner, instance.ID, netbox.DeviceFilter{Query: "host"})
	if err != nil {
		t.Fatal(err)
	}
	if seenAuth.Load() != "Token owner-key" || len(snap.Devices) != 1 || snap.Devices[0].ID != 101 || snap.Devices[0].ForgeID == "" || snap.Devices[0].SiteID != 7 || snap.Devices[0].RackID != 8 || snap.Devices[0].Rack != "R8" {
		t.Fatalf("snapshot %+v", snap)
	}
	if _, err = svc.Snapshot(ctx, reader, snap.ID); !errors.Is(err, ErrNotVisible) {
		t.Fatalf("other user read snapshot: %v", err)
	}
	if _, err = svc.Select(ctx, owner, snap.ID, []int64{999}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("selected absent device: %v", err)
	}
	selection, err := svc.Select(ctx, owner, snap.ID, []int64{101})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Selection(ctx, reader, selection.ID); !errors.Is(err, ErrNotVisible) {
		t.Fatalf("other user read selection: %v", err)
	}
	if _, err = svc.Interfaces(ctx, owner, selection.ID, 999, 0); !errors.Is(err, ErrNotVisible) {
		t.Fatalf("unselected interface lookup: %v", err)
	}
	if interfaceCalls.Load() != 0 {
		t.Fatal("unselected device contacted NetBox")
	}
	page, err := svc.Interfaces(ctx, owner, selection.ID, 101, 0)
	if err != nil || len(page.Results) != 1 || page.Results[0].MAC != "00:11:22:33:44:55" || page.Results[0].CableID == nil || *page.Results[0].CableID != 19 || !page.Results[0].CableKnown || page.Results[0].CableState != "occupied" || !page.Results[0].LAGKnown || page.Results[0].ParentKnown || page.Results[0].BridgeKnown {
		t.Fatalf("interface evidence: %+v %v", page, err)
	}
	wrongDevice.Store(true)
	if _, err = svc.Interfaces(ctx, owner, selection.ID, 101, 0); !errors.Is(err, netbox.ErrRemote) {
		t.Fatalf("other device returned: %v", err)
	}
	now = now.Add(6 * time.Minute)
	if _, err = svc.Snapshot(ctx, owner, snap.ID); !errors.Is(err, ErrStale) {
		t.Fatalf("expired snapshot: %v", err)
	}
	now = now.Add(-6 * time.Minute)
	maliciousNext.Store(true)
	if _, err = svc.Refresh(ctx, owner, instance.ID, netbox.DeviceFilter{Query: "host"}); !errors.Is(err, netbox.ErrRemote) {
		t.Fatalf("unsafe pagination accepted: %v", err)
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM servers`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("failed page mutated registry: %d %v", count, err)
	}
	if _, err = nb.SaveCredential(ctx, owner, instance.ID, "rotated-owner-key"); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Snapshot(ctx, owner, snap.ID); !errors.Is(err, ErrStale) {
		t.Fatalf("old snapshot after key rotation: %v", err)
	}
	if _, err = svc.Selection(ctx, owner, selection.ID); !errors.Is(err, ErrStale) {
		t.Fatalf("old selection after key rotation: %v", err)
	}
}

func TestSelectedDeviceAddressesAreScopedAndPaginated(t *testing.T) {
	var malicious atomic.Bool
	var omitVRF atomic.Bool
	var calls atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/dcim/devices/":
			fmt.Fprint(w, `{"count":1,"next":null,"results":[{"id":101,"name":"host1"}]}`)
		case "/api/ipam/ip-addresses/":
			calls.Add(1)
			if r.URL.Query().Get("device_id") != "101" {
				t.Errorf("unexpected filter %s", r.URL.String())
			}
			if malicious.Load() {
				fmt.Fprint(w, `{"count":1,"next":null,"results":[{"id":3,"address":"192.0.2.3/24","assigned_object_type":"dcim.interface","assigned_object_id":9,"assigned_object":{"id":9,"name":"eth0","device":{"id":999}}}]}`)
				return
			}
			if omitVRF.Load() {
				fmt.Fprint(w, `{"count":1,"next":null,"results":[{"id":1,"address":"192.0.2.1/24","assigned_object_type":"dcim.interface","assigned_object_id":9,"assigned_object":{"id":9,"name":"bond0","device":{"id":101}}}]}`)
				return
			}
			if r.URL.Query().Get("offset") == "0" {
				fmt.Fprint(w, `{"count":2,"next":"/api/ipam/ip-addresses/?device_id=101&offset=1&limit=50","results":[{"id":1,"address":"192.0.2.1/24","vrf":{"id":4,"name":"control"},"assigned_object_type":"dcim.interface","assigned_object_id":9,"assigned_object":{"id":9,"name":"bond0","device":{"id":101}}}]}`)
			} else {
				fmt.Fprint(w, `{"count":2,"next":null,"results":[{"id":2,"address":"2001:db8::1/64","vrf":null,"assigned_object_type":"dcim.interface","assigned_object_id":10,"assigned_object":{"id":10,"name":"vlan1","device":{"id":101}}}]}`)
			}
		default:
			w.WriteHeader(404)
		}
	}))
	defer remote.Close()
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
	vault, err := secrets.New(db.DB, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32))))
	if err != nil {
		t.Fatal(err)
	}
	host, _, _ := net.SplitHostPort(remote.Listener.Addr().String())
	nb := &netbox.Service{DB: db.DB, Auth: a, Vault: vault, AllowHTTP: true, AllowedHosts: []string{host}, ConnectionsEnabled: true}
	instance, err := nb.CreateInstance(ctx, owner, auth.SharedWorkspaceID, "test", remote.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = nb.SaveCredential(ctx, owner, instance.ID, "key"); err != nil {
		t.Fatal(err)
	}
	svc := Service{DB: db.DB, NetBox: nb}
	snap, err := svc.Refresh(ctx, owner, instance.ID, netbox.DeviceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	selection, err := svc.Select(ctx, owner, snap.ID, []int64{101})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Addresses(ctx, owner, selection.ID, 999, 0); !errors.Is(err, ErrNotVisible) || calls.Load() != 0 {
		t.Fatalf("unselected lookup: %v", err)
	}
	first, err := svc.Addresses(ctx, owner, selection.ID, 101, 0)
	if err != nil || !first.HasMore || len(first.Results) != 1 || !first.Results[0].VRFKnown || first.Results[0].VRFID == nil || *first.Results[0].VRFID != 4 || first.Results[0].InterfaceID != 9 {
		t.Fatalf("first page: %+v %v", first, err)
	}
	second, err := svc.Addresses(ctx, owner, selection.ID, 101, 1)
	if err != nil || second.HasMore || !second.Results[0].VRFKnown || second.Results[0].VRFID != nil || second.Results[0].Address != "2001:db8::1/64" {
		t.Fatalf("global VRF: %+v %v", second, err)
	}
	omitVRF.Store(true)
	missing, err := svc.Addresses(ctx, owner, selection.ID, 101, 0)
	if err != nil || len(missing.Results) != 1 || missing.Results[0].VRFKnown {
		t.Fatalf("omitted VRF: %+v %v", missing, err)
	}
	time.Sleep(600 * time.Millisecond)
	malicious.Store(true)
	if _, err = svc.Addresses(ctx, owner, selection.ID, 101, 0); !errors.Is(err, netbox.ErrRemote) {
		t.Fatalf("wrong device accepted: %v", err)
	}
}

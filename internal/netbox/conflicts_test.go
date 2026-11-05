package netbox

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"forge/internal/auth"
	"forge/internal/secrets"
	"forge/internal/store/sqlite"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAddressCandidatesBoundedAndFiltered(t *testing.T) {
	var ignored atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ipam/ip-addresses/" || r.Header.Get("Authorization") != "Token key" || r.URL.Query().Get("parent") != "192.0.2.1/32" {
			t.Errorf("unexpected request %s", r.URL.String())
		}
		if ignored.Load() {
			fmt.Fprint(w, `{"count":1,"results":[{"id":2,"address":"192.0.2.2/24","vrf":null}]}`)
			return
		}
		fmt.Fprint(w, `{"count":1,"results":[{"id":1,"address":"192.0.2.1/24","vrf":null,"assigned_object_type":"dcim.interface","assigned_object_id":10}]}`)
	}))
	defer server.Close()
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
	v, err := secrets.New(db.DB, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32))))
	if err != nil {
		t.Fatal(err)
	}
	host, _, _ := net.SplitHostPort(server.Listener.Addr().String())
	svc := Service{DB: db.DB, Auth: a, Vault: v, AllowHTTP: true, AllowedHosts: []string{host}, ConnectionsEnabled: true}
	instance, err := svc.CreateInstance(ctx, owner, auth.SharedWorkspaceID, "nb", server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.SaveCredential(ctx, owner, instance.ID, "key"); err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("192.0.2.1")
	items, err := svc.AddressCandidates(ctx, owner, instance.ID, []netip.Addr{ip})
	if err != nil || len(items) != 1 || !items[0].VRFKnown || items[0].VRFID != nil {
		t.Fatalf("candidates %+v: %v", items, err)
	}
	ignored.Store(true)
	if _, err = svc.AddressCandidates(ctx, owner, instance.ID, []netip.Addr{ip}); !errors.Is(err, ErrRemote) {
		t.Fatalf("ignored filter accepted: %v", err)
	}
	if _, err = svc.AddressCandidates(ctx, owner, instance.ID, []netip.Addr{ip, ip}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate host accepted: %v", err)
	}
}

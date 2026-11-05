package netbox

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

	"forge/internal/auth"
	"forge/internal/secrets"
	"forge/internal/store/sqlite"
)

func TestVRFPickerUsesOwnKeyAndRejectsUnsafePagination(t *testing.T) {
	var unsafe atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/ipam/vrfs/" || r.Header.Get("Authorization") != "Token key" {
			t.Errorf("unexpected request %s", r.URL.String())
		}
		if unsafe.Load() {
			fmt.Fprint(w, `{"count":2,"next":"https://attacker.invalid/api/ipam/vrfs/?offset=1","results":[{"id":1,"name":"ctl"}]}`)
			return
		}
		fmt.Fprint(w, `{"count":2,"next":"/api/ipam/vrfs/?limit=50&offset=1","results":[{"id":1,"name":"ctl","rd":"65000:1"}]}`)
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
	reader, _, err := a.CreateUser(ctx, owner, "reader", auth.Readonly)
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
	if _, err = svc.VRFs(ctx, reader, instance.ID, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("reader used another key: %v", err)
	}
	page, err := svc.VRFs(ctx, owner, instance.ID, 0)
	if err != nil || !page.HasMore || len(page.Results) != 1 || page.Results[0].RD != "65000:1" {
		t.Fatalf("page: %+v %v", page, err)
	}
	unsafe.Store(true)
	if _, err = svc.VRFs(ctx, owner, instance.ID, 0); !errors.Is(err, ErrRemote) {
		t.Fatalf("unsafe pagination: %v", err)
	}
}

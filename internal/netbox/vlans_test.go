package netbox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"forge/internal/auth"
	"forge/internal/secrets"
	"forge/internal/store/sqlite"
)

func TestVLANPickerAndBoundedIDLookup(t *testing.T) {
	var bad atomic.Bool
	var batches atomic.Bool
	var batchCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/ipam/vlans/" || r.Header.Get("Authorization") != "Token key" {
			t.Errorf("unexpected request %s", r.URL.String())
		}
		if len(r.URL.Query()["id"]) > 0 {
			if batches.Load() {
				batchCalls.Add(1)
				ids := r.URL.Query()["id"]
				if len(ids) > DevicePageSize {
					t.Error("oversized batch")
				}
				objects := []map[string]any{}
				for _, raw := range ids {
					id, _ := strconv.Atoi(raw)
					if id != 51 {
						objects = append(objects, map[string]any{"id": id, "vid": id, "name": "vlan"})
					}
				}
				json.NewEncoder(w).Encode(map[string]any{"count": len(objects), "next": nil, "results": objects})
				return
			}
			if bad.Load() {
				fmt.Fprint(w, `{"count":1,"next":null,"results":[{"id":99,"vid":100,"name":"other"}]}`)
			} else {
				fmt.Fprint(w, `{"count":1,"next":null,"results":[{"id":1,"vid":100,"name":"ctl","site":{"name":"DC"}}]}`)
			}
			return
		}
		fmt.Fprint(w, `{"count":2,"next":"/api/ipam/vlans/?q=ctl&limit=50&offset=1","results":[{"id":1,"vid":100,"name":"ctl","scope":{"display":"Site DC"}}]}`)
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
	page, err := svc.VLANs(ctx, owner, instance.ID, "ctl", 0)
	if err != nil || !page.HasMore || page.Results[0].VID != 100 || page.Results[0].Scope != "Site DC" {
		t.Fatalf("picker: %+v %v", page, err)
	}
	page, err = svc.VLANsByID(ctx, owner, instance.ID, []int64{1})
	if err != nil || page.Results[0].Scope != "DC" {
		t.Fatalf("batch: %+v %v", page, err)
	}
	bad.Store(true)
	if _, err = svc.VLANsByID(ctx, owner, instance.ID, []int64{1}); !errors.Is(err, ErrRemote) {
		t.Fatalf("ignored ID filter: %v", err)
	}
	bad.Store(false)
	batches.Store(true)
	ids := make([]int64, 51)
	for i := range ids {
		ids[i] = int64(i + 1)
	}
	items, err := svc.AuditVLANs(ctx, owner, instance.ID, ids)
	if err != nil || len(items) != 50 || batchCalls.Load() != 2 {
		t.Fatalf("bounded batches and hidden ID: %d items, %d calls, %v", len(items), batchCalls.Load(), err)
	}
	ids[50] = ids[0]
	if _, err = svc.AuditVLANs(ctx, owner, instance.ID, ids); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate accepted: %v", err)
	}
}

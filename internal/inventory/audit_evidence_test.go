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
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"forge/internal/auth"
	"forge/internal/netbox"
	"forge/internal/secrets"
	"forge/internal/store/sqlite"
)

func TestAuditInterfaceEvidenceIsBoundedAndRejectsDuplicatePages(t *testing.T) {
	var duplicate atomic.Bool
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/dcim/devices/" {
			fmt.Fprint(w, `{"count":1,"next":null,"results":[{"id":1,"name":"host1"}]}`)
			return
		}
		if r.URL.Path != "/api/dcim/interfaces/" {
			http.NotFound(w, r)
			return
		}
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		id := offset + 1
		if duplicate.Load() && offset == 1 {
			id = 1
		}
		next := "null"
		if offset < 4 {
			next = fmt.Sprintf(`"/api/dcim/interfaces/?device_id=1&limit=50&offset=%d"`, offset+1)
		}
		fmt.Fprintf(w, `{"count":5,"next":%s,"results":[{"id":%d,"name":"eth%d","device":{"id":1}}]}`, next, id, offset)
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
	nb := &netbox.Service{DB: db.DB, Auth: a, Vault: vault, AllowHTTP: true, ConnectionsEnabled: true, AllowedHosts: []string{host}}
	instance, err := nb.CreateInstance(ctx, owner, auth.SharedWorkspaceID, "nb", remote.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = nb.SaveCredential(ctx, owner, instance.ID, "key"); err != nil {
		t.Fatal(err)
	}
	svc := &Service{DB: db.DB, NetBox: nb}
	snap, err := svc.Refresh(ctx, owner, instance.ID, netbox.DeviceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	selection, err := svc.Select(ctx, owner, snap.ID, []int64{1})
	if err != nil {
		t.Fatal(err)
	}
	page, err := svc.AuditInterfaces(ctx, owner, selection.ID, 1)
	if err != nil || len(page.Results) != 4 || !page.HasMore || page.Count != 5 {
		t.Fatalf("bounded page: %+v %v", page, err)
	}
	duplicate.Store(true)
	if _, err = svc.AuditInterfaces(ctx, owner, selection.ID, 1); !errors.Is(err, netbox.ErrRemote) {
		t.Fatalf("duplicate across pages accepted: %v", err)
	}
}

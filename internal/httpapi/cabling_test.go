package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"forge/internal/auth"
	"forge/internal/profiles"
	"forge/internal/store/sqlite"
)

func TestCablingProfileHTTP(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a := &auth.Service{DB: db.DB, BootstrapToken: strings.Repeat("x", 32)}
	_, token, err := a.Bootstrap(ctx, strings.Repeat("x", 32), "owner")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.DB.Exec(`INSERT INTO netbox_instances(id,environment_id,name,base_url,created_at) VALUES('nb',?,'nb','https://nb.test','now')`, auth.SharedWorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	h := Handler(nil, nil, a, nil, nil, nil, nil, &profiles.Service{DB: db.DB, Auth: a}, nil, false, false)
	call := func(method, path string, body any, cookies []*http.Cookie, csrf string) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest(method, "http://forge.test"+path, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		for _, c := range cookies {
			r.AddCookie(c)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	login := call("POST", "/api/v1/auth/login", map[string]string{"token": token}, nil, "")
	if login.Code != 200 {
		t.Fatal(login.Body.String())
	}
	cookies := login.Result().Cookies()
	csrf := ""
	for _, c := range cookies {
		if c.Name == "forge_csrf" {
			csrf = c.Value
		}
	}
	created := call("POST", "/api/v1/cabling-profiles", map[string]string{"name": "uplinks"}, cookies, csrf)
	if created.Code != 201 {
		t.Fatalf("create %d %s", created.Code, created.Body.String())
	}
	var p struct {
		ID         string `json:"id"`
		RowVersion int    `json:"row_version"`
	}
	if json.Unmarshal(created.Body.Bytes(), &p) != nil || p.ID == "" {
		t.Fatal(created.Body.String())
	}
	path := "/api/v1/cabling-profiles/" + p.ID
	body := map[string]any{"row_version": p.RowVersion, "profile": map[string]any{"netbox_instance_id": "nb", "switches": []any{map[string]any{"device_id": 1, "fabric": "A"}}, "preferred_racks": []int{}, "allow_same_site": false, "distinct_switches": false, "distinct_fabrics": false, "requirements": []any{map[string]any{"id": "eth0", "speed_mbps": 10000, "media": "sfp", "port_role": "server", "fabric": "A"}}}}
	denied := call("PUT", path+"/draft", body, cookies, "")
	if denied.Code != 401 && denied.Code != 403 {
		t.Fatalf("csrf %d", denied.Code)
	}
	updated := call("PUT", path+"/draft", body, cookies, csrf)
	if updated.Code != 200 {
		t.Fatalf("save %d %s", updated.Code, updated.Body.String())
	}
	published := call("POST", path+"/publish", map[string]int{"row_version": 2}, cookies, csrf)
	if published.Code != 201 || !strings.Contains(published.Body.String(), `"netbox_references_verified":false`) {
		t.Fatalf("publish %d %s", published.Code, published.Body.String())
	}
	revision := call("GET", path+"/revisions/1", nil, cookies, "")
	if revision.Code != 200 || !strings.Contains(revision.Body.String(), `"speed_mbps":10000`) {
		t.Fatalf("revision %d %s", revision.Code, revision.Body.String())
	}
}

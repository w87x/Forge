package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"forge/internal/auth"
	"forge/internal/netbox"
	"forge/internal/profiles"
	"forge/internal/secrets"
	"forge/internal/store/sqlite"
)

func TestSharedWorkspaceRequiresNoEnvironmentSetup(t *testing.T) {
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
	v, err := secrets.New(db.DB, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32))))
	if err != nil {
		t.Fatal(err)
	}
	nb := &netbox.Service{DB: db.DB, Auth: a, Vault: v}
	ps := &profiles.Service{DB: db.DB, Auth: a, Vault: v}
	h := Handler(nil, nil, a, v, nil, nb, nil, ps, nil, false, false)
	request := func(method, path string, body any, cookies []*http.Cookie, csrf string) *httptest.ResponseRecorder {
		data, _ := json.Marshal(body)
		r := httptest.NewRequest(method, "http://forge.test"+path, bytes.NewReader(data))
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
	login := request("POST", "/api/v1/auth/login", map[string]string{"token": token}, nil, "")
	cookies := login.Result().Cookies()
	csrf := ""
	for _, c := range cookies {
		if c.Name == "forge_csrf" {
			csrf = c.Value
		}
	}
	for _, tc := range []struct {
		path string
		body any
	}{{"/api/v1/shared-secrets", map[string]string{"label": "prefix", "kind": "bmc_credential", "value": "fake"}}, {"/api/v1/netbox/instances", map[string]string{"name": "netbox", "base_url": "https://netbox.test"}}, {"/api/v1/network-profiles", map[string]string{"name": "network"}}} {
		res := request("POST", tc.path, tc.body, cookies, csrf)
		if res.Code != 201 {
			t.Fatalf("%s: %d %s", tc.path, res.Code, res.Body.String())
		}
	}
	list := request("GET", "/api/v1/network-profiles", nil, cookies, "")
	if list.Code != 200 || !strings.Contains(list.Body.String(), `"name":"network"`) {
		t.Fatalf("list: %d %s", list.Code, list.Body.String())
	}
}

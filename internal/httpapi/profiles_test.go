package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"forge/internal/auth"
	"forge/internal/profiles"
	"forge/internal/secrets"
	"forge/internal/store/sqlite"
)

func TestConnectionProfileHTTPWorkflow(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a := &auth.Service{DB: db.DB, BootstrapToken: strings.Repeat("x", 32)}
	actor, token, err := a.Bootstrap(ctx, strings.Repeat("x", 32), "operator")
	if err != nil {
		t.Fatal(err)
	}
	env, err := a.CreateEnvironment(ctx, actor, "lab")
	if err != nil {
		t.Fatal(err)
	}
	vault, err := secrets.New(db.DB, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32))))
	if err != nil {
		t.Fatal(err)
	}
	profileService := &profiles.Service{DB: db.DB, Auth: a, Vault: vault}
	handler := Handler(nil, nil, a, vault, nil, nil, nil, profileService, nil, false, false)
	request := func(method, path, body string, cookies []*http.Cookie, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://forge.test"+path, bytes.NewBufferString(body))
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		for _, c := range cookies {
			r.AddCookie(c)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	login := request("POST", "/api/v1/auth/login", fmt.Sprintf(`{"token":%q}`, token), nil, "")
	if login.Code != 200 {
		t.Fatalf("login %d", login.Code)
	}
	cookies := login.Result().Cookies()
	var csrf string
	for _, c := range cookies {
		if c.Name == "forge_csrf" {
			csrf = c.Value
		}
	}
	secret := request("POST", "/api/v1/environments/"+env.ID+"/secrets", `{"label":"prefix","kind":"bmc_credential","value":"hidden-prefix"}`, cookies, csrf)
	if secret.Code != 201 || strings.Contains(secret.Body.String(), "hidden-prefix") {
		t.Fatalf("secret response: %d %s", secret.Code, secret.Body.String())
	}
	var meta secrets.Metadata
	if err = json.Unmarshal(secret.Body.Bytes(), &meta); err != nil {
		t.Fatal(err)
	}
	draft := profiles.Connection{Driver: "redfish.generic", Priority: 100, AddressSource: "netbox_custom_field", AddressField: "bmc_address", Username: "admin", PasswordMode: "ipv4_octet", PrefixSecretID: meta.ID, PaddingWidth: 3}
	createBody, _ := json.Marshal(map[string]any{"environment_id": env.ID, "name": "BMC", "draft": draft})
	created := request("POST", "/api/v1/profiles", string(createBody), cookies, csrf)
	if created.Code != 201 {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	var p profiles.Profile
	if err = json.Unmarshal(created.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	published := request("POST", "/api/v1/profiles/"+p.ID+"/publish", fmt.Sprintf(`{"row_version":%d}`, p.RowVersion), cookies, csrf)
	if published.Code != 201 {
		t.Fatalf("publish: %d %s", published.Code, published.Body.String())
	}
	preview := request("POST", "/api/v1/profiles/"+p.ID+"/preview", `{"bmc_ip":"10.20.30.7","declared_serial":""}`, cookies, csrf)
	if preview.Code != 200 || !strings.Contains(preview.Body.String(), `"device_value":"007"`) || strings.Contains(preview.Body.String(), "hidden-prefix") {
		t.Fatalf("preview: %d %s", preview.Code, preview.Body.String())
	}
}

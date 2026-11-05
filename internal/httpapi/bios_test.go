package httpapi

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"forge/internal/auth"
	"forge/internal/inspection"
	"forge/internal/store/sqlite"
)

func TestBIOSProfilesHTTPAuthenticationAndCSRF(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a := &auth.Service{DB: db.DB, BootstrapToken: strings.Repeat("x", 32)}
	_, token, err := a.Bootstrap(ctx, strings.Repeat("x", 32), "operator")
	if err != nil {
		t.Fatal(err)
	}
	h := Handler(nil, nil, a, nil, nil, nil, nil, nil, &inspection.Service{DB: db.DB, Auth: a}, false, false)
	request := func(method, path, body string, cookies []*http.Cookie, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://forge.test"+path, bytes.NewBufferString(body))
		for _, c := range cookies {
			r.AddCookie(c)
		}
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if got := request("GET", "/api/v1/bios-profiles", "", nil, ""); got.Code != 401 {
		t.Fatalf("anonymous: %d", got.Code)
	}
	login := request("POST", "/api/v1/auth/login", fmt.Sprintf(`{"token":%q}`, token), nil, "")
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
	if got := request("GET", "/api/v1/bios-profiles", "", cookies, ""); got.Code != 200 || strings.TrimSpace(got.Body.String()) != "[]" {
		t.Fatalf("list: %d %s", got.Code, got.Body.String())
	}
	if got := request("POST", "/api/v1/bios-profiles", "{}", cookies, ""); got.Code != 401 {
		t.Fatalf("missing CSRF: %d", got.Code)
	}
	if got := request("POST", "/api/v1/bios-profiles", "{}", cookies, csrf); got.Code != 400 {
		t.Fatalf("invalid request: %d %s", got.Code, got.Body.String())
	}
}

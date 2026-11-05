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
	"forge/internal/store/sqlite"
)

func TestAuthenticationHTTPFlow(t *testing.T) {
	db, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &auth.Service{DB: db.DB, BootstrapToken: strings.Repeat("x", 32)}
	handler := Handler(nil, nil, s, nil, nil, nil, nil, nil, nil, false, false)
	request := func(method, path, body string, cookies []*http.Cookie, csrf, origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://forge.test"+path, bytes.NewBufferString(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		return res
	}
	boot := request("POST", "/api/v1/auth/bootstrap", `{"token":"`+strings.Repeat("x", 32)+`","username":"operator"}`, nil, "", "")
	if boot.Code != 201 {
		t.Fatalf("bootstrap: %d %s", boot.Code, boot.Body.String())
	}
	var response struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(boot.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	login := request("POST", "/api/v1/auth/login", `{"token":"`+response.Token+`"}`, nil, "", "")
	if login.Code != 200 {
		t.Fatalf("login %d %s", login.Code, login.Body.String())
	}
	cookies := login.Result().Cookies()
	var csrf string
	for _, cookie := range cookies {
		if cookie.Name == "forge_csrf" {
			csrf = cookie.Value
		}
	}
	if csrf == "" {
		t.Fatal("missing csrf cookie")
	}
	if got := request("POST", "/api/v1/users", `{"username":"reader","role":"readonly"}`, cookies, "", "").Code; got != 401 {
		t.Fatalf("missing csrf: %d", got)
	}
	if got := request("POST", "/api/v1/users", `{"username":"reader","role":"readonly"}`, cookies, csrf, "http://evil.test").Code; got != 403 {
		t.Fatalf("cross origin: %d", got)
	}
	created := request("POST", "/api/v1/users", `{"username":"reader","role":"readonly"}`, cookies, csrf, "")
	if created.Code != 201 {
		t.Fatalf("create reader: %d %s", created.Code, created.Body.String())
	}
	if err := json.Unmarshal(created.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	readLogin := request("POST", "/api/v1/auth/login", `{"token":"`+response.Token+`"}`, nil, "", "")
	readCookies := readLogin.Result().Cookies()
	var readCSRF string
	for _, c := range readCookies {
		if c.Name == "forge_csrf" {
			readCSRF = c.Value
		}
	}
	if got := request("POST", "/api/v1/users", `{"username":"bad","role":"full"}`, readCookies, readCSRF, "").Code; got != 403 {
		t.Fatalf("readonly create: %d", got)
	}
	if got := request("GET", "/api/v1/users", "", readCookies, "", "").Code; got != 403 {
		t.Fatalf("readonly list users: %d", got)
	}
	if got := request("POST", "/api/v1/auth/logout", "", cookies, csrf, "").Code; got != 204 {
		t.Fatalf("logout: %d", got)
	}
	if got := request("GET", "/api/v1/me", "", cookies, "", "").Code; got != 401 {
		t.Fatalf("logged-out session: %d", got)
	}
}

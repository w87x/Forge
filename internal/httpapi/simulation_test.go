package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"forge/internal/auth"
	"forge/internal/jobs"
	"forge/internal/simulation"
	"forge/internal/store/sqlite"
)

func TestSimulationJobHTTP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	authService := &auth.Service{DB: db.DB, BootstrapToken: strings.Repeat("x", 32)}
	actor, token, err := authService.Bootstrap(ctx, strings.Repeat("x", 32), "full")
	if err != nil {
		t.Fatal(err)
	}
	store := &jobs.Store{DB: db.DB}
	handler := Handler(nil, nil, authService, nil, store, nil, nil, nil, nil, true, false)
	loginReq := httptest.NewRequest("POST", "http://forge.test/api/v1/auth/login", bytes.NewBufferString(`{"token":"`+token+`"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	login := httptest.NewRecorder()
	handler.ServeHTTP(login, loginReq)
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
	create := func(key string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://forge.test/api/v1/simulation/jobs", nil)
		for _, c := range cookies {
			r.AddCookie(c)
		}
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	first := create("same")
	second := create("same")
	if first.Code != 202 || second.Code != 200 {
		t.Fatalf("idempotency status: %d %d", first.Code, second.Code)
	}
	var a, b jobs.Job
	if err := json.Unmarshal(first.Body.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(second.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if a.ID != b.ID {
		t.Fatal("duplicate job")
	}
	_, readerToken, err := authService.CreateUser(ctx, actor, "reader", auth.Readonly)
	if err != nil {
		t.Fatal(err)
	}
	readerReq := httptest.NewRequest("POST", "http://forge.test/api/v1/auth/login", bytes.NewBufferString(`{"token":"`+readerToken+`"}`))
	readerReq.Header.Set("Content-Type", "application/json")
	readerLogin := httptest.NewRecorder()
	handler.ServeHTTP(readerLogin, readerReq)
	if readerLogin.Code != 200 {
		t.Fatal(readerLogin.Body.String())
	}
	readerCookies := readerLogin.Result().Cookies()
	var readerCSRF string
	for _, c := range readerCookies {
		if c.Name == "forge_csrf" {
			readerCSRF = c.Value
		}
	}
	readerStart := httptest.NewRequest("POST", "http://forge.test/api/v1/simulation/jobs", nil)
	for _, c := range readerCookies {
		readerStart.AddCookie(c)
	}
	readerStart.Header.Set("X-CSRF-Token", readerCSRF)
	readerStart.Header.Set("Idempotency-Key", "reader")
	readerOut := httptest.NewRecorder()
	handler.ServeHTTP(readerOut, readerStart)
	if readerOut.Code != 403 {
		t.Fatalf("readonly start: %d", readerOut.Code)
	}
	readerJob := httptest.NewRequest("GET", "http://forge.test/api/v1/jobs/"+a.ID, nil)
	for _, c := range readerCookies {
		readerJob.AddCookie(c)
	}
	readerOut = httptest.NewRecorder()
	handler.ServeHTTP(readerOut, readerJob)
	if readerOut.Code != 403 {
		t.Fatalf("other user's job: %d", readerOut.Code)
	}
	done := make(chan struct{})
	go func() { defer close(done); simulation.Run(ctx, store, slog.Default()) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		j, err := store.Get(ctx, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		if j.Status == jobs.Succeeded {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	j, err := store.Get(ctx, a.ID)
	if err != nil || j.Status != jobs.Succeeded {
		t.Fatalf("job %s %v", j.Status, err)
	}
	r := httptest.NewRequest("GET", "http://forge.test/api/v1/jobs/"+a.ID+"/events", nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	r.Header.Set("Last-Event-ID", "2")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "id: 3") || strings.Contains(w.Body.String(), "id: 2\n") {
		t.Fatalf("event replay %d %s", w.Code, w.Body.String())
	}
}

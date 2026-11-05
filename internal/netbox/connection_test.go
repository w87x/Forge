package netbox

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"forge/internal/auth"
	"forge/internal/secrets"
	"forge/internal/store/sqlite"
)

func TestReadOnlyConnectionAndCooldown(t *testing.T) {
	var requests int
	var expectedAuth = "Token legacy-key"
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != "GET" || r.URL.Path != "/netbox/api/" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != expectedAuth {
			t.Errorf("unexpected authorization scheme")
		}
		if requests == 3 {
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(429)
			return
		}
		w.Header().Set("API-Version", "4.3")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"dcim":"/api/dcim/"}`))
	}))
	defer remote.Close()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	authService := &auth.Service{DB: db.DB, BootstrapToken: strings.Repeat("x", 32)}
	owner, _, err := authService.Bootstrap(ctx, strings.Repeat("x", 32), "owner")
	if err != nil {
		t.Fatal(err)
	}
	env, err := authService.CreateEnvironment(ctx, owner, "lab")
	if err != nil {
		t.Fatal(err)
	}
	vault, err := secrets.New(db.DB, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32))))
	if err != nil {
		t.Fatal(err)
	}
	host, _, _ := net.SplitHostPort(remote.Listener.Addr().String())
	service := Service{DB: db.DB, Auth: authService, Vault: vault, AllowHTTP: true, AllowedHosts: []string{host}, ConnectionsEnabled: true}
	instance, err := service.CreateInstance(ctx, owner, env.ID, "local", remote.URL+"/netbox")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SaveCredential(ctx, owner, instance.ID, "legacy-key"); err != nil {
		t.Fatal(err)
	}
	report, err := service.CheckConnection(ctx, owner, instance.ID)
	if err != nil || !report.Reachable || report.APIVersion != "4.3" || report.WritesEnabled || report.Authentication != "unverified" {
		t.Fatalf("report %+v %v", report, err)
	}
	if _, err := service.SaveCredential(ctx, owner, instance.ID, "nbt_key.secret"); err != nil {
		t.Fatal(err)
	}
	expectedAuth = "Bearer nbt_key.secret"
	if _, err := service.CheckConnection(ctx, owner, instance.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CheckConnection(ctx, owner, instance.ID); err == nil {
		t.Fatal("429 was not returned")
	}
	var rate *RateLimitError
	if _, err := service.CheckConnection(ctx, owner, instance.ID); !errors.As(err, &rate) || rate.RetryAfter < 29*time.Second {
		t.Fatalf("shared cooldown: %v", err)
	}
	if requests != 3 {
		t.Fatalf("cooldown still sent requests: %d", requests)
	}
}

func TestRetryAfterLongerThanOneDay(t *testing.T) {
	if got := retryAfter("172800", time.Now()); got != 48*time.Hour {
		t.Fatalf("shortened retry: %v", got)
	}
}

func TestRetryAfterHugeIntegerDoesNotRetryEarly(t *testing.T) {
	if got := retryAfter("99999999999999999999999999999999999", time.Now()); got < 100*365*24*time.Hour {
		t.Fatalf("huge Retry-After shortened to %v", got)
	}
}

package auth

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"forge/internal/store/sqlite"
)

func TestBootstrapSessionsAndRevocation(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "forge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	svc := Service{DB: db.DB, BootstrapToken: strings.Repeat("x", 32), Now: func() time.Time { return now }}
	if _, _, err := svc.Bootstrap(ctx, "bad", "root"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("bad bootstrap: %v", err)
	}
	root, token, err := svc.Bootstrap(ctx, strings.Repeat("x", 32), "root")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Bootstrap(ctx, strings.Repeat("x", 32), "again"); !errors.Is(err, ErrAlreadySetup) {
		t.Fatalf("second bootstrap: %v", err)
	}
	var stored []byte
	if err := db.DB.QueryRow(`SELECT token_hash FROM local_tokens WHERE user_id=?`, root.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if string(stored) == token {
		t.Fatal("stored cleartext token")
	}
	session, err := svc.Login(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SessionUser(ctx, session.Token, "wrong", true); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong CSRF: %v", err)
	}
	if _, err := svc.SessionUser(ctx, session.Token, session.CSRF, true); err != nil {
		t.Fatal(err)
	}
	reader, readerToken, err := svc.CreateUser(ctx, root, "reader", Readonly)
	if err != nil {
		t.Fatal(err)
	}
	env, err := svc.CreateEnvironment(ctx, root, "lab")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := svc.EnvironmentAllowed(ctx, reader, View, env.ID); err != nil || !ok {
		t.Fatalf("shared workspace access: %v %v", ok, err)
	}
	if err := svc.AddEnvironmentMember(ctx, root, env.ID, reader.ID); err != nil {
		t.Fatal(err)
	}
	if ok, err := svc.EnvironmentAllowed(ctx, reader, View, env.ID); err != nil || !ok {
		t.Fatalf("member access: %v %v", ok, err)
	}
	if ok, err := svc.EnvironmentAllowed(ctx, reader, Operate, env.ID); err != nil || ok {
		t.Fatalf("readonly operation: %v %v", ok, err)
	}
	if _, _, err := svc.CreateUser(ctx, reader, "denied", Full); !errors.Is(err, ErrForbidden) {
		t.Fatalf("readonly create: %v", err)
	}
	readerSession, err := svc.Login(ctx, readerToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RevokeUserTokens(ctx, root, reader.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, readerToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked token: %v", err)
	}
	replacement, err := svc.IssueToken(ctx, root, reader.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, replacement); err != nil {
		t.Fatalf("replacement token: %v", err)
	}
	if _, err := svc.SessionUser(ctx, readerSession.Token, "", false); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked session: %v", err)
	}
	now = now.Add(61 * time.Minute)
	if _, err := svc.SessionUser(ctx, session.Token, "", false); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("idle timeout: %v", err)
	}
}

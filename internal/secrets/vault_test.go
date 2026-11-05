package secrets

import (
	"context"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"forge/internal/auth"
	"forge/internal/store/sqlite"
)

func TestSecretScopeAndIntegrity(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "secret.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	for _, id := range []string{"a", "b"} {
		if _, err := db.DB.Exec(`INSERT INTO users(id,username,role,created_at) VALUES(?,?,?,?)`, id, id, "full", stamp); err != nil {
			t.Fatal(err)
		}
	}
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	v, err := New(db.DB, key)
	if err != nil {
		t.Fatal(err)
	}
	a := auth.User{ID: "a", Role: auth.Full}
	b := auth.User{ID: "b", Role: auth.Full}
	m, err := v.Put(ctx, a, Scope{OwnerID: "a"}, "netbox", "primary", []byte("secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get(ctx, b, m.ID); err == nil {
		t.Fatal("other user could access secret")
	}
	got, err := v.Get(ctx, a, m.ID)
	if err != nil || string(got) != "secret-value" {
		t.Fatalf("get: %q %v", got, err)
	}
	if gen, err := v.Replace(ctx, a, m.ID, []byte("rotated")); err != nil || gen != 2 {
		t.Fatalf("rotate: %d %v", gen, err)
	}
	if got, err := v.Get(ctx, a, m.ID); err != nil || string(got) != "rotated" {
		t.Fatalf("rotated get: %q %v", got, err)
	}
	wrong, _ := New(db.DB, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("y", 32))))
	if _, err := wrong.Get(ctx, a, m.ID); err == nil {
		t.Fatal("wrong key succeeded")
	}
	if _, err := db.DB.Exec(`UPDATE secret_records SET kind='other' WHERE id=?`, m.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get(ctx, a, m.ID); err == nil {
		t.Fatal("tampered metadata succeeded")
	}
}

func TestSharedWorkspaceUpgradePreservesLegacySecretEncryption(t *testing.T) {
	ctx := context.Background()
	name := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sqlite.Open(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	a := &auth.Service{DB: db.DB, BootstrapToken: strings.Repeat("b", 32)}
	owner, _, err := a.Bootstrap(ctx, strings.Repeat("b", 32), "owner")
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := a.CreateUser(ctx, owner, "operator", auth.Full)
	if err != nil {
		t.Fatal(err)
	}
	reader, _, err := a.CreateUser(ctx, owner, "reader", auth.Readonly)
	if err != nil {
		t.Fatal(err)
	}
	env, err := a.CreateEnvironment(ctx, owner, "old-site")
	if err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	v, err := New(db.DB, key)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := v.Put(ctx, owner, Scope{EnvironmentID: env.ID}, "bmc", "legacy", []byte("legacy-password"))
	if err != nil {
		t.Fatal(err)
	}
	private, err := v.Put(ctx, owner, Scope{OwnerID: owner.ID}, "netbox", "private", []byte("private-key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.DB.Exec(`DROP TRIGGER workspace_user_membership; DROP TRIGGER workspace_environment_membership; DELETE FROM environment_memberships WHERE user_id=? AND environment_id=?; DELETE FROM schema_migrations WHERE version=16`, other.ID, env.ID); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	v, err = New(db.DB, key)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := v.Get(ctx, other, shared.ID); err != nil || string(got) != "legacy-password" {
		t.Fatalf("legacy secret after upgrade: %q %v", got, err)
	}
	if _, err = v.Get(ctx, other, private.ID); err == nil {
		t.Fatal("private credential became shared")
	}
	if _, err = v.ListShared(ctx, reader); err == nil {
		t.Fatal("read-only user accessed shared credential metadata")
	}
	if items, err := v.ListShared(ctx, other); err != nil || len(items) != 1 || items[0].ID != shared.ID {
		t.Fatalf("shared list: %+v %v", items, err)
	}
}

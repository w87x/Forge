package netbox

import (
	"context"
	"encoding/base64"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"forge/internal/auth"
	"forge/internal/secrets"
	"forge/internal/store/sqlite"
)

func TestCredentialsAreScopedUniqueAndRotated(t *testing.T) {
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
	reader, _, err := authService.CreateUser(ctx, owner, "reader", auth.Readonly)
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
	service := Service{DB: db.DB, Auth: authService, Vault: vault}
	if _, err := service.CreateInstance(ctx, owner, env.ID, "bad", "http://netbox.test"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("insecure URL: %v", err)
	}
	instance, err := service.CreateInstance(ctx, owner, env.ID, "primary", "https://netbox.test")
	if err != nil {
		t.Fatal(err)
	}
	if list, err := service.Instances(ctx, reader); err != nil || len(list) != 1 {
		t.Fatalf("reader cannot see shared instance: %+v %v", list, err)
	}
	if err := authService.AddEnvironmentMember(ctx, owner, env.ID, reader.ID); err != nil {
		t.Fatal(err)
	}
	a, err := service.SaveCredential(ctx, owner, instance.ID, "owner-secret-token")
	if err != nil || a.Generation != 1 {
		t.Fatalf("save: %+v %v", a, err)
	}
	if _, err := service.SaveCredential(ctx, reader, instance.ID, "owner-secret-token"); !errors.Is(err, ErrDuplicateCredential) {
		t.Fatalf("shared token accepted: %v", err)
	}
	b, err := service.SaveCredential(ctx, reader, instance.ID, "reader-secret-token")
	if err != nil || b.Generation != 1 {
		t.Fatalf("reader save: %+v %v", b, err)
	}
	b, err = service.SaveCredential(ctx, reader, instance.ID, "reader-replacement-token")
	if err != nil || b.Generation != 2 {
		t.Fatalf("rotate: %+v %v", b, err)
	}
	_, _, value, err := service.CredentialValue(ctx, reader, instance.ID)
	if err != nil || string(value) != "reader-replacement-token" {
		t.Fatalf("get reader credential: %v", err)
	}
	if items, err := vault.ListOwned(ctx, reader); err != nil || len(items) != 0 {
		t.Fatalf("credential secret exposed in generic list: %+v %v", items, err)
	}
	var secretID string
	if err := db.DB.QueryRow(`SELECT secret_id FROM netbox_credentials WHERE user_id=?`, reader.ID).Scan(&secretID); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.ReplaceOwned(ctx, reader, secretID, []byte("bypass")); !errors.Is(err, secrets.ErrForbidden) {
		t.Fatalf("bypassed generation: %v", err)
	}
	if err := service.DeleteCredential(ctx, reader, instance.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := service.CredentialValue(ctx, reader, instance.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("deleted credential still usable: %v", err)
	}
	_, _, value, err = service.CredentialValue(ctx, owner, instance.ID)
	if err != nil || string(value) != "owner-secret-token" {
		t.Fatalf("owner credential changed: %v", err)
	}
}

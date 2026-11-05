package profiles

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

func TestProfileDraftRevisionAndEnvironmentScope(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a := &auth.Service{DB: db.DB, BootstrapToken: strings.Repeat("x", 32)}
	owner, _, err := a.Bootstrap(ctx, strings.Repeat("x", 32), "owner")
	if err != nil {
		t.Fatal(err)
	}
	reader, _, err := a.CreateUser(ctx, owner, "reader", auth.Readonly)
	if err != nil {
		t.Fatal(err)
	}
	env, err := a.CreateEnvironment(ctx, owner, "lab")
	if err != nil {
		t.Fatal(err)
	}
	vault, err := secrets.New(db.DB, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32))))
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := vault.Put(ctx, owner, secrets.Scope{EnvironmentID: env.ID}, "bmc_prefix", "prefix", []byte("P"))
	if err != nil {
		t.Fatal(err)
	}
	s := Service{DB: db.DB, Auth: a, Vault: vault}
	draft := Connection{Driver: "redfish.generic", AddressSource: "netbox_custom_field", AddressField: "bmc_ip", Username: "admin", PasswordMode: "ipv4_octet", PrefixSecretID: prefix.ID}
	p, err := s.Create(ctx, owner, env.ID, "server", draft)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Get(ctx, reader, p.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unscoped reader: %v", err)
	}
	if err = a.AddEnvironmentMember(ctx, owner, env.ID, reader.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Get(ctx, reader, p.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("reader saw unpublished draft: %v", err)
	}
	r1, err := s.Publish(ctx, owner, p.ID, p.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	view, err := s.Get(ctx, reader, p.ID)
	if err != nil || view.Draft != nil || view.Published == nil {
		t.Fatalf("reader view: %+v %v", view, err)
	}
	p, err = s.Get(ctx, owner, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	draft.PaddingWidth = 3
	p, err = s.Update(ctx, owner, p.ID, p.RowVersion, draft)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Update(ctx, owner, p.ID, p.RowVersion-1, draft); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update: %v", err)
	}
	r2, err := s.Publish(ctx, owner, p.ID, p.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	if r1.Number != 1 || r2.Number != 2 || r1.Hash == r2.Hash {
		t.Fatalf("revision hashes: %+v %+v", r1, r2)
	}
	old, err := s.Revision(ctx, owner, p.ID, 1)
	if err != nil || old.Content.PaddingWidth != 0 {
		t.Fatalf("old revision changed: %+v %v", old, err)
	}
	if _, err = s.Update(ctx, reader, p.ID, p.RowVersion, draft); !errors.Is(err, ErrForbidden) {
		t.Fatalf("readonly update: %v", err)
	}
}

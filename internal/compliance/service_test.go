package compliance

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"forge/internal/auth"
	"forge/internal/store/sqlite"
)

func TestHardwareProfilesAreSharedAndImmutable(t *testing.T) {
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
	s := Service{DB: db.DB}
	p, err := s.Create(ctx, owner, "compute", Hardware{RequireSerial: true, MinMemoryGiB: 64})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Get(ctx, reader, p.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("draft visible: %v", err)
	}
	r1, err := s.Publish(ctx, owner, p.ID, p.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Publish(ctx, owner, p.ID, p.RowVersion); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale publish: %v", err)
	}
	visible, err := s.Get(ctx, reader, p.ID)
	if err != nil || visible.Draft != nil || visible.Published == nil {
		t.Fatalf("published visibility: %+v %v", visible, err)
	}
	if _, err = s.Update(ctx, reader, p.ID, visible.RowVersion, Hardware{RequireSerial: true}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("readonly update: %v", err)
	}
	p, err = s.Get(ctx, owner, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	p, err = s.Update(ctx, owner, p.ID, p.RowVersion, Hardware{RequireSerial: true, MinMemoryGiB: 128})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := s.Publish(ctx, owner, p.ID, p.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	old, err := s.Revision(ctx, reader, p.ID, 1)
	if err != nil || old.Hardware.MinMemoryGiB != 64 || r1.Hash == r2.Hash {
		t.Fatalf("revision changed: %+v %v", old, err)
	}
}

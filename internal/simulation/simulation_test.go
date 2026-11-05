package simulation

import (
	"context"
	"path/filepath"
	"testing"

	"forge/internal/store/sqlite"
)

func TestModeCannotChange(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := EnsureMode(ctx, db.DB, true); err != nil {
		t.Fatal(err)
	}
	if err := EnsureMode(ctx, db.DB, true); err != nil {
		t.Fatal(err)
	}
	if err := EnsureMode(ctx, db.DB, false); err == nil {
		t.Fatal("simulation database reused for normal mode")
	}
}

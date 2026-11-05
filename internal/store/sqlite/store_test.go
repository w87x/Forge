package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
)

func TestOpenMigrateAndForeignKeys(t *testing.T) {
	ctx := context.Background()
	name := filepath.Join(t.TempDir(), "forge.db")
	s, err := Open(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE child(parent_id INTEGER REFERENCES parent(id));`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO child(parent_id) VALUES(42)`); err == nil {
		t.Fatal("foreign keys are not enabled")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var count int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version=1`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("migration count %d: %v", count, err)
	}
}

func TestUpgradeLegacyObservationSchema(t *testing.T) {
	ctx := context.Background()
	name := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL); CREATE TABLE jobs(id TEXT PRIMARY KEY); CREATE TABLE observations(id TEXT PRIMARY KEY); CREATE TABLE users(id TEXT PRIMARY KEY); CREATE TABLE environments(id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE); CREATE TABLE environment_memberships(user_id TEXT NOT NULL,environment_id TEXT NOT NULL,PRIMARY KEY(user_id,environment_id)); INSERT INTO observations(id) VALUES('legacy')`); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 11; i++ {
		if _, err = db.Exec(`INSERT INTO schema_migrations VALUES(?,?)`, i, "old"); err != nil {
			t.Fatal(err)
		}
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var id string
	var jobID sql.NullString
	if err = s.DB.QueryRow(`SELECT id,job_id FROM observations WHERE id='legacy'`).Scan(&id, &jobID); err != nil || id != "legacy" || jobID.Valid {
		t.Fatal(fmt.Sprintf("legacy row: %q %+v %v", id, jobID, err))
	}
	if _, err = s.DB.Exec(`INSERT INTO jobs(id) VALUES('job'); INSERT INTO observations(id,job_id) VALUES('new','job')`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`INSERT INTO observations(id,job_id) VALUES('duplicate','job')`); err == nil {
		t.Fatal("job ID must be unique")
	}
}

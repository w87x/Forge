// Package sqlite implements Forge's local, single-writer database.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct{ DB *sql.DB }

// Open opens a database on local storage, and applies its migrations.
func Open(ctx context.Context, filename string) (*Store, error) {
	abs, err := filepath.Abs(filename)
	if err != nil {
		return nil, fmt.Errorf("database path: %w", err)
	}
	u := url.URL{Scheme: "file", Path: abs}
	q := u.Query()
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	// One connection serializes writes and ensures every connection has the same pragmas.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0 * time.Second)
	s := &Store{DB: db}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.DB.Close() }

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.DB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`)
	if err != nil {
		return fmt.Errorf("create migration table: %w", err)
	}
	for _, m := range migrations {
		var exists bool
		if err := s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = ?)`, m.version).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		tx, err := s.DB.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if m.version == 12 {
			err = ensureObservationJobID(ctx, tx)
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, m.sql)
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)`, m.version, time.Now().UTC().Format(time.RFC3339Nano))
		}
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %d: %w", m.version, err)
		}
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", m.version, err)
		}
	}
	return nil
}

// Early development databases may have applied migration 10 before job_id was
// added to the observation schema. Preserve their records when upgrading.
func ensureObservationJobID(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(observations)`)
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid, notNull, pk int
		var name, typ string
		var defaultValue any
		if err = rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == "job_id" {
			found = true
		}
	}
	err = rows.Err()
	if closeErr := rows.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if !found {
		_, err = tx.ExecContext(ctx, `ALTER TABLE observations ADD COLUMN job_id TEXT REFERENCES jobs(id)`)
	}
	return err
}

type migration struct {
	version int
	sql     string
}

var migrations = []migration{
	{1, `CREATE TABLE IF NOT EXISTS app_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)`},
	{2, `
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK(role IN ('full', 'readonly')),
  disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN (0, 1)),
  created_at TEXT NOT NULL
);
CREATE TABLE environments (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE);
CREATE TABLE environment_memberships (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, environment_id)
);
CREATE TABLE local_tokens (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash BLOB NOT NULL UNIQUE, created_at TEXT NOT NULL, revoked_at TEXT
);
CREATE TABLE sessions (
  id_hash BLOB PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_hash BLOB NOT NULL, created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, expires_at TEXT NOT NULL
);
`},
	{3, `CREATE TABLE secret_records (
  id TEXT PRIMARY KEY,
  owner_id TEXT REFERENCES users(id),
  environment_id TEXT REFERENCES environments(id),
  kind TEXT NOT NULL, label TEXT NOT NULL,
  key_id TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
  generation INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  CHECK ((owner_id IS NOT NULL) != (environment_id IS NOT NULL))
)`},
	{4, `CREATE TABLE audit_events (
  id TEXT PRIMARY KEY, actor_id TEXT REFERENCES users(id),
  action TEXT NOT NULL, target_id TEXT NOT NULL, created_at TEXT NOT NULL
)`},
	{5, `
CREATE TABLE jobs (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL,
  actor_id TEXT NOT NULL REFERENCES users(id), input_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('queued','running','retry_wait','waiting_remote','awaiting_approval','cancel_requested','cancelled','succeeded','failed','needs_attention')),
  attempts INTEGER NOT NULL DEFAULT 0, next_attempt_ns INTEGER NOT NULL,
  deadline_ns INTEGER NOT NULL, lease_owner TEXT, lease_until_ns INTEGER,
  lease_generation INTEGER NOT NULL DEFAULT 0, created_ns INTEGER NOT NULL
);
CREATE INDEX jobs_eligible ON jobs(status,next_attempt_ns);
CREATE TABLE job_steps (
  job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  position INTEGER NOT NULL, name TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','running','succeeded','failed')),
  effect TEXT NOT NULL CHECK(effect IN ('not_started','sent','confirmed','uncertain')),
  remote_ref TEXT NOT NULL DEFAULT '', PRIMARY KEY(job_id,position)
);
CREATE TABLE job_events (
  job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  sequence INTEGER NOT NULL, type TEXT NOT NULL, message TEXT NOT NULL,
  created_ns INTEGER NOT NULL, PRIMARY KEY(job_id,sequence)
);
CREATE TABLE resource_leases (
  resource_key TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id),
  owner TEXT NOT NULL, generation INTEGER NOT NULL, expires_ns INTEGER NOT NULL
);
`},
	{6, `CREATE TABLE job_requests (
  actor_id TEXT NOT NULL REFERENCES users(id), route TEXT NOT NULL,
  request_key TEXT NOT NULL, body_hash TEXT NOT NULL,
  job_id TEXT NOT NULL REFERENCES jobs(id),
  PRIMARY KEY(actor_id,route,request_key)
)`},
	{7, `
CREATE TABLE netbox_instances (
  id TEXT PRIMARY KEY, environment_id TEXT NOT NULL REFERENCES environments(id),
  name TEXT NOT NULL, base_url TEXT NOT NULL, created_at TEXT NOT NULL,
  UNIQUE(environment_id,name), UNIQUE(environment_id,base_url)
);
CREATE TABLE netbox_credentials (
  instance_id TEXT NOT NULL REFERENCES netbox_instances(id),
  user_id TEXT NOT NULL REFERENCES users(id),
  secret_id TEXT NOT NULL UNIQUE REFERENCES secret_records(id) ON DELETE RESTRICT,
  fingerprint BLOB NOT NULL, generation INTEGER NOT NULL,
  updated_at TEXT NOT NULL, PRIMARY KEY(instance_id,user_id),
  UNIQUE(instance_id,fingerprint)
);
`},
	{8, `
CREATE TABLE servers (
  id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES netbox_instances(id),
  netbox_device_id INTEGER NOT NULL, name TEXT NOT NULL, last_seen_at TEXT NOT NULL,
  UNIQUE(instance_id,netbox_device_id)
);
CREATE TABLE inventory_snapshots (
  id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES netbox_instances(id),
  actor_id TEXT NOT NULL REFERENCES users(id), credential_generation INTEGER NOT NULL,
  filter_json TEXT NOT NULL, page_json TEXT NOT NULL,
  fetched_at_ns INTEGER NOT NULL, expires_at_ns INTEGER NOT NULL
);
CREATE INDEX inventory_by_actor ON inventory_snapshots(actor_id,instance_id,fetched_at_ns);
CREATE TABLE inventory_selections (
  id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL REFERENCES inventory_snapshots(id),
  actor_id TEXT NOT NULL REFERENCES users(id), device_ids_json TEXT NOT NULL, created_at_ns INTEGER NOT NULL
);
`},
	{9, `
CREATE TABLE profiles (
  id TEXT PRIMARY KEY, environment_id TEXT NOT NULL REFERENCES environments(id),
  name TEXT NOT NULL, kind TEXT NOT NULL, draft_json TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1, published_revision INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL, UNIQUE(environment_id,kind,name)
);
CREATE TABLE profile_revisions (
  profile_id TEXT NOT NULL REFERENCES profiles(id), revision INTEGER NOT NULL,
  content_json TEXT NOT NULL, content_hash TEXT NOT NULL, actor_id TEXT NOT NULL REFERENCES users(id),
  published_at TEXT NOT NULL, PRIMARY KEY(profile_id,revision)
);
`},
	{10, `CREATE TABLE observations (
  id TEXT PRIMARY KEY, actor_id TEXT NOT NULL REFERENCES users(id),
  job_id TEXT NOT NULL UNIQUE REFERENCES jobs(id),
  server_id TEXT NOT NULL REFERENCES servers(id),
  selection_id TEXT NOT NULL REFERENCES inventory_selections(id),
  profile_id TEXT NOT NULL, profile_revision INTEGER NOT NULL,
  management_address TEXT NOT NULL, observed_json TEXT NOT NULL,
  collected_at_ns INTEGER NOT NULL,
  FOREIGN KEY(profile_id,profile_revision) REFERENCES profile_revisions(profile_id,revision)
);
CREATE INDEX observations_server_actor ON observations(actor_id,server_id,collected_at_ns);`},
	{11, `CREATE TABLE job_inputs (job_id TEXT PRIMARY KEY REFERENCES jobs(id), content_json TEXT NOT NULL)`},
	{12, `CREATE UNIQUE INDEX IF NOT EXISTS observations_job_id_unique ON observations(job_id)`},
	{13, `CREATE TABLE bios_profiles (
 id TEXT PRIMARY KEY, environment_id TEXT NOT NULL REFERENCES environments(id), name TEXT NOT NULL,
 draft_json TEXT NOT NULL, row_version INTEGER NOT NULL DEFAULT 1, published_revision INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL, UNIQUE(environment_id,name)
);
CREATE TABLE bios_profile_revisions (
 profile_id TEXT NOT NULL REFERENCES bios_profiles(id), revision INTEGER NOT NULL,
 content_json TEXT NOT NULL, content_hash TEXT NOT NULL, actor_id TEXT NOT NULL REFERENCES users(id),
 published_at TEXT NOT NULL, PRIMARY KEY(profile_id,revision)
);`},
	{14, `CREATE TABLE network_profiles (
 id TEXT PRIMARY KEY, environment_id TEXT NOT NULL REFERENCES environments(id), name TEXT NOT NULL,
 draft_json TEXT NOT NULL, row_version INTEGER NOT NULL DEFAULT 1, published_revision INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL, UNIQUE(environment_id,name)
);
CREATE TABLE network_profile_revisions (
 profile_id TEXT NOT NULL REFERENCES network_profiles(id), revision INTEGER NOT NULL,
 content_json TEXT NOT NULL, content_hash TEXT NOT NULL, actor_id TEXT NOT NULL REFERENCES users(id),
 published_at TEXT NOT NULL, PRIMARY KEY(profile_id,revision)
);`},
	{15, `CREATE TABLE allocation_imports (
 id TEXT PRIMARY KEY, actor_id TEXT NOT NULL REFERENCES users(id), instance_id TEXT NOT NULL REFERENCES netbox_instances(id),
 selection_id TEXT NOT NULL REFERENCES inventory_selections(id), profile_id TEXT NOT NULL,
 profile_revision INTEGER NOT NULL, device_ids_json TEXT NOT NULL, bindings_json TEXT NOT NULL,
 addresses_json TEXT NOT NULL, source_hash TEXT NOT NULL, parser_version INTEGER NOT NULL, created_at TEXT NOT NULL,
 FOREIGN KEY(profile_id,profile_revision) REFERENCES network_profile_revisions(profile_id,revision)
);
CREATE INDEX allocation_imports_actor ON allocation_imports(actor_id,instance_id,created_at);`},
	{16, `INSERT INTO environments(id,name) VALUES('forge-shared-workspace','__forge_shared_workspace__:' || lower(hex(randomblob(16)))) ON CONFLICT(id) DO NOTHING;
INSERT OR IGNORE INTO environment_memberships(user_id,environment_id) SELECT users.id,environments.id FROM users CROSS JOIN environments;
CREATE TRIGGER workspace_user_membership AFTER INSERT ON users BEGIN
 INSERT OR IGNORE INTO environment_memberships(user_id,environment_id) SELECT NEW.id,id FROM environments;
END;
CREATE TRIGGER workspace_environment_membership AFTER INSERT ON environments BEGIN
 INSERT OR IGNORE INTO environment_memberships(user_id,environment_id) SELECT id,NEW.id FROM users;
END;`},
	{17, `CREATE TABLE hardware_profiles (
 id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, draft_json TEXT NOT NULL,
 row_version INTEGER NOT NULL DEFAULT 1, published_revision INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE hardware_profile_revisions (
 profile_id TEXT NOT NULL REFERENCES hardware_profiles(id), revision INTEGER NOT NULL, content_json TEXT NOT NULL,
 content_hash TEXT NOT NULL, actor_id TEXT NOT NULL REFERENCES users(id), published_at TEXT NOT NULL,
 PRIMARY KEY(profile_id,revision)
);`},
	{18, `CREATE TABLE hardware_audits (
 id TEXT PRIMARY KEY, actor_id TEXT NOT NULL REFERENCES users(id), profile_id TEXT NOT NULL,
 profile_revision INTEGER NOT NULL, job_id TEXT NOT NULL REFERENCES jobs(id), result_json TEXT NOT NULL,
 created_at TEXT NOT NULL, FOREIGN KEY(profile_id,profile_revision) REFERENCES hardware_profile_revisions(profile_id,revision)
);
CREATE INDEX hardware_audits_actor ON hardware_audits(actor_id,created_at);`},
	{19, `CREATE TABLE network_audits (
 id TEXT PRIMARY KEY, actor_id TEXT NOT NULL REFERENCES users(id), import_id TEXT NOT NULL REFERENCES allocation_imports(id),
 device_id INTEGER NOT NULL, result_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX network_audits_actor ON network_audits(actor_id,import_id,created_at);`},
	{20, `CREATE TABLE combined_audits (
 id TEXT PRIMARY KEY, actor_id TEXT NOT NULL REFERENCES users(id), hardware_audit_id TEXT NOT NULL REFERENCES hardware_audits(id),
 network_audit_id TEXT NOT NULL REFERENCES network_audits(id), job_id TEXT NOT NULL REFERENCES jobs(id),
 result_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX combined_audits_actor ON combined_audits(actor_id,created_at);`},
	{21, `CREATE TABLE investigation_drafts (
 id TEXT PRIMARY KEY, actor_id TEXT NOT NULL REFERENCES users(id), audit_id TEXT NOT NULL REFERENCES combined_audits(id),
 content_json TEXT NOT NULL, content_hash TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX investigation_drafts_actor ON investigation_drafts(actor_id,created_at);`},
	{22, `ALTER TABLE investigation_drafts ADD COLUMN completed_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE investigation_drafts ADD COLUMN row_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE investigation_drafts ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';`},
	{23, `CREATE TABLE cabling_profiles (
 id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, draft_json TEXT NOT NULL,
 row_version INTEGER NOT NULL DEFAULT 1, published_revision INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE cabling_profile_revisions (
 profile_id TEXT NOT NULL REFERENCES cabling_profiles(id), revision INTEGER NOT NULL,
 content_json TEXT NOT NULL, content_hash TEXT NOT NULL, actor_id TEXT NOT NULL REFERENCES users(id),
 published_at TEXT NOT NULL, PRIMARY KEY(profile_id,revision)
);`},
}

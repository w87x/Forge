package jobs

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"forge/internal/store/sqlite"
)

func TestClaimAndUncertainRecovery(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := db.DB.Exec(`INSERT INTO users(id,username,role,created_at) VALUES('a','a','full',?)`, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	s := Store{DB: db.DB, Now: func() time.Time { return now }}
	job, err := s.Create(ctx, "inspect", "a", "sha256:test", now.Add(time.Hour), []string{"remote"})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := s.ClaimNext(ctx, "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.ID != job.ID || claimed.Generation != 1 {
		t.Fatalf("bad claim: %+v", claimed)
	}
	if _, err := s.ClaimNext(ctx, "other", time.Minute); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second claim: %v", err)
	}
	if err := s.StartExternal(ctx, job.ID, "worker", claimed.Generation, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.ScheduleRetry(ctx, job.ID, "worker", claimed.Generation, now.Add(time.Minute), 3); !errors.Is(err, ErrConflict) {
		t.Fatalf("unsafe retry: %v", err)
	}
	now = now.Add(2 * time.Minute)
	status, err := s.RecoverExpired(ctx, job.ID)
	if err != nil || status != NeedsAttention {
		t.Fatalf("recovery %s %v", status, err)
	}
	if err := s.ConfirmExternal(ctx, job.ID, "worker", claimed.Generation, 0, "remote"); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired worker modified job: %v", err)
	}
	if _, err := s.ClaimNext(ctx, "other", time.Minute); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("uncertain job replayed: %v", err)
	}
	events, err := s.Events(ctx, job.ID, 0)
	if err != nil || len(events) != 4 {
		t.Fatalf("events %v %v", events, err)
	}
	for i, e := range events {
		if e.Sequence != int64(i+1) {
			t.Fatalf("event sequence: %+v", events)
		}
	}
}
func TestRetryAndCancel(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	if _, err := db.DB.Exec(`INSERT INTO users(id,username,role,created_at) VALUES('a','a','full',?)`, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	s := Store{DB: db.DB, Now: func() time.Time { return now }}
	j, err := s.Create(ctx, "test", "a", "hash", now.Add(time.Hour), []string{"one"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.ClaimNext(ctx, "w", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ScheduleRetry(ctx, j.ID, "w", c.Generation, now.Add(5*time.Minute), 3); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimNext(ctx, "w", time.Minute); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("early retry: %v", err)
	}
	now = now.Add(5 * time.Minute)
	if _, err := s.ClaimNext(ctx, "w", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.RequestCancel(ctx, j.ID, "a"); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, j.ID)
	if err != nil || got.Status != CancelRequested {
		t.Fatalf("cancel: %+v %v", got, err)
	}
}

func TestResourceLeaseDoesNotStealUnresolvedWork(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	if _, err := db.DB.Exec(`INSERT INTO users(id,username,role,created_at) VALUES('a','a','full',?)`, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	s := Store{DB: db.DB, Now: func() time.Time { return now }}
	_, err = s.Create(ctx, "test", "a", "first", now.Add(time.Hour), []string{"remote"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Create(ctx, "test", "a", "second", now.Add(time.Hour), []string{"remote"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.ClaimNext(ctx, "a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.ClaimNext(ctx, "b", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AcquireResource(ctx, "bmc:1", a.ID, "a", a.Generation, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.AcquireResource(ctx, "bmc:1", b.ID, "b", b.Generation, time.Minute); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate lease: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if err := s.AcquireResource(ctx, "bmc:1", b.ID, "b", b.Generation, time.Minute); !errors.Is(err, ErrConflict) {
		t.Fatalf("stole unresolved lease: %v", err)
	}
	if status, err := s.RecoverExpired(ctx, a.ID); err != nil || status != Queued {
		t.Fatalf("recover: %s %v", status, err)
	}
	if err := s.AcquireResource(ctx, "bmc:1", b.ID, "b", b.Generation, time.Minute); err != nil {
		t.Fatal(err)
	}
}

func TestLocalStepCanResumeAfterClaimRecovery(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	if _, err := db.DB.Exec(`INSERT INTO users(id,username,role,created_at) VALUES('a','a','full',?)`, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	s := Store{DB: db.DB, Now: func() time.Time { return now }}
	j, err := s.Create(ctx, "simulation.inspect", "a", "hash", now.Add(time.Hour), []string{"first", "second"})
	if err != nil {
		t.Fatal(err)
	}
	claim, err := s.ClaimNext(ctx, "w", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteLocalStep(ctx, j.ID, "w", claim.Generation, 0); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if status, err := s.RecoverExpired(ctx, j.ID); err != nil || status != Queued {
		t.Fatalf("recover %s %v", status, err)
	}
	claim, err = s.ClaimNext(ctx, "w2", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteLocalStep(ctx, j.ID, "w2", claim.Generation, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteLocalStep(ctx, j.ID, "w2", claim.Generation, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(ctx, j.ID, "w2", claim.Generation); err != nil {
		t.Fatal(err)
	}
	events, err := s.Events(ctx, j.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, event := range events {
		if event.Message == "Step 1 completed" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("duplicate step events: %d", count)
	}
}

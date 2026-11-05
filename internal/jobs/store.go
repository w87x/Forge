// Package jobs persists work before it is executed and records recovery evidence.
package jobs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var ErrConflict = errors.New("job is not in the expected state")

type Status string

const (
	Queued           Status = "queued"
	Running          Status = "running"
	RetryWait        Status = "retry_wait"
	WaitingRemote    Status = "waiting_remote"
	AwaitingApproval Status = "awaiting_approval"
	CancelRequested  Status = "cancel_requested"
	Cancelled        Status = "cancelled"
	Succeeded        Status = "succeeded"
	Failed           Status = "failed"
	NeedsAttention   Status = "needs_attention"
)

type Job struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"`
	ActorID     string    `json:"actor_id"`
	InputHash   string    `json:"input_hash"`
	Status      Status    `json:"status"`
	Attempts    int       `json:"attempts"`
	NextAttempt time.Time `json:"next_attempt"`
	Deadline    time.Time `json:"deadline"`
	LeaseOwner  string    `json:"-"`
	LeaseUntil  time.Time `json:"-"`
	Generation  int64     `json:"-"`
}
type Event struct {
	Sequence int64     `json:"sequence"`
	Type     string    `json:"type"`
	Message  string    `json:"message"`
	At       time.Time `json:"at"`
}
type Step struct {
	Position  int
	Name      string
	Status    string
	Effect    string
	RemoteRef string
}
type Store struct {
	DB  *sql.DB
	Now func() time.Time
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}
func ns(t time.Time) int64 { return t.UnixNano() }

func addEvent(ctx context.Context, tx *sql.Tx, jobID, kind, message string, at time.Time) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO job_events(job_id,sequence,type,message,created_ns) SELECT ?,COALESCE(MAX(sequence),0)+1,?,?,? FROM job_events WHERE job_id=?`, jobID, kind, message, ns(at), jobID)
	return err
}

func (s *Store) Create(ctx context.Context, kind, actorID, inputHash string, deadline time.Time, stepNames []string) (Job, error) {
	if kind == "" || actorID == "" || inputHash == "" || !deadline.After(s.now()) || len(stepNames) == 0 {
		return Job{}, errors.New("invalid job input")
	}
	for _, name := range stepNames {
		if name == "" {
			return Job{}, errors.New("invalid step name")
		}
	}
	job := Job{ID: uuid.NewString(), Kind: kind, ActorID: actorID, InputHash: inputHash, Status: Queued, NextAttempt: s.now(), Deadline: deadline}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Job{}, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO jobs(id,kind,actor_id,input_hash,status,next_attempt_ns,deadline_ns,created_ns) VALUES(?,?,?,?,?,?,?,?)`, job.ID, kind, actorID, inputHash, job.Status, ns(job.NextAttempt), ns(deadline), ns(s.now()))
	if err != nil {
		return Job{}, err
	}
	for i, name := range stepNames {
		if _, err = tx.ExecContext(ctx, `INSERT INTO job_steps(job_id,position,name,status,effect) VALUES(?,?,?,'pending','not_started')`, job.ID, i, name); err != nil {
			return Job{}, err
		}
	}
	if err = addEvent(ctx, tx, job.ID, "queued", "Job queued", s.now()); err != nil {
		return Job{}, err
	}
	if err = tx.Commit(); err != nil {
		return Job{}, err
	}
	return job, nil
}

func scanJob(scanner interface{ Scan(...any) error }) (Job, error) {
	var j Job
	var next, deadline int64
	var owner sql.NullString
	var until sql.NullInt64
	err := scanner.Scan(&j.ID, &j.Kind, &j.ActorID, &j.InputHash, &j.Status, &j.Attempts, &next, &deadline, &owner, &until, &j.Generation)
	if err != nil {
		return Job{}, err
	}
	j.NextAttempt = time.Unix(0, next).UTC()
	j.Deadline = time.Unix(0, deadline).UTC()
	j.LeaseOwner = owner.String
	if until.Valid {
		j.LeaseUntil = time.Unix(0, until.Int64).UTC()
	}
	return j, nil
}

const columns = `id,kind,actor_id,input_hash,status,attempts,next_attempt_ns,deadline_ns,lease_owner,lease_until_ns,lease_generation`

func (s *Store) Get(ctx context.Context, id string) (Job, error) {
	return scanJob(s.DB.QueryRowContext(ctx, `SELECT `+columns+` FROM jobs WHERE id=?`, id))
}
func (s *Store) Events(ctx context.Context, id string, after int64) ([]Event, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT sequence,type,message,created_ns FROM job_events WHERE job_id=? AND sequence>? ORDER BY sequence LIMIT 1000`, id, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Event{}
	for rows.Next() {
		var e Event
		var at int64
		if err := rows.Scan(&e.Sequence, &e.Type, &e.Message, &at); err != nil {
			return nil, err
		}
		e.At = time.Unix(0, at).UTC()
		items = append(items, e)
	}
	return items, rows.Err()
}

// ClaimNext claims only queued work. Expired running work is not replayed here.
func (s *Store) ClaimNext(ctx context.Context, worker string, ttl time.Duration) (Job, error) {
	return s.claim(ctx, worker, ttl, "")
}

func (s *Store) ClaimKind(ctx context.Context, worker string, ttl time.Duration, kind string) (Job, error) {
	if kind == "" {
		return Job{}, errors.New("missing job kind")
	}
	return s.claim(ctx, worker, ttl, kind)
}

func (s *Store) claim(ctx context.Context, worker string, ttl time.Duration, kind string) (Job, error) {
	if worker == "" || ttl <= 0 {
		return Job{}, errors.New("invalid claim")
	}
	now := s.now()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Job{}, err
	}
	defer tx.Rollback()
	j, err := scanJob(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM jobs WHERE status IN ('queued','retry_wait') AND next_attempt_ns<=? AND deadline_ns>? AND (?='' OR kind=?) ORDER BY next_attempt_ns,created_ns,id LIMIT 1`, ns(now), ns(now), kind, kind))
	if err != nil {
		return Job{}, err
	}
	res, err := tx.ExecContext(ctx, `UPDATE jobs SET status='running',attempts=attempts+1,lease_owner=?,lease_until_ns=?,lease_generation=lease_generation+1 WHERE id=? AND status IN ('queued','retry_wait')`, worker, ns(now.Add(ttl)), j.ID)
	if err != nil {
		return Job{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Job{}, err
	}
	if n != 1 {
		return Job{}, ErrConflict
	}
	if err = addEvent(ctx, tx, j.ID, "running", "Job claimed", now); err != nil {
		return Job{}, err
	}
	if err = tx.Commit(); err != nil {
		return Job{}, err
	}
	return s.Get(ctx, j.ID)
}

// CreateIdempotent atomically associates a request key with one job for the actor.
func (s *Store) CreateIdempotent(ctx context.Context, actorID, route, key, bodyHash, kind string, deadline time.Time, stepNames []string) (Job, bool, error) {
	return s.CreateIdempotentInput(ctx, actorID, route, key, bodyHash, kind, deadline, stepNames, nil)
}

// CreateIdempotentInput stores nonsecret job input atomically with the job.
func (s *Store) CreateIdempotentInput(ctx context.Context, actorID, route, key, bodyHash, kind string, deadline time.Time, stepNames []string, input []byte) (Job, bool, error) {
	if actorID == "" || route == "" || key == "" || len(key) > 128 || bodyHash == "" || kind == "" || !deadline.After(s.now()) || len(stepNames) == 0 {
		return Job{}, false, errors.New("invalid job request")
	}
	for _, name := range stepNames {
		if name == "" {
			return Job{}, false, errors.New("invalid step name")
		}
	}
	if len(input) > 64<<10 {
		return Job{}, false, errors.New("job input too large")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Job{}, false, err
	}
	defer tx.Rollback()
	var jobID, storedHash string
	err = tx.QueryRowContext(ctx, `SELECT job_id,body_hash FROM job_requests WHERE actor_id=? AND route=? AND request_key=?`, actorID, route, key).Scan(&jobID, &storedHash)
	if err == nil {
		if storedHash != bodyHash {
			return Job{}, false, ErrConflict
		}
		j, err := scanJob(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM jobs WHERE id=?`, jobID))
		if err != nil {
			return Job{}, false, err
		}
		if err = tx.Commit(); err != nil {
			return Job{}, false, err
		}
		return j, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Job{}, false, err
	}
	now := s.now()
	j := Job{ID: uuid.NewString(), Kind: kind, ActorID: actorID, InputHash: bodyHash, Status: Queued, NextAttempt: now, Deadline: deadline}
	if _, err = tx.ExecContext(ctx, `INSERT INTO jobs(id,kind,actor_id,input_hash,status,next_attempt_ns,deadline_ns,created_ns) VALUES(?,?,?,?,?,?,?,?)`, j.ID, kind, actorID, bodyHash, j.Status, ns(now), ns(deadline), ns(now)); err != nil {
		return Job{}, false, err
	}
	for i, name := range stepNames {
		if _, err = tx.ExecContext(ctx, `INSERT INTO job_steps(job_id,position,name,status,effect) VALUES(?,?,?,'pending','not_started')`, j.ID, i, name); err != nil {
			return Job{}, false, err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO job_requests(actor_id,route,request_key,body_hash,job_id) VALUES(?,?,?,?,?)`, actorID, route, key, bodyHash, j.ID); err != nil {
		return Job{}, false, err
	}
	if input != nil {
		if _, err = tx.ExecContext(ctx, `INSERT INTO job_inputs(job_id,content_json) VALUES(?,?)`, j.ID, string(input)); err != nil {
			return Job{}, false, err
		}
	}
	if err = addEvent(ctx, tx, j.ID, "queued", "Job queued", now); err != nil {
		return Job{}, false, err
	}
	if err = tx.Commit(); err != nil {
		return Job{}, false, err
	}
	return j, true, nil
}

func (s *Store) Input(ctx context.Context, jobID string) ([]byte, error) {
	var content string
	err := s.DB.QueryRowContext(ctx, `SELECT content_json FROM job_inputs WHERE job_id=?`, jobID).Scan(&content)
	return []byte(content), err
}

// FindIdempotent checks a previously accepted request without creating work.
func (s *Store) FindIdempotent(ctx context.Context, actorID, route, key, bodyHash string) (Job, bool, error) {
	var id, storedHash string
	err := s.DB.QueryRowContext(ctx, `SELECT job_id,body_hash FROM job_requests WHERE actor_id=? AND route=? AND request_key=?`, actorID, route, key).Scan(&id, &storedHash)
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, false, nil
	}
	if err != nil {
		return Job{}, false, err
	}
	if storedHash != bodyHash {
		return Job{}, false, ErrConflict
	}
	job, err := s.Get(ctx, id)
	return job, true, err
}

func (s *Store) ListByActor(ctx context.Context, actorID string) ([]Job, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+columns+` FROM jobs WHERE actor_id=? ORDER BY created_ns DESC,id DESC LIMIT 100`, actorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Job{}
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, j)
	}
	return items, rows.Err()
}

// CompleteLocalStep is only for work which has no externally visible effects.
func (s *Store) CompleteLocalStep(ctx context.Context, jobID, worker string, generation int64, position int) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE job_steps SET status='succeeded' WHERE job_id=? AND position=? AND status='pending' AND effect='not_started' AND EXISTS(SELECT 1 FROM jobs WHERE id=? AND status='running' AND lease_owner=? AND lease_generation=? AND lease_until_ns>?)`, jobID, position, jobID, worker, generation, ns(s.now()))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		var completed bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM job_steps p JOIN jobs j ON j.id=p.job_id WHERE p.job_id=? AND p.position=? AND p.status='succeeded' AND p.effect='not_started' AND j.status='running' AND j.lease_owner=? AND j.lease_generation=? AND j.lease_until_ns>?)`, jobID, position, worker, generation, ns(s.now())).Scan(&completed); err != nil {
			return err
		}
		if !completed {
			return ErrConflict
		}
		return tx.Commit()
	}
	if err = addEvent(ctx, tx, jobID, "step_completed", fmt.Sprintf("Step %d completed", position+1), s.now()); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Complete(ctx context.Context, jobID, worker string, generation int64) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE jobs SET status='succeeded',lease_owner=NULL,lease_until_ns=NULL WHERE id=? AND status='running' AND lease_owner=? AND lease_generation=? AND lease_until_ns>? AND NOT EXISTS(SELECT 1 FROM job_steps WHERE job_id=? AND status!='succeeded')`, jobID, worker, generation, ns(s.now()), jobID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	if err = addEvent(ctx, tx, jobID, "succeeded", "Job completed", s.now()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Park(ctx context.Context, jobID, worker string, generation int64, message string) error {
	if message == "" {
		return errors.New("missing attention reason")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE jobs SET status='needs_attention',lease_owner=NULL,lease_until_ns=NULL WHERE id=? AND status='running' AND lease_owner=? AND lease_generation=? AND lease_until_ns>?`, jobID, worker, generation, ns(s.now()))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	if err = addEvent(ctx, tx, jobID, "needs_attention", message, s.now()); err != nil {
		return err
	}
	return tx.Commit()
}

// StartExternal records intent before a remote request is sent. A worker whose
// lease has expired is rejected; the remote system cannot honor a fencing token.
func (s *Store) StartExternal(ctx context.Context, jobID, worker string, generation int64, position int) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE job_steps SET status='running',effect='sent' WHERE job_id=? AND position=? AND status='pending' AND effect='not_started' AND EXISTS(SELECT 1 FROM jobs WHERE id=? AND status='running' AND lease_owner=? AND lease_generation=? AND lease_until_ns>?)`, jobID, position, jobID, worker, generation, ns(s.now()))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	if err = addEvent(ctx, tx, jobID, "effect_sent", "External operation dispatched", s.now()); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) ConfirmExternal(ctx context.Context, jobID, worker string, generation int64, position int, remoteRef string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE job_steps SET status='succeeded',effect='confirmed',remote_ref=? WHERE job_id=? AND position=? AND effect='sent' AND EXISTS(SELECT 1 FROM jobs WHERE id=? AND status IN ('running','cancel_requested') AND lease_owner=? AND lease_generation=? AND lease_until_ns>?)`, remoteRef, jobID, position, jobID, worker, generation, ns(s.now()))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	if err = addEvent(ctx, tx, jobID, "effect_confirmed", "External operation confirmed", s.now()); err != nil {
		return err
	}
	return tx.Commit()
}

// RecoverExpired never makes a possibly-dispatched remote effect runnable.
func (s *Store) RecoverExpired(ctx context.Context, jobID string) (Status, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	now := s.now()
	j, err := scanJob(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM jobs WHERE id=?`, jobID))
	if err != nil {
		return "", err
	}
	if (j.Status != Running && j.Status != CancelRequested) || j.LeaseUntil.IsZero() || j.LeaseUntil.After(now) {
		return "", ErrConflict
	}
	var uncertain bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM job_steps WHERE job_id=? AND effect IN ('sent','uncertain'))`, jobID).Scan(&uncertain); err != nil {
		return "", err
	}
	status := Queued
	message := "Expired claim recovered"
	if j.Status == CancelRequested {
		status = Cancelled
		message = "Cancellation completed after claim expiry"
	}
	if uncertain {
		status = NeedsAttention
		message = "External outcome requires reconciliation"
		if _, err = tx.ExecContext(ctx, `UPDATE job_steps SET effect='uncertain' WHERE job_id=? AND effect='sent'`, jobID); err != nil {
			return "", err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE jobs SET status=?,lease_owner=NULL,lease_until_ns=NULL WHERE id=?`, status, jobID); err != nil {
		return "", err
	}
	if err = addEvent(ctx, tx, jobID, string(status), message, now); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return status, nil
}

func (s *Store) RequestCancel(ctx context.Context, id, actorID string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE jobs SET status=CASE WHEN status IN ('queued','retry_wait','awaiting_approval') THEN 'cancelled' ELSE 'cancel_requested' END WHERE id=? AND actor_id=? AND status IN ('queued','running','retry_wait','waiting_remote','awaiting_approval')`, id, actorID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	var status Status
	if err = tx.QueryRowContext(ctx, `SELECT status FROM jobs WHERE id=?`, id).Scan(&status); err != nil {
		return err
	}
	message := "Cancellation requested"
	if status == Cancelled {
		message = "Job cancelled before execution"
	}
	if err = addEvent(ctx, tx, id, string(status), message, s.now()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ScheduleRetry(ctx context.Context, jobID, worker string, generation int64, at time.Time, maxAttempts int) error {
	if !at.After(s.now()) || maxAttempts < 1 {
		return errors.New("invalid retry schedule")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE jobs SET status='retry_wait',next_attempt_ns=?,lease_owner=NULL,lease_until_ns=NULL WHERE id=? AND status='running' AND lease_owner=? AND lease_generation=? AND lease_until_ns>? AND attempts<? AND deadline_ns>? AND NOT EXISTS(SELECT 1 FROM job_steps WHERE job_id=? AND effect IN ('sent','uncertain'))`, ns(at), jobID, worker, generation, ns(s.now()), maxAttempts, ns(at), jobID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("schedule retry: %w", ErrConflict)
	}
	if err = addEvent(ctx, tx, jobID, "retry_wait", "Retry scheduled", s.now()); err != nil {
		return err
	}
	return tx.Commit()
}

// Renew extends only a claim which is still owned and has not expired.
func (s *Store) Renew(ctx context.Context, id, worker string, generation int64, ttl time.Duration) error {
	if ttl <= 0 {
		return errors.New("invalid lease duration")
	}
	now := s.now()
	res, err := s.DB.ExecContext(ctx, `UPDATE jobs SET lease_until_ns=? WHERE id=? AND status IN ('running','cancel_requested') AND lease_owner=? AND lease_generation=? AND lease_until_ns>?`, ns(now.Add(ttl)), id, worker, generation, ns(now))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	return nil
}

// AcquireResource will not steal a resource from an expired but unresolved job.
func (s *Store) AcquireResource(ctx context.Context, resource, jobID, worker string, generation int64, ttl time.Duration) error {
	if resource == "" || worker == "" || ttl <= 0 {
		return errors.New("invalid resource lease")
	}
	now := s.now()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var valid bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM jobs WHERE id=? AND status='running' AND lease_owner=? AND lease_generation=? AND lease_until_ns>?)`, jobID, worker, generation, ns(now)).Scan(&valid); err != nil {
		return err
	}
	if !valid {
		return ErrConflict
	}
	var existingJob, status string
	var expires int64
	err = tx.QueryRowContext(ctx, `SELECT r.job_id,j.status,r.expires_ns FROM resource_leases r JOIN jobs j ON j.id=r.job_id WHERE r.resource_key=?`, resource).Scan(&existingJob, &status, &expires)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && existingJob != jobID && (expires > ns(now) || status == string(Running) || status == string(CancelRequested) || status == string(NeedsAttention) || status == string(WaitingRemote)) {
		return ErrConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO resource_leases(resource_key,job_id,owner,generation,expires_ns) VALUES(?,?,?,?,?) ON CONFLICT(resource_key) DO UPDATE SET job_id=excluded.job_id,owner=excluded.owner,generation=excluded.generation,expires_ns=excluded.expires_ns`, resource, jobID, worker, generation, ns(now.Add(ttl)))
	if err != nil {
		return err
	}
	return tx.Commit()
}

// ExpirePending fails jobs whose deadline elapsed before their next attempt.
// It deliberately leaves in-flight remote work to reconciliation.
func (s *Store) ExpirePending(ctx context.Context) (int, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	now := s.now()
	rows, err := tx.QueryContext(ctx, `SELECT id FROM jobs WHERE status IN ('queued','retry_wait') AND deadline_ns<=?`, ns(now))
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	for _, id := range ids {
		if _, err = tx.ExecContext(ctx, `UPDATE jobs SET status='failed' WHERE id=?`, id); err != nil {
			return 0, err
		}
		if err = addEvent(ctx, tx, id, "failed", "Deadline expired before execution", now); err != nil {
			return 0, err
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return len(ids), nil
}

func (s *Store) RecoverDue(ctx context.Context) error {
	rows, err := s.DB.QueryContext(ctx, `SELECT id FROM jobs WHERE status IN ('running','cancel_requested') AND lease_until_ns IS NOT NULL AND lease_until_ns<=?`, ns(s.now()))
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, id := range ids {
		if _, err := s.RecoverExpired(ctx, id); err != nil && !errors.Is(err, ErrConflict) {
			return err
		}
	}
	return nil
}

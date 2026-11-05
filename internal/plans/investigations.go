package plans

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"forge/internal/audit"
	"forge/internal/auth"
	"github.com/google/uuid"
)

// Investigation is a read-only task derived from an audit finding, not an
// instruction to modify NetBox. Audit coverage is not sufficient to infer
// that an object is absent or that creating it is safe.
type Investigation struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Rule     string `json:"rule"`
	Status   string `json:"status"`
	Message  string `json:"message"`
}
type InvestigationDraft struct {
	ID               string          `json:"id"`
	AuditID          string          `json:"audit_id"`
	Tasks            []Investigation `json:"tasks"`
	ContentHash      string          `json:"content_hash"`
	CreatedAt        string          `json:"created_at"`
	CurrentFreshness []string        `json:"current_freshness"`
	Completed        []string        `json:"completed"`
	RowVersion       int64           `json:"row_version"`
	UpdatedAt        string          `json:"updated_at"`
}
type InvestigationService struct {
	DB     *sql.DB
	Audits *audit.Service
}

var ErrForbidden = errors.New("investigation access denied")

// CompileInvestigations produces only human investigation tasks. IDs are
// deterministic within the immutable source audit; no finding is interpreted
// as permission to create, change or delete an infrastructure object.
func CompileInvestigations(result audit.Result) []Investigation {
	out := []Investigation{}
	add := func(cat, rule, status, message string, index int) {
		if status != "pass" {
			out = append(out, Investigation{ID: fmt.Sprintf("%s:%d", cat, index), Category: cat, Rule: rule, Status: status, Message: message})
		}
	}
	for i, f := range result.Hardware.Findings {
		add("hardware", f.Rule, f.Status, f.Message, i)
	}
	for i, f := range result.Network.Findings {
		add("network", f.Rule, f.Status, f.Message, i)
	}
	if result.BIOS != nil {
		for i, f := range result.BIOS.Findings {
			add("bios", f.Attribute, f.Status, "Review the active BIOS setting and baseline evidence", i)
		}
		if result.BIOS.Status != "pass" && len(result.BIOS.Findings) == 0 {
			add("bios", "coverage", result.BIOS.Status, result.BIOS.Reason, 0)
		}
	}
	for i, msg := range result.Freshness {
		add("evidence", "freshness", "unknown", msg, i)
	}
	return out
}

// Create compiles exclusively from the saved server audit. The database fence
// rechecks actor, role, selection scope, credential generation and freshness.
func (s *InvestigationService) Create(ctx context.Context, actor auth.User, auditID, selectionID string) (InvestigationDraft, error) {
	if !auth.Allowed(actor, auth.Operate) {
		return InvestigationDraft{}, ErrForbidden
	}
	source, err := s.Audits.Get(ctx, actor, auditID, selectionID)
	if err != nil {
		return InvestigationDraft{}, err
	}
	tasks := CompileInvestigations(*source.Result)
	payload, err := json.Marshal(tasks)
	if err != nil {
		return InvestigationDraft{}, err
	}
	sum := sha256.Sum256(payload)
	draft := InvestigationDraft{ID: uuid.NewString(), AuditID: auditID, Tasks: tasks, ContentHash: hex.EncodeToString(sum[:]), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), CurrentFreshness: source.CurrentFreshness, Completed: []string{}, RowVersion: 1}
	res, err := s.DB.ExecContext(ctx, `INSERT INTO investigation_drafts(id,actor_id,audit_id,content_json,content_hash,created_at)
      SELECT ?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM combined_audits a JOIN network_audits na ON na.id=a.network_audit_id JOIN allocation_imports ai ON ai.id=na.import_id JOIN inventory_selections x ON x.id=? AND x.actor_id=a.actor_id JOIN inventory_snapshots snap ON snap.id=x.snapshot_id AND snap.instance_id=ai.instance_id JOIN netbox_credentials c ON c.instance_id=snap.instance_id AND c.user_id=x.actor_id AND c.generation=snap.credential_generation JOIN netbox_instances n ON n.id=snap.instance_id JOIN environment_memberships m ON m.environment_id=n.environment_id AND m.user_id=x.actor_id JOIN users u ON u.id=x.actor_id AND u.role='full' AND u.disabled=0 WHERE a.id=? AND a.actor_id=? AND x.device_ids_json=ai.device_ids_json AND snap.expires_at_ns>?)`, draft.ID, actor.ID, auditID, string(payload), draft.ContentHash, draft.CreatedAt, selectionID, auditID, actor.ID, time.Now().UnixNano())
	if err != nil {
		return InvestigationDraft{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return InvestigationDraft{}, err
	}
	if n != 1 {
		return InvestigationDraft{}, ErrForbidden
	}
	return draft, nil
}

func (s *InvestigationService) Get(ctx context.Context, actor auth.User, id, selectionID string) (InvestigationDraft, error) {
	if !auth.Allowed(actor, auth.View) {
		return InvestigationDraft{}, ErrForbidden
	}
	var d InvestigationDraft
	var payload, progress string
	err := s.DB.QueryRowContext(ctx, `SELECT id,audit_id,content_json,content_hash,created_at,completed_json,row_version,updated_at FROM investigation_drafts WHERE id=? AND actor_id=?`, id, actor.ID).Scan(&d.ID, &d.AuditID, &payload, &d.ContentHash, &d.CreatedAt, &progress, &d.RowVersion, &d.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return InvestigationDraft{}, ErrForbidden
	}
	if err != nil {
		return InvestigationDraft{}, err
	}
	source, err := s.Audits.Get(ctx, actor, d.AuditID, selectionID)
	if err != nil {
		return InvestigationDraft{}, err
	}
	d.CurrentFreshness = source.CurrentFreshness
	sum := sha256.Sum256([]byte(payload))
	if hex.EncodeToString(sum[:]) != d.ContentHash {
		return InvestigationDraft{}, ErrInvalid
	}
	if json.Unmarshal([]byte(payload), &d.Tasks) != nil || json.Unmarshal([]byte(progress), &d.Completed) != nil {
		return InvestigationDraft{}, ErrInvalid
	}
	if !validProgress(d.Tasks, d.Completed) {
		return InvestigationDraft{}, ErrInvalid
	}
	return d, nil
}

// List only exposes drafts for an audit currently visible through the actor's
// selected device set. The source audit is rechecked after the database read.
func (s *InvestigationService) List(ctx context.Context, actor auth.User, auditID, selectionID string) ([]InvestigationDraft, error) {
	if _, err := s.Audits.Get(ctx, actor, auditID, selectionID); err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id,created_at,content_hash,content_json,completed_json,row_version,updated_at FROM investigation_drafts WHERE audit_id=? AND actor_id=? ORDER BY created_at DESC,id DESC LIMIT 100`, auditID, actor.ID)
	if err != nil {
		return nil, err
	}
	result := []InvestigationDraft{}
	for rows.Next() {
		var d InvestigationDraft
		var payload, progress string
		d.AuditID = auditID
		if err = rows.Scan(&d.ID, &d.CreatedAt, &d.ContentHash, &payload, &progress, &d.RowVersion, &d.UpdatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		sum := sha256.Sum256([]byte(payload))
		if hex.EncodeToString(sum[:]) != d.ContentHash || json.Unmarshal([]byte(payload), &d.Tasks) != nil || json.Unmarshal([]byte(progress), &d.Completed) != nil {
			rows.Close()
			return nil, ErrInvalid
		}
		if !validProgress(d.Tasks, d.Completed) {
			rows.Close()
			return nil, ErrInvalid
		}
		result = append(result, d)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	source, err := s.Audits.Get(ctx, actor, auditID, selectionID)
	if err != nil {
		return nil, err
	}
	for i := range result {
		result[i].CurrentFreshness = source.CurrentFreshness
	}
	return result, nil
}

var ErrConflict = errors.New("investigation progress changed")

func validProgress(tasks []Investigation, completed []string) bool {
	if completed == nil {
		return false
	}
	allowed := make(map[string]bool, len(tasks))
	for _, task := range tasks {
		allowed[task.ID] = true
	}
	seen := map[string]bool{}
	for _, id := range completed {
		if !allowed[id] || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

// UpdateProgress records operator review only. It cannot alter the immutable
// source tasks and is never an approval to change infrastructure.
func (s *InvestigationService) UpdateProgress(ctx context.Context, actor auth.User, id, selectionID string, rowVersion int64, completed []string) (InvestigationDraft, error) {
	if !auth.Allowed(actor, auth.Operate) {
		return InvestigationDraft{}, ErrForbidden
	}
	if rowVersion < 1 || completed == nil {
		return InvestigationDraft{}, ErrInvalid
	}
	d, err := s.Get(ctx, actor, id, selectionID)
	if err != nil {
		return InvestigationDraft{}, err
	}
	if d.RowVersion != rowVersion {
		return InvestigationDraft{}, ErrConflict
	}
	if !validProgress(d.Tasks, completed) {
		return InvestigationDraft{}, ErrInvalid
	}
	sorted := append([]string{}, completed...)
	sort.Strings(sorted)
	payload, err := json.Marshal(sorted)
	if err != nil {
		return InvestigationDraft{}, err
	}
	now := time.Now().UTC()
	res, err := s.DB.ExecContext(ctx, `UPDATE investigation_drafts SET completed_json=?,row_version=row_version+1,updated_at=? WHERE id=? AND actor_id=? AND row_version=? AND content_hash=? AND EXISTS (SELECT 1 FROM combined_audits a JOIN network_audits na ON na.id=a.network_audit_id JOIN allocation_imports ai ON ai.id=na.import_id JOIN inventory_selections x ON x.id=? AND x.actor_id=a.actor_id JOIN inventory_snapshots snap ON snap.id=x.snapshot_id AND snap.instance_id=ai.instance_id JOIN netbox_credentials c ON c.instance_id=snap.instance_id AND c.user_id=x.actor_id AND c.generation=snap.credential_generation JOIN netbox_instances n ON n.id=snap.instance_id JOIN environment_memberships m ON m.environment_id=n.environment_id AND m.user_id=x.actor_id JOIN users u ON u.id=x.actor_id AND u.role='full' AND u.disabled=0 WHERE a.id=investigation_drafts.audit_id AND a.actor_id=? AND x.device_ids_json=ai.device_ids_json AND snap.expires_at_ns>?)`, string(payload), now.Format(time.RFC3339Nano), id, actor.ID, rowVersion, d.ContentHash, selectionID, actor.ID, now.UnixNano())
	if err != nil {
		return InvestigationDraft{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return InvestigationDraft{}, err
	}
	if n != 1 {
		return InvestigationDraft{}, ErrConflict
	}
	return s.Get(ctx, actor, id, selectionID)
}

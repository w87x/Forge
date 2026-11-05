package network

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"forge/internal/auth"
	"forge/internal/inventory"
	"github.com/google/uuid"
)

type SavedAudit struct {
	ID        string       `json:"id"`
	ImportID  string       `json:"import_id"`
	DeviceID  int64        `json:"device_id"`
	CreatedAt string       `json:"created_at"`
	Result    *AuditResult `json:"result,omitempty"`
}

// SaveAudit is called only after a read-only check using the same frozen
// selection. Its SQL fence rejects credential changes and expired visibility.
func (s *ImportService) SaveAudit(ctx context.Context, actor auth.User, selection inventory.Selection, importID string, deviceID int64, result AuditResult) (SavedAudit, error) {
	if !auth.Allowed(actor, auth.Operate) {
		return SavedAudit{}, ErrForbidden
	}
	selected := false
	for _, id := range selection.DeviceIDs {
		if id == deviceID {
			selected = true
			break
		}
	}
	if !selected {
		return SavedAudit{}, ErrForbidden
	}
	data, err := json.Marshal(result)
	if err != nil {
		return SavedAudit{}, err
	}
	item := SavedAudit{ID: uuid.NewString(), ImportID: importID, DeviceID: deviceID, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), Result: &result}
	res, err := s.DB.ExecContext(ctx, `INSERT INTO network_audits(id,actor_id,import_id,device_id,result_json,created_at) SELECT ?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM allocation_imports a JOIN inventory_selections x ON x.id=? JOIN inventory_snapshots snap ON snap.id=x.snapshot_id JOIN netbox_credentials c ON c.instance_id=snap.instance_id AND c.user_id=x.actor_id AND c.generation=snap.credential_generation JOIN netbox_instances n ON n.id=snap.instance_id JOIN environment_memberships m ON m.environment_id=n.environment_id AND m.user_id=x.actor_id JOIN users u ON u.id=x.actor_id AND u.role='full' AND u.disabled=0 WHERE a.id=? AND a.actor_id=? AND a.instance_id=snap.instance_id AND a.device_ids_json=? AND x.actor_id=? AND snap.expires_at_ns>?)`, item.ID, actor.ID, importID, deviceID, string(data), item.CreatedAt, selection.ID, importID, actor.ID, canonicalIDs(selection.DeviceIDs), actor.ID, time.Now().UnixNano())
	if err != nil {
		return SavedAudit{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return SavedAudit{}, err
	}
	if n != 1 {
		return SavedAudit{}, ErrForbidden
	}
	return item, nil
}

// ListAudits uses a fresh matching selection as a visibility proof and never
// returns records for another operator or a different selected device set.
func (s *ImportService) ListAudits(ctx context.Context, actor auth.User, selectionID string) ([]SavedAudit, error) {
	imports, err := s.List(ctx, actor, selectionID)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	for _, item := range imports {
		allowed[item.ID] = true
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id,import_id,device_id,created_at FROM network_audits WHERE actor_id=? ORDER BY created_at DESC,id DESC LIMIT 100`, actor.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []SavedAudit{}
	for rows.Next() {
		var a SavedAudit
		if err = rows.Scan(&a.ID, &a.ImportID, &a.DeviceID, &a.CreatedAt); err != nil {
			return nil, err
		}
		if allowed[a.ImportID] {
			result = append(result, a)
		}
	}
	return result, rows.Err()
}
func (s *ImportService) GetAudit(ctx context.Context, actor auth.User, selectionID, id string) (SavedAudit, error) {
	items, err := s.ListAudits(ctx, actor, selectionID)
	if err != nil {
		return SavedAudit{}, err
	}
	allowed := false
	for _, item := range items {
		if item.ID == id {
			allowed = true
			break
		}
	}
	if !allowed {
		return SavedAudit{}, ErrForbidden
	}
	var item SavedAudit
	var payload string
	err = s.DB.QueryRowContext(ctx, `SELECT id,import_id,device_id,created_at,result_json FROM network_audits WHERE id=? AND actor_id=?`, id, actor.ID).Scan(&item.ID, &item.ImportID, &item.DeviceID, &item.CreatedAt, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return SavedAudit{}, ErrForbidden
	}
	if err != nil {
		return SavedAudit{}, err
	}
	item.Result = &AuditResult{}
	if err = json.Unmarshal([]byte(payload), item.Result); err != nil {
		return SavedAudit{}, err
	}
	selection, err := s.Inventory.Selection(ctx, actor, selectionID)
	if err != nil {
		return SavedAudit{}, err
	}
	if _, err = s.Inventory.Snapshot(ctx, actor, selection.SnapshotID); err != nil {
		return SavedAudit{}, err
	}
	return item, nil
}

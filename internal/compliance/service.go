package compliance

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"forge/internal/auth"
	"forge/internal/inspection"
	"forge/internal/inventory"
	"github.com/google/uuid"
)

var ErrForbidden = errors.New("hardware profile access denied")
var ErrInvalid = errors.New("invalid hardware profile")
var ErrConflict = errors.New("hardware profile changed")

type Profile struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	RowVersion        int       `json:"row_version"`
	PublishedRevision int       `json:"published_revision"`
	Draft             *Hardware `json:"draft,omitempty"`
	Published         *Hardware `json:"published,omitempty"`
}
type Revision struct {
	ProfileID   string   `json:"profile_id"`
	Number      int      `json:"revision"`
	Hardware    Hardware `json:"hardware"`
	Hash        string   `json:"hash"`
	PublishedAt string   `json:"published_at"`
}
type Service struct {
	DB          *sql.DB
	Inspections *inspection.Service
	Inventory   *inventory.Service
}

func (s *Service) Create(ctx context.Context, a auth.User, name string, h Hardware) (Profile, error) {
	if !auth.Allowed(a, auth.Operate) {
		return Profile{}, ErrForbidden
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 || strings.ContainsAny(name, "\x00\r\n") || h.Validate() != nil {
		return Profile{}, ErrInvalid
	}
	data, err := json.Marshal(h)
	if err != nil {
		return Profile{}, ErrInvalid
	}
	p := Profile{ID: uuid.NewString(), Name: name, RowVersion: 1, Draft: &h}
	res, err := s.DB.ExecContext(ctx, `INSERT INTO hardware_profiles(id,name,draft_json,created_at) SELECT ?,?,?,? WHERE EXISTS(SELECT 1 FROM users WHERE id=? AND role='full' AND disabled=0)`, p.ID, name, string(data), time.Now().UTC().Format(time.RFC3339Nano), a.ID)
	if err != nil {
		return Profile{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Profile{}, err
	}
	if n != 1 {
		return Profile{}, ErrForbidden
	}
	return p, nil
}
func (s *Service) Get(ctx context.Context, a auth.User, id string) (Profile, error) {
	if !auth.Allowed(a, auth.View) {
		return Profile{}, ErrForbidden
	}
	var p Profile
	var data string
	err := s.DB.QueryRowContext(ctx, `SELECT id,name,draft_json,row_version,published_revision FROM hardware_profiles WHERE id=?`, id).Scan(&p.ID, &p.Name, &data, &p.RowVersion, &p.PublishedRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return Profile{}, ErrForbidden
	}
	if err != nil {
		return Profile{}, err
	}
	if a.Role == auth.Full {
		p.Draft = &Hardware{}
		if err = json.Unmarshal([]byte(data), p.Draft); err != nil {
			return Profile{}, err
		}
	} else if p.PublishedRevision == 0 {
		return Profile{}, ErrForbidden
	}
	if p.PublishedRevision > 0 {
		r, err := s.Revision(ctx, a, id, p.PublishedRevision)
		if err != nil {
			return Profile{}, err
		}
		p.Published = &r.Hardware
	}
	return p, nil
}
func (s *Service) List(ctx context.Context, a auth.User) ([]Profile, error) {
	if !auth.Allowed(a, auth.View) {
		return nil, ErrForbidden
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id FROM hardware_profiles WHERE (?='full' OR published_revision>0) ORDER BY name,id`, a.Role)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	result := []Profile{}
	for _, id := range ids {
		p, err := s.Get(ctx, a, id)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, nil
}
func (s *Service) Update(ctx context.Context, a auth.User, id string, version int, h Hardware) (Profile, error) {
	if !auth.Allowed(a, auth.Operate) {
		return Profile{}, ErrForbidden
	}
	if _, err := s.Get(ctx, a, id); err != nil {
		return Profile{}, err
	}
	if h.Validate() != nil {
		return Profile{}, ErrInvalid
	}
	data, err := json.Marshal(h)
	if err != nil {
		return Profile{}, ErrInvalid
	}
	res, err := s.DB.ExecContext(ctx, `UPDATE hardware_profiles SET draft_json=?,row_version=row_version+1 WHERE id=? AND row_version=? AND EXISTS(SELECT 1 FROM users WHERE id=? AND role='full' AND disabled=0)`, string(data), id, version, a.ID)
	if err != nil {
		return Profile{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Profile{}, err
	}
	if n != 1 {
		return Profile{}, ErrConflict
	}
	return s.Get(ctx, a, id)
}
func (s *Service) Publish(ctx context.Context, a auth.User, id string, version int) (Revision, error) {
	if !auth.Allowed(a, auth.Operate) {
		return Revision{}, ErrForbidden
	}
	p, err := s.Get(ctx, a, id)
	if err != nil {
		return Revision{}, err
	}
	if version != p.RowVersion {
		return Revision{}, ErrConflict
	}
	if p.Draft == nil || p.Draft.Validate() != nil {
		return Revision{}, ErrInvalid
	}
	h := *p.Draft
	if !h.RequireSerial && !h.RequireModel && h.Manufacturer == "" && h.Model == "" && h.MinCPUSockets == 0 && h.MinMemoryGiB == 0 && h.MinDrives == 0 && h.MinPhysicalNICs == 0 && !h.RequireInterfacesDocumented && h.RAIDExpectation == "" {
		return Revision{}, ErrInvalid
	}
	data, err := json.Marshal(h)
	if err != nil {
		return Revision{}, err
	}
	digest := sha256.Sum256(data)
	r := Revision{ProfileID: id, Number: p.PublishedRevision + 1, Hardware: h, Hash: hex.EncodeToString(digest[:]), PublishedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Revision{}, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE hardware_profiles SET published_revision=?,row_version=row_version+1 WHERE id=? AND row_version=? AND published_revision=? AND EXISTS(SELECT 1 FROM users WHERE id=? AND role='full' AND disabled=0)`, r.Number, id, version, p.PublishedRevision, a.ID)
	if err != nil {
		return Revision{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Revision{}, err
	}
	if n != 1 {
		return Revision{}, ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO hardware_profile_revisions(profile_id,revision,content_json,content_hash,actor_id,published_at) VALUES(?,?,?,?,?,?)`, id, r.Number, string(data), r.Hash, a.ID, r.PublishedAt); err != nil {
		return Revision{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor_id,action,target_id,created_at) VALUES(?,?,?,?,?)`, uuid.NewString(), a.ID, "hardware_profile.publish", id, r.PublishedAt); err != nil {
		return Revision{}, err
	}
	if err = tx.Commit(); err != nil {
		return Revision{}, err
	}
	return r, nil
}
func (s *Service) Revision(ctx context.Context, a auth.User, id string, n int) (Revision, error) {
	if !auth.Allowed(a, auth.View) {
		return Revision{}, ErrForbidden
	}
	var r Revision
	var data string
	err := s.DB.QueryRowContext(ctx, `SELECT profile_id,revision,content_json,content_hash,published_at FROM hardware_profile_revisions WHERE profile_id=? AND revision=?`, id, n).Scan(&r.ProfileID, &r.Number, &data, &r.Hash, &r.PublishedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Revision{}, ErrForbidden
	}
	if err != nil {
		return Revision{}, err
	}
	err = json.Unmarshal([]byte(data), &r.Hardware)
	return r, err
}
func (s *Service) Preview(ctx context.Context, a auth.User, id string, revision int, jobID string) (Result, error) {
	r, err := s.Revision(ctx, a, id, revision)
	if err != nil {
		return Result{}, err
	}
	record, err := s.Inspections.Get(ctx, a, jobID)
	if err != nil {
		return Result{}, err
	}
	var selectionID string
	if err = s.DB.QueryRowContext(ctx, `SELECT selection_id FROM observations WHERE job_id=? AND actor_id=?`, jobID, a.ID).Scan(&selectionID); err != nil {
		return Result{}, ErrForbidden
	}
	var device *inventory.Device
	selection, err := s.Inventory.Selection(ctx, a, selectionID)
	if err != nil {
		return Result{}, err
	}
	if snap, err := s.Inventory.Snapshot(ctx, a, selection.SnapshotID); err == nil {
		for _, d := range snap.Devices {
			if d.ID == record.DeviceID {
				copy := d
				device = &copy
				break
			}
		}
	} else if !errors.Is(err, inventory.ErrStale) {
		return Result{}, err
	}
	return Evaluate(r.Hardware, device, &record, time.Now()), nil
}

type Audit struct {
	ID        string  `json:"id"`
	ProfileID string  `json:"profile_id"`
	Revision  int     `json:"revision"`
	JobID     string  `json:"job_id"`
	CreatedAt string  `json:"created_at"`
	Result    *Result `json:"result,omitempty"`
}

// RunAudit records the result of a fresh evaluation of cached evidence. It
// performs no hardware or NetBox mutations. The original actor owns the run.
func (s *Service) RunAudit(ctx context.Context, a auth.User, id string, revision int, jobID string) (Audit, error) {
	if !auth.Allowed(a, auth.Operate) {
		return Audit{}, ErrForbidden
	}
	result, err := s.Preview(ctx, a, id, revision, jobID)
	if err != nil {
		return Audit{}, err
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return Audit{}, err
	}
	item := Audit{ID: uuid.NewString(), ProfileID: id, Revision: revision, JobID: jobID, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), Result: &result}
	res, err := s.DB.ExecContext(ctx, `INSERT INTO hardware_audits(id,actor_id,profile_id,profile_revision,job_id,result_json,created_at) SELECT ?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM observations o JOIN inventory_selections x ON x.id=o.selection_id JOIN inventory_snapshots snap ON snap.id=x.snapshot_id JOIN netbox_credentials c ON c.instance_id=snap.instance_id AND c.user_id=x.actor_id AND c.generation=snap.credential_generation JOIN netbox_instances n ON n.id=snap.instance_id JOIN environment_memberships m ON m.environment_id=n.environment_id AND m.user_id=x.actor_id JOIN users u ON u.id=x.actor_id AND u.role='full' AND u.disabled=0 JOIN hardware_profile_revisions p ON p.profile_id=? AND p.revision=? WHERE o.job_id=? AND o.actor_id=? AND x.actor_id=?)`, item.ID, a.ID, id, revision, jobID, string(payload), item.CreatedAt, id, revision, jobID, a.ID, a.ID)
	if err != nil {
		return Audit{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Audit{}, err
	}
	if n != 1 {
		return Audit{}, ErrForbidden
	}
	return item, nil
}
func (s *Service) ListAudits(ctx context.Context, a auth.User) ([]Audit, error) {
	if !auth.Allowed(a, auth.View) {
		return nil, ErrForbidden
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id,profile_id,profile_revision,job_id,created_at FROM hardware_audits WHERE actor_id=? ORDER BY created_at DESC,id DESC LIMIT 100`, a.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Audit{}
	for rows.Next() {
		var item Audit
		if err = rows.Scan(&item.ID, &item.ProfileID, &item.Revision, &item.JobID, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
func (s *Service) GetAudit(ctx context.Context, a auth.User, id string) (Audit, error) {
	if !auth.Allowed(a, auth.View) {
		return Audit{}, ErrForbidden
	}
	var item Audit
	var data string
	err := s.DB.QueryRowContext(ctx, `SELECT id,profile_id,profile_revision,job_id,created_at,result_json FROM hardware_audits WHERE id=? AND actor_id=?`, id, a.ID).Scan(&item.ID, &item.ProfileID, &item.Revision, &item.JobID, &item.CreatedAt, &data)
	if errors.Is(err, sql.ErrNoRows) {
		return Audit{}, ErrForbidden
	}
	if err != nil {
		return Audit{}, err
	}
	if _, err = s.Inspections.Get(ctx, a, item.JobID); err != nil {
		return Audit{}, err
	}
	item.Result = &Result{}
	if err = json.Unmarshal([]byte(data), item.Result); err != nil {
		return Audit{}, err
	}
	return item, nil
}

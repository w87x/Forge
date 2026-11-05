package bios

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
	"github.com/google/uuid"
)

var ErrForbidden = errors.New("BIOS profile access denied")
var ErrInvalid = errors.New("invalid BIOS profile")
var ErrConflict = errors.New("BIOS profile changed")

type Profile struct {
	ID                string    `json:"id"`
	EnvironmentID     string    `json:"environment_id"`
	Name              string    `json:"name"`
	RowVersion        int       `json:"row_version"`
	PublishedRevision int       `json:"published_revision"`
	Draft             []Variant `json:"draft,omitempty"`
	Published         []Variant `json:"published,omitempty"`
}
type Revision struct {
	ProfileID   string    `json:"profile_id"`
	Number      int       `json:"revision"`
	Variants    []Variant `json:"variants"`
	Hash        string    `json:"hash"`
	PublishedAt string    `json:"published_at"`
}
type Service struct {
	DB          *sql.DB
	Auth        *auth.Service
	Inspections *inspection.Service
}

func (s *Service) access(ctx context.Context, actor auth.User, env string, action auth.Action) error {
	ok, err := s.Auth.EnvironmentAllowed(ctx, actor, action, env)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	return nil
}
func (s *Service) environmentForJob(ctx context.Context, jobID string) (string, error) {
	var env string
	err := s.DB.QueryRowContext(ctx, `SELECT n.environment_id FROM observations o JOIN servers s ON s.id=o.server_id JOIN netbox_instances n ON n.id=s.instance_id WHERE o.job_id=?`, jobID).Scan(&env)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrForbidden
	}
	return env, err
}
func (s *Service) reference(ctx context.Context, actor auth.User, jobID string, attributes []string) (Variant, string, error) {
	if !auth.Allowed(actor, auth.Operate) {
		return Variant{}, "", ErrForbidden
	}
	record, err := s.Inspections.Get(ctx, actor, jobID)
	if err != nil {
		return Variant{}, "", err
	}
	// A stale observation remains useful for review, but is not a reference
	// for creating new expectations without a fresh inspection.
	if record.CollectedAt.After(time.Now().Add(time.Minute)) || time.Since(record.CollectedAt) > 24*time.Hour {
		return Variant{}, "", ErrInvalidReference
	}
	env, err := s.environmentForJob(ctx, jobID)
	if err != nil {
		return Variant{}, "", err
	}
	if err = s.access(ctx, actor, env, auth.Operate); err != nil {
		return Variant{}, "", err
	}
	v, err := Capture(record, attributes)
	return v, env, err
}
func (s *Service) Create(ctx context.Context, actor auth.User, name, jobID string, attrs []string) (Profile, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 || strings.ContainsAny(name, "\x00\r\n") {
		return Profile{}, ErrInvalid
	}
	v, _, err := s.reference(ctx, actor, jobID, attrs)
	if err != nil {
		return Profile{}, err
	}
	env := auth.SharedWorkspaceID
	p := Profile{ID: uuid.NewString(), EnvironmentID: env, Name: name, RowVersion: 1, Draft: []Variant{v}}
	data, err := json.Marshal(p.Draft)
	if err != nil {
		return Profile{}, err
	}
	res, err := s.DB.ExecContext(ctx, `INSERT INTO bios_profiles(id,environment_id,name,draft_json,created_at) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM users u JOIN environment_memberships m ON m.user_id=u.id WHERE u.id=? AND u.disabled=0 AND u.role='full' AND m.environment_id=?)`, p.ID, env, name, string(data), time.Now().UTC().Format(time.RFC3339Nano), actor.ID, env)
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
func (s *Service) Get(ctx context.Context, actor auth.User, id string) (Profile, error) {
	var p Profile
	var draft string
	err := s.DB.QueryRowContext(ctx, `SELECT id,environment_id,name,row_version,published_revision,draft_json FROM bios_profiles WHERE id=?`, id).Scan(&p.ID, &p.EnvironmentID, &p.Name, &p.RowVersion, &p.PublishedRevision, &draft)
	if errors.Is(err, sql.ErrNoRows) {
		return Profile{}, ErrForbidden
	}
	if err != nil {
		return Profile{}, err
	}
	if err = s.access(ctx, actor, p.EnvironmentID, auth.View); err != nil {
		return Profile{}, err
	}
	if actor.Role == auth.Full {
		if err = json.Unmarshal([]byte(draft), &p.Draft); err != nil {
			return Profile{}, err
		}
	} else if p.PublishedRevision == 0 {
		return Profile{}, ErrForbidden
	}
	if p.PublishedRevision > 0 {
		r, err := s.Revision(ctx, actor, id, p.PublishedRevision)
		if err != nil {
			return Profile{}, err
		}
		p.Published = r.Variants
	}
	return p, nil
}
func (s *Service) List(ctx context.Context, actor auth.User) ([]Profile, error) {
	if !auth.Allowed(actor, auth.View) {
		return nil, ErrForbidden
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT p.id FROM bios_profiles p JOIN environment_memberships m ON m.environment_id=p.environment_id WHERE m.user_id=? AND (?='full' OR p.published_revision>0) ORDER BY p.name,p.id`, actor.ID, actor.Role)
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
	items := []Profile{}
	for _, id := range ids {
		p, err := s.Get(ctx, actor, id)
		if err != nil {
			return nil, err
		}
		items = append(items, p)
	}
	return items, nil
}
func sameVariant(a, b Variant) bool {
	return a.Manufacturer == b.Manufacturer && a.Model == b.Model && a.Firmware == b.Firmware && a.Registry == b.Registry && a.RegistryHash == b.RegistryHash
}
func (s *Service) AddVariant(ctx context.Context, actor auth.User, id string, version int, jobID string, attrs []string) (Profile, error) {
	p, err := s.Get(ctx, actor, id)
	if err != nil {
		return Profile{}, err
	}
	if err = s.access(ctx, actor, p.EnvironmentID, auth.Operate); err != nil {
		return Profile{}, err
	}
	if p.RowVersion != version {
		return Profile{}, ErrConflict
	}
	v, _, err := s.reference(ctx, actor, jobID, attrs)
	if err != nil {
		return Profile{}, err
	}
	variants := append([]Variant(nil), p.Draft...)
	replaced := false
	for i := range variants {
		if sameVariant(variants[i], v) {
			variants[i] = v
			replaced = true
			break
		}
	}
	if !replaced {
		if len(variants) >= 100 {
			return Profile{}, ErrInvalid
		}
		variants = append(variants, v)
	}
	data, err := json.Marshal(variants)
	if err != nil {
		return Profile{}, err
	}
	res, err := s.DB.ExecContext(ctx, `UPDATE bios_profiles SET draft_json=?,row_version=row_version+1 WHERE id=? AND row_version=? AND EXISTS(SELECT 1 FROM users u JOIN environment_memberships m ON m.user_id=u.id WHERE u.id=? AND u.disabled=0 AND u.role='full' AND m.environment_id=bios_profiles.environment_id)`, string(data), id, version, actor.ID)
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
	return s.Get(ctx, actor, id)
}

func (s *Service) RemoveVariant(ctx context.Context, actor auth.User, id string, version, index int) (Profile, error) {
	p, err := s.Get(ctx, actor, id)
	if err != nil {
		return Profile{}, err
	}
	if err = s.access(ctx, actor, p.EnvironmentID, auth.Operate); err != nil {
		return Profile{}, err
	}
	if p.RowVersion != version {
		return Profile{}, ErrConflict
	}
	if index < 0 || index >= len(p.Draft) {
		return Profile{}, ErrInvalid
	}
	variants := append([]Variant{}, p.Draft[:index]...)
	variants = append(variants, p.Draft[index+1:]...)
	data, err := json.Marshal(variants)
	if err != nil {
		return Profile{}, err
	}
	res, err := s.DB.ExecContext(ctx, `UPDATE bios_profiles SET draft_json=?,row_version=row_version+1 WHERE id=? AND row_version=? AND EXISTS(SELECT 1 FROM users u JOIN environment_memberships m ON m.user_id=u.id WHERE u.id=? AND u.disabled=0 AND u.role='full' AND m.environment_id=bios_profiles.environment_id)`, string(data), id, version, actor.ID)
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
	return s.Get(ctx, actor, id)
}
func (s *Service) Publish(ctx context.Context, actor auth.User, id string, version int) (Revision, error) {
	p, err := s.Get(ctx, actor, id)
	if err != nil {
		return Revision{}, err
	}
	if err = s.access(ctx, actor, p.EnvironmentID, auth.Operate); err != nil {
		return Revision{}, err
	}
	if p.RowVersion != version {
		return Revision{}, ErrConflict
	}
	if len(p.Draft) == 0 {
		return Revision{}, ErrInvalid
	}
	data, err := json.Marshal(p.Draft)
	if err != nil {
		return Revision{}, err
	}
	hash := sha256.Sum256(data)
	r := Revision{ProfileID: id, Number: p.PublishedRevision + 1, Variants: p.Draft, Hash: hex.EncodeToString(hash[:]), PublishedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Revision{}, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE bios_profiles SET published_revision=?,row_version=row_version+1 WHERE id=? AND row_version=? AND published_revision=? AND EXISTS(SELECT 1 FROM users u JOIN environment_memberships m ON m.user_id=u.id WHERE u.id=? AND u.disabled=0 AND u.role='full' AND m.environment_id=bios_profiles.environment_id)`, r.Number, id, version, p.PublishedRevision, actor.ID)
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
	if _, err = tx.ExecContext(ctx, `INSERT INTO bios_profile_revisions(profile_id,revision,content_json,content_hash,actor_id,published_at) VALUES(?,?,?,?,?,?)`, id, r.Number, string(data), r.Hash, actor.ID, r.PublishedAt); err != nil {
		return Revision{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor_id,action,target_id,created_at) VALUES(?,?,?,?,?)`, uuid.NewString(), actor.ID, "bios_profile.publish", id, r.PublishedAt); err != nil {
		return Revision{}, err
	}
	if err = tx.Commit(); err != nil {
		return Revision{}, err
	}
	return r, nil
}
func (s *Service) Revision(ctx context.Context, actor auth.User, id string, num int) (Revision, error) {
	var r Revision
	var env, data string
	err := s.DB.QueryRowContext(ctx, `SELECT r.profile_id,r.revision,r.content_json,r.content_hash,r.published_at,p.environment_id FROM bios_profile_revisions r JOIN bios_profiles p ON p.id=r.profile_id WHERE r.profile_id=? AND r.revision=?`, id, num).Scan(&r.ProfileID, &r.Number, &data, &r.Hash, &r.PublishedAt, &env)
	if errors.Is(err, sql.ErrNoRows) {
		return Revision{}, ErrForbidden
	}
	if err != nil {
		return Revision{}, err
	}
	if err = s.access(ctx, actor, env, auth.View); err != nil {
		return Revision{}, err
	}
	err = json.Unmarshal([]byte(data), &r.Variants)
	return r, err
}
func (s *Service) CompareJob(ctx context.Context, actor auth.User, id string, num int, jobID string) (Comparison, error) {
	p, err := s.Get(ctx, actor, id)
	if err != nil {
		return Comparison{}, err
	}
	r, err := s.Revision(ctx, actor, id, num)
	if err != nil {
		return Comparison{}, err
	}
	record, err := s.Inspections.Get(ctx, actor, jobID)
	if err != nil {
		return Comparison{}, err
	}
	_, err = s.environmentForJob(ctx, jobID)
	if err != nil {
		return Comparison{}, err
	}
	if err = s.access(ctx, actor, p.EnvironmentID, auth.View); err != nil {
		return Comparison{}, err
	}
	if record.IdentityStatus != "match" {
		return Comparison{Status: "unknown", Reason: "server identity is not verified", Findings: []Finding{}}, nil
	}
	if record.CollectedAt.After(time.Now().Add(time.Minute)) || time.Since(record.CollectedAt) > 24*time.Hour {
		return Comparison{Status: "unknown", Reason: "inspection is older than 24 hours or has an invalid timestamp", Findings: []Finding{}}, nil
	}
	for _, v := range r.Variants {
		if v.Manufacturer == record.Observed.Manufacturer && v.Model == record.Observed.Model && v.Firmware == record.Observed.BIOSVersion && v.Registry == record.Observed.BIOSRegistry && v.RegistryHash == record.Observed.BIOSRegistryHash {
			return Compare(v, record.Observed), nil
		}
	}
	if record.Observed.Manufacturer == "" || record.Observed.Model == "" || record.Observed.BIOSVersion == "" || record.Observed.BIOSRegistry == "" || record.Observed.BIOSRegistryHash == "" || record.Observed.BIOSRegistryCoverage != "available" {
		return Comparison{Status: "unknown", Reason: "missing compatibility evidence", Findings: []Finding{}}, nil
	}
	return Comparison{Status: "not_applicable", Reason: "no compatible vendor, model, firmware and registry variant", Findings: []Finding{}}, nil
}

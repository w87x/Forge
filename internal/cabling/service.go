package cabling

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
	"github.com/google/uuid"
)

var ErrForbidden = errors.New("cabling profile access denied")
var ErrConflict = errors.New("cabling profile changed")

type StoredProfile struct {
	ID                       string   `json:"id"`
	Name                     string   `json:"name"`
	RowVersion               int      `json:"row_version"`
	PublishedRevision        int      `json:"published_revision"`
	Draft                    *Profile `json:"draft,omitempty"`
	Published                *Profile `json:"published,omitempty"`
	NetBoxReferencesVerified bool     `json:"netbox_references_verified"`
}
type Revision struct {
	ProfileID                string  `json:"profile_id"`
	Number                   int     `json:"number"`
	Profile                  Profile `json:"profile"`
	Hash                     string  `json:"hash"`
	PublishedAt              string  `json:"published_at"`
	NetBoxReferencesVerified bool    `json:"netbox_references_verified"`
}
type Service struct{ DB *sql.DB }

func normalize(p *Profile) {
	if p.Switches == nil {
		p.Switches = []Switch{}
	}
	if p.PreferredRacks == nil {
		p.PreferredRacks = []int64{}
	}
	if p.Requirements == nil {
		p.Requirements = []RequirementSpec{}
	}
}
func (s *Service) Create(ctx context.Context, a auth.User, name string) (StoredProfile, error) {
	if !auth.Allowed(a, auth.Operate) {
		return StoredProfile{}, ErrForbidden
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 || strings.ContainsAny(name, "\x00\r\n") {
		return StoredProfile{}, ErrInvalid
	}
	p := Profile{}
	normalize(&p)
	b, _ := json.Marshal(p)
	out := StoredProfile{ID: uuid.NewString(), Name: name, RowVersion: 1, Draft: &p}
	res, err := s.DB.ExecContext(ctx, `INSERT INTO cabling_profiles(id,name,draft_json,created_at) SELECT ?,?,?,? WHERE EXISTS(SELECT 1 FROM users WHERE id=? AND role='full' AND disabled=0)`, out.ID, name, string(b), time.Now().UTC().Format(time.RFC3339Nano), a.ID)
	if err != nil {
		return StoredProfile{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return StoredProfile{}, err
	}
	if n != 1 {
		return StoredProfile{}, ErrForbidden
	}
	return out, nil
}
func (s *Service) Get(ctx context.Context, a auth.User, id string) (StoredProfile, error) {
	if !auth.Allowed(a, auth.View) {
		return StoredProfile{}, ErrForbidden
	}
	var p StoredProfile
	var data string
	err := s.DB.QueryRowContext(ctx, `SELECT id,name,row_version,published_revision,draft_json FROM cabling_profiles WHERE id=?`, id).Scan(&p.ID, &p.Name, &p.RowVersion, &p.PublishedRevision, &data)
	if errors.Is(err, sql.ErrNoRows) {
		return StoredProfile{}, ErrForbidden
	}
	if err != nil {
		return StoredProfile{}, err
	}
	if a.Role == auth.Full {
		p.Draft = &Profile{}
		if err = json.Unmarshal([]byte(data), p.Draft); err != nil {
			return StoredProfile{}, err
		}
		normalize(p.Draft)
	} else if p.PublishedRevision == 0 {
		return StoredProfile{}, ErrForbidden
	}
	if p.PublishedRevision > 0 {
		r, err := s.Revision(ctx, a, id, p.PublishedRevision)
		if err != nil {
			return StoredProfile{}, err
		}
		p.Published = &r.Profile
	}
	return p, nil
}
func (s *Service) List(ctx context.Context, a auth.User) ([]StoredProfile, error) {
	if !auth.Allowed(a, auth.View) {
		return nil, ErrForbidden
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id FROM cabling_profiles WHERE ?='full' OR published_revision>0 ORDER BY name,id`, a.Role)
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
	out := []StoredProfile{}
	for _, id := range ids {
		p, err := s.Get(ctx, a, id)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}
func (s *Service) Update(ctx context.Context, a auth.User, id string, version int, p Profile) (StoredProfile, error) {
	if !auth.Allowed(a, auth.Operate) {
		return StoredProfile{}, ErrForbidden
	}
	if len(p.Switches) > 256 || len(p.PreferredRacks) > 256 || len(p.Requirements) > 8 {
		return StoredProfile{}, ErrInvalid
	}
	normalize(&p)
	data, err := json.Marshal(p)
	if err != nil || len(data) > 1<<20 {
		return StoredProfile{}, ErrInvalid
	}
	res, err := s.DB.ExecContext(ctx, `UPDATE cabling_profiles SET draft_json=?,row_version=row_version+1 WHERE id=? AND row_version=? AND EXISTS(SELECT 1 FROM users WHERE id=? AND role='full' AND disabled=0)`, string(data), id, version, a.ID)
	if err != nil {
		return StoredProfile{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return StoredProfile{}, err
	}
	if n != 1 {
		return StoredProfile{}, ErrConflict
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
	if p.RowVersion != version {
		return Revision{}, ErrConflict
	}
	if p.Draft == nil {
		return Revision{}, ErrInvalid
	}
	if err = ValidateProfile(*p.Draft); err != nil {
		return Revision{}, err
	}
	data, err := json.Marshal(p.Draft)
	if err != nil {
		return Revision{}, err
	}
	hash := sha256.Sum256(data)
	r := Revision{ProfileID: id, Number: p.PublishedRevision + 1, Profile: *p.Draft, Hash: hex.EncodeToString(hash[:]), PublishedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Revision{}, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE cabling_profiles SET published_revision=?,row_version=row_version+1 WHERE id=? AND row_version=? AND published_revision=? AND EXISTS(SELECT 1 FROM users u JOIN environment_memberships m ON m.user_id=u.id JOIN netbox_instances n ON n.environment_id=m.environment_id WHERE u.id=? AND u.role='full' AND u.disabled=0 AND n.id=?)`, r.Number, id, version, p.PublishedRevision, a.ID, p.Draft.NetBoxInstanceID)
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
	if _, err = tx.ExecContext(ctx, `INSERT INTO cabling_profile_revisions(profile_id,revision,content_json,content_hash,actor_id,published_at) VALUES(?,?,?,?,?,?)`, id, r.Number, string(data), r.Hash, a.ID, r.PublishedAt); err != nil {
		return Revision{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor_id,action,target_id,created_at) VALUES(?,?,?,?,?)`, uuid.NewString(), a.ID, "cabling_profile.publish", id, r.PublishedAt); err != nil {
		return Revision{}, err
	}
	if err = tx.Commit(); err != nil {
		return Revision{}, err
	}
	return r, nil
}
func (s *Service) Revision(ctx context.Context, a auth.User, id string, num int) (Revision, error) {
	if !auth.Allowed(a, auth.View) {
		return Revision{}, ErrForbidden
	}
	var r Revision
	var data string
	err := s.DB.QueryRowContext(ctx, `SELECT profile_id,revision,content_json,content_hash,published_at FROM cabling_profile_revisions WHERE profile_id=? AND revision=?`, id, num).Scan(&r.ProfileID, &r.Number, &data, &r.Hash, &r.PublishedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Revision{}, ErrForbidden
	}
	if err != nil {
		return Revision{}, err
	}
	if err = json.Unmarshal([]byte(data), &r.Profile); err != nil {
		return Revision{}, err
	}
	normalize(&r.Profile)
	return r, nil
}

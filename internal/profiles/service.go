package profiles

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
	"forge/internal/secrets"
	"github.com/google/uuid"
)

type Profile struct {
	ID                string      `json:"id"`
	EnvironmentID     string      `json:"environment_id"`
	Name              string      `json:"name"`
	Kind              string      `json:"kind"`
	RowVersion        int         `json:"row_version"`
	PublishedRevision int         `json:"published_revision"`
	Draft             *Connection `json:"draft,omitempty"`
	Published         *Connection `json:"published,omitempty"`
}
type Revision struct {
	ProfileID   string     `json:"profile_id"`
	Number      int        `json:"revision"`
	Content     Connection `json:"content"`
	Hash        string     `json:"hash"`
	PublishedAt string     `json:"published_at"`
}
type Service struct {
	DB    *sql.DB
	Auth  *auth.Service
	Vault *secrets.Vault
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

func (s *Service) Create(ctx context.Context, actor auth.User, env, name string, draft Connection) (Profile, error) {
	if err := s.access(ctx, actor, env, auth.Operate); err != nil {
		return Profile{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 || strings.ContainsAny(name, "\x00\r\n") {
		return Profile{}, ErrInvalid
	}
	encoded, err := json.Marshal(draft)
	if err != nil {
		return Profile{}, err
	}
	p := Profile{ID: uuid.NewString(), EnvironmentID: env, Name: name, Kind: "connection", RowVersion: 1, Draft: &draft}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO profiles(id,environment_id,name,kind,draft_json,created_at) VALUES(?,?,?,'connection',?,?)`, p.ID, env, name, string(encoded), time.Now().UTC().Format(time.RFC3339Nano))
	return p, err
}
func (s *Service) Get(ctx context.Context, actor auth.User, id string) (Profile, error) {
	var p Profile
	var draft string
	err := s.DB.QueryRowContext(ctx, `SELECT id,environment_id,name,kind,draft_json,row_version,published_revision FROM profiles WHERE id=?`, id).Scan(&p.ID, &p.EnvironmentID, &p.Name, &p.Kind, &draft, &p.RowVersion, &p.PublishedRevision)
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
		var c Connection
		if err = json.Unmarshal([]byte(draft), &c); err != nil {
			return Profile{}, err
		}
		p.Draft = &c
	}
	if p.PublishedRevision > 0 {
		revision, err := s.Revision(ctx, actor, p.ID, p.PublishedRevision)
		if err != nil {
			return Profile{}, err
		}
		p.Published = &revision.Content
	} else if actor.Role != auth.Full {
		return Profile{}, ErrForbidden
	}
	return p, nil
}
func (s *Service) List(ctx context.Context, actor auth.User) ([]Profile, error) {
	if !auth.Allowed(actor, auth.View) {
		return nil, ErrForbidden
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT p.id FROM profiles p JOIN environment_memberships m ON m.environment_id=p.environment_id WHERE m.user_id=? AND (?='full' OR p.published_revision>0) ORDER BY p.name,p.id`, actor.ID, actor.Role)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
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
func (s *Service) Update(ctx context.Context, actor auth.User, id string, version int, draft Connection) (Profile, error) {
	p, err := s.Get(ctx, actor, id)
	if err != nil {
		return Profile{}, err
	}
	if err = s.access(ctx, actor, p.EnvironmentID, auth.Operate); err != nil {
		return Profile{}, err
	}
	if version < 1 {
		return Profile{}, ErrInvalid
	}
	encoded, err := json.Marshal(draft)
	if err != nil {
		return Profile{}, err
	}
	res, err := s.DB.ExecContext(ctx, `UPDATE profiles SET draft_json=?,row_version=row_version+1 WHERE id=? AND row_version=?`, string(encoded), id, version)
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
	if p.Draft == nil || version != p.RowVersion {
		return Revision{}, ErrConflict
	}
	if err = p.Draft.Validate(); err != nil {
		return Revision{}, err
	}
	for _, secretID := range []string{p.Draft.StaticSecretID, p.Draft.PrefixSecretID, p.Draft.SuffixSecretID} {
		if secretID != "" {
			if _, err = s.Vault.SharedSecret(ctx, actor, secretID); err != nil {
				return Revision{}, ErrInvalid
			}
		}
	}
	encoded, err := json.Marshal(p.Draft)
	if err != nil {
		return Revision{}, err
	}
	hash := sha256.Sum256(encoded)
	r := Revision{ProfileID: id, Number: p.PublishedRevision + 1, Content: *p.Draft, Hash: hex.EncodeToString(hash[:]), PublishedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Revision{}, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE profiles SET published_revision=?,row_version=row_version+1 WHERE id=? AND row_version=? AND published_revision=?`, r.Number, id, version, p.PublishedRevision)
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
	if _, err = tx.ExecContext(ctx, `INSERT INTO profile_revisions(profile_id,revision,content_json,content_hash,actor_id,published_at) VALUES(?,?,?,?,?,?)`, id, r.Number, string(encoded), r.Hash, actor.ID, r.PublishedAt); err != nil {
		return Revision{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor_id,action,target_id,created_at) VALUES(?,?,?,?,?)`, uuid.NewString(), actor.ID, "profile.publish", id, r.PublishedAt); err != nil {
		return Revision{}, err
	}
	if err = tx.Commit(); err != nil {
		return Revision{}, err
	}
	return r, nil
}
func (s *Service) Revision(ctx context.Context, actor auth.User, id string, number int) (Revision, error) {
	var r Revision
	var env, payload string
	err := s.DB.QueryRowContext(ctx, `SELECT r.profile_id,r.revision,r.content_json,r.content_hash,r.published_at,p.environment_id FROM profile_revisions r JOIN profiles p ON p.id=r.profile_id WHERE r.profile_id=? AND r.revision=?`, id, number).Scan(&r.ProfileID, &r.Number, &payload, &r.Hash, &r.PublishedAt, &env)
	if errors.Is(err, sql.ErrNoRows) {
		return Revision{}, ErrForbidden
	}
	if err != nil {
		return Revision{}, err
	}
	if err = s.access(ctx, actor, env, auth.View); err != nil {
		return Revision{}, err
	}
	if err = json.Unmarshal([]byte(payload), &r.Content); err != nil {
		return Revision{}, err
	}
	return r, nil
}

// Password resolves environment-scoped secret segments only for a full operator.
// The caller must erase the returned bytes after use and must never persist them.
func (s *Service) Password(ctx context.Context, actor auth.User, environmentID string, c Connection, bmcIP, declaredSerial string) ([]byte, error) {
	if err := s.access(ctx, actor, environmentID, auth.Operate); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	load := func(id string) ([]byte, error) {
		if id == "" {
			return nil, nil
		}
		if _, err := s.Vault.SharedSecret(ctx, actor, id); err != nil {
			return nil, ErrInvalid
		}
		return s.Vault.Get(ctx, actor, id)
	}
	var static, prefix, suffix []byte
	defer func() {
		for _, part := range [][]byte{static, prefix, suffix} {
			for i := range part {
				part[i] = 0
			}
		}
	}()
	var err error
	if static, err = load(c.StaticSecretID); err != nil {
		return nil, err
	}
	if prefix, err = load(c.PrefixSecretID); err != nil {
		return nil, err
	}
	if suffix, err = load(c.SuffixSecretID); err != nil {
		return nil, err
	}
	return Compose(c, bmcIP, declaredSerial, static, prefix, suffix)
}

package network

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

var ErrForbidden = errors.New("network profile access denied")
var ErrInvalid = errors.New("invalid network profile")
var ErrConflict = errors.New("network profile changed")

type Profile struct {
	ID                       string `json:"id"`
	EnvironmentID            string `json:"environment_id"`
	Name                     string `json:"name"`
	RowVersion               int    `json:"row_version"`
	PublishedRevision        int    `json:"published_revision"`
	Draft                    *Graph `json:"draft,omitempty"`
	Published                *Graph `json:"published,omitempty"`
	NetBoxReferencesVerified bool   `json:"netbox_references_verified"`
}
type Revision struct {
	ProfileID                string `json:"profile_id"`
	Number                   int    `json:"revision"`
	Graph                    Graph  `json:"graph"`
	Hash                     string `json:"hash"`
	PublishedAt              string `json:"published_at"`
	NetBoxReferencesVerified bool   `json:"netbox_references_verified"`
}
type Service struct {
	DB   *sql.DB
	Auth *auth.Service
}

func normalizeGraph(g *Graph) {
	if g.Nodes == nil {
		g.Nodes = []Node{}
	}
	if g.Networks == nil {
		g.Networks = []Network{}
	}
	for i := range g.Nodes {
		if g.Nodes[i].Members == nil {
			g.Nodes[i].Members = []string{}
		}
	}
}

func (s *Service) access(ctx context.Context, a auth.User, env string, action auth.Action) error {
	ok, err := s.Auth.EnvironmentAllowed(ctx, a, action, env)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	return nil
}
func (s *Service) Create(ctx context.Context, a auth.User, env, name string) (Profile, error) {
	if err := s.access(ctx, a, env, auth.Operate); err != nil {
		return Profile{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 || strings.ContainsAny(name, "\x00\r\n") {
		return Profile{}, ErrInvalid
	}
	p := Profile{ID: uuid.NewString(), EnvironmentID: env, Name: name, RowVersion: 1, Draft: &Graph{Nodes: []Node{}, Networks: []Network{}}}
	data, _ := json.Marshal(p.Draft)
	res, err := s.DB.ExecContext(ctx, `INSERT INTO network_profiles(id,environment_id,name,draft_json,created_at) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM users u JOIN environment_memberships m ON m.user_id=u.id WHERE u.id=? AND u.disabled=0 AND u.role='full' AND m.environment_id=?)`, p.ID, env, name, string(data), time.Now().UTC().Format(time.RFC3339Nano), a.ID, env)
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
	var p Profile
	var data string
	err := s.DB.QueryRowContext(ctx, `SELECT id,environment_id,name,draft_json,row_version,published_revision FROM network_profiles WHERE id=?`, id).Scan(&p.ID, &p.EnvironmentID, &p.Name, &data, &p.RowVersion, &p.PublishedRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return Profile{}, ErrForbidden
	}
	if err != nil {
		return Profile{}, err
	}
	if err = s.access(ctx, a, p.EnvironmentID, auth.View); err != nil {
		return Profile{}, err
	}
	if a.Role == auth.Full {
		p.Draft = &Graph{}
		if err = json.Unmarshal([]byte(data), p.Draft); err != nil {
			return Profile{}, err
		}
		normalizeGraph(p.Draft)
	} else if p.PublishedRevision == 0 {
		return Profile{}, ErrForbidden
	}
	if p.PublishedRevision > 0 {
		r, err := s.Revision(ctx, a, id, p.PublishedRevision)
		if err != nil {
			return Profile{}, err
		}
		p.Published = &r.Graph
	}
	return p, nil
}
func (s *Service) List(ctx context.Context, a auth.User) ([]Profile, error) {
	if !auth.Allowed(a, auth.View) {
		return nil, ErrForbidden
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT p.id FROM network_profiles p JOIN environment_memberships m ON m.environment_id=p.environment_id WHERE m.user_id=? AND (?='full' OR p.published_revision>0) ORDER BY p.name,p.id`, a.ID, a.Role)
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
	out := []Profile{}
	for _, id := range ids {
		p, err := s.Get(ctx, a, id)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}
func (s *Service) Update(ctx context.Context, a auth.User, id string, version int, g Graph) (Profile, error) {
	p, err := s.Get(ctx, a, id)
	if err != nil {
		return Profile{}, err
	}
	if err = s.access(ctx, a, p.EnvironmentID, auth.Operate); err != nil {
		return Profile{}, err
	}
	if len(g.Nodes) > 256 || len(g.Networks) > 256 {
		return Profile{}, ErrInvalid
	}
	normalizeGraph(&g)
	data, err := json.Marshal(g)
	if err != nil || len(data) > 1<<20 {
		return Profile{}, ErrInvalid
	}
	res, err := s.DB.ExecContext(ctx, `UPDATE network_profiles SET draft_json=?,row_version=row_version+1 WHERE id=? AND row_version=? AND EXISTS(SELECT 1 FROM users u JOIN environment_memberships m ON m.user_id=u.id WHERE u.id=? AND u.disabled=0 AND u.role='full' AND m.environment_id=network_profiles.environment_id)`, string(data), id, version, a.ID)
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
func (s *Service) Publish(ctx context.Context, a auth.User, id string, version int) (Revision, []Issue, error) {
	p, err := s.Get(ctx, a, id)
	if err != nil {
		return Revision{}, nil, err
	}
	if err = s.access(ctx, a, p.EnvironmentID, auth.Operate); err != nil {
		return Revision{}, nil, err
	}
	if p.RowVersion != version {
		return Revision{}, nil, ErrConflict
	}
	if p.Draft == nil || len(p.Draft.Nodes) == 0 || len(p.Draft.Networks) == 0 {
		return Revision{}, []Issue{{Field: "graph", Message: "at least one interface and network are required"}}, ErrInvalid
	}
	if issues := Validate(*p.Draft); len(issues) > 0 {
		return Revision{}, issues, ErrInvalid
	}
	if p.Draft.NetBoxInstanceID != "" {
		var visible bool
		if err = s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM netbox_instances n JOIN environment_memberships m ON m.environment_id=n.environment_id WHERE n.id=? AND m.user_id=?)`, p.Draft.NetBoxInstanceID, a.ID).Scan(&visible); err != nil {
			return Revision{}, nil, err
		}
		if !visible {
			return Revision{}, []Issue{{Field: "netbox_instance_id", Message: "NetBox connection is unavailable"}}, ErrInvalid
		}
	}
	data, err := json.Marshal(p.Draft)
	if err != nil {
		return Revision{}, nil, err
	}
	digest := sha256.Sum256(data)
	r := Revision{ProfileID: id, Number: p.PublishedRevision + 1, Graph: *p.Draft, Hash: hex.EncodeToString(digest[:]), PublishedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Revision{}, nil, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE network_profiles SET published_revision=?,row_version=row_version+1 WHERE id=? AND row_version=? AND published_revision=? AND EXISTS(SELECT 1 FROM users u JOIN environment_memberships m ON m.user_id=u.id WHERE u.id=? AND u.disabled=0 AND u.role='full' AND m.environment_id=network_profiles.environment_id)`, r.Number, id, version, p.PublishedRevision, a.ID)
	if err != nil {
		return Revision{}, nil, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Revision{}, nil, err
	}
	if n != 1 {
		return Revision{}, nil, ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO network_profile_revisions(profile_id,revision,content_json,content_hash,actor_id,published_at) VALUES(?,?,?,?,?,?)`, id, r.Number, string(data), r.Hash, a.ID, r.PublishedAt); err != nil {
		return Revision{}, nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor_id,action,target_id,created_at) VALUES(?,?,?,?,?)`, uuid.NewString(), a.ID, "network_profile.publish", id, r.PublishedAt); err != nil {
		return Revision{}, nil, err
	}
	if err = tx.Commit(); err != nil {
		return Revision{}, nil, err
	}
	return r, nil, nil
}
func (s *Service) Revision(ctx context.Context, a auth.User, id string, num int) (Revision, error) {
	var r Revision
	var data, env string
	err := s.DB.QueryRowContext(ctx, `SELECT r.profile_id,r.revision,r.content_json,r.content_hash,r.published_at,p.environment_id FROM network_profile_revisions r JOIN network_profiles p ON p.id=r.profile_id WHERE r.profile_id=? AND r.revision=?`, id, num).Scan(&r.ProfileID, &r.Number, &data, &r.Hash, &r.PublishedAt, &env)
	if errors.Is(err, sql.ErrNoRows) {
		return Revision{}, ErrForbidden
	}
	if err != nil {
		return Revision{}, err
	}
	if err = s.access(ctx, a, env, auth.View); err != nil {
		return Revision{}, err
	}
	err = json.Unmarshal([]byte(data), &r.Graph)
	return r, err
}

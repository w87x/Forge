// Package netbox owns environment-scoped NetBox connection metadata and credentials.
package netbox

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"

	"forge/internal/auth"
	"forge/internal/secrets"
	"github.com/google/uuid"
)

var ErrForbidden = errors.New("NetBox access denied")
var ErrInvalid = errors.New("invalid NetBox configuration")
var ErrDuplicateCredential = errors.New("credential is already associated with another user")

type Instance struct {
	ID            string `json:"id"`
	EnvironmentID string `json:"environment_id"`
	Name          string `json:"name"`
	BaseURL       string `json:"base_url"`
}
type Credential struct {
	InstanceID string `json:"instance_id"`
	Generation int    `json:"generation"`
	UpdatedAt  string `json:"updated_at"`
}
type Service struct {
	DB                 *sql.DB
	Auth               *auth.Service
	Vault              *secrets.Vault
	AllowHTTP          bool
	AllowedHosts       []string
	ConnectionsEnabled bool
	limitsMu           sync.Mutex
	limits             map[string]*hostLimit
}

func (s *Service) check(ctx context.Context, actor auth.User, action auth.Action, environmentID string) error {
	ok, err := s.Auth.EnvironmentAllowed(ctx, actor, action, environmentID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	return nil
}
func normalizeURL(raw string, allowHTTP bool) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", ErrInvalid
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return "", ErrInvalid
	}
	if u.Opaque != "" || strings.Contains(u.Path, "..") || strings.ContainsAny(u.Host, "\r\n\t ") {
		return "", ErrInvalid
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}
func (s *Service) CreateInstance(ctx context.Context, actor auth.User, environmentID, name, rawURL string) (Instance, error) {
	if err := s.check(ctx, actor, auth.Operate, environmentID); err != nil {
		return Instance{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 || strings.ContainsAny(name, "\x00\r\n") {
		return Instance{}, ErrInvalid
	}
	baseURL, err := normalizeURL(rawURL, s.AllowHTTP)
	if err != nil {
		return Instance{}, err
	}
	item := Instance{ID: uuid.NewString(), EnvironmentID: environmentID, Name: name, BaseURL: baseURL}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Instance{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO netbox_instances(id,environment_id,name,base_url,created_at) VALUES(?,?,?,?,?)`, item.ID, item.EnvironmentID, item.Name, item.BaseURL, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return Instance{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor_id,action,target_id,created_at) VALUES(?,?,?,?,?)`, uuid.NewString(), actor.ID, "netbox.instance.create", item.ID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return Instance{}, err
	}
	if err = tx.Commit(); err != nil {
		return Instance{}, err
	}
	return item, nil
}
func (s *Service) Instances(ctx context.Context, actor auth.User) ([]Instance, error) {
	if !auth.Allowed(actor, auth.View) {
		return nil, ErrForbidden
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT n.id,n.environment_id,n.name,n.base_url FROM netbox_instances n JOIN environment_memberships m ON m.environment_id=n.environment_id WHERE m.user_id=? ORDER BY n.name,n.id`, actor.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Instance{}
	for rows.Next() {
		var item Instance
		if err = rows.Scan(&item.ID, &item.EnvironmentID, &item.Name, &item.BaseURL); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
func (s *Service) instance(ctx context.Context, actor auth.User, id string) (Instance, error) {
	var item Instance
	err := s.DB.QueryRowContext(ctx, `SELECT id,environment_id,name,base_url FROM netbox_instances WHERE id=?`, id).Scan(&item.ID, &item.EnvironmentID, &item.Name, &item.BaseURL)
	if errors.Is(err, sql.ErrNoRows) {
		return Instance{}, ErrForbidden
	}
	if err != nil {
		return Instance{}, err
	}
	if err = s.check(ctx, actor, auth.View, item.EnvironmentID); err != nil {
		return Instance{}, err
	}
	return item, nil
}

func (s *Service) Instance(ctx context.Context, actor auth.User, id string) (Instance, error) {
	return s.instance(ctx, actor, id)
}
func (s *Service) Credential(ctx context.Context, actor auth.User, instanceID string) (Credential, error) {
	if _, err := s.instance(ctx, actor, instanceID); err != nil {
		return Credential{}, err
	}
	var c Credential
	err := s.DB.QueryRowContext(ctx, `SELECT instance_id,generation,updated_at FROM netbox_credentials WHERE instance_id=? AND user_id=?`, instanceID, actor.ID).Scan(&c.InstanceID, &c.Generation, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Credential{}, ErrInvalid
	}
	return c, err
}

func (s *Service) Credentials(ctx context.Context, actor auth.User) ([]Credential, error) {
	if !auth.Allowed(actor, auth.ManageOwnCredential) {
		return nil, ErrForbidden
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT c.instance_id,c.generation,c.updated_at FROM netbox_credentials c JOIN netbox_instances n ON n.id=c.instance_id JOIN environment_memberships m ON m.environment_id=n.environment_id AND m.user_id=c.user_id WHERE c.user_id=? ORDER BY c.instance_id`, actor.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Credential{}
	for rows.Next() {
		var c Credential
		if err = rows.Scan(&c.InstanceID, &c.Generation, &c.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, c)
	}
	return items, rows.Err()
}
func (s *Service) SaveCredential(ctx context.Context, actor auth.User, instanceID, token string) (Credential, error) {
	item, err := s.instance(ctx, actor, instanceID)
	if err != nil {
		return Credential{}, err
	}
	if !auth.Allowed(actor, auth.ManageOwnCredential) || token == "" || len(token) > 8192 || strings.ContainsAny(token, "\r\n\x00") {
		return Credential{}, ErrInvalid
	}
	fingerprint := s.Vault.Fingerprint([]byte(token))
	var owner string
	err = s.DB.QueryRowContext(ctx, `SELECT user_id FROM netbox_credentials WHERE instance_id=? AND fingerprint=?`, instanceID, fingerprint).Scan(&owner)
	if err == nil {
		if subtle.ConstantTimeCompare([]byte(owner), []byte(actor.ID)) != 1 {
			return Credential{}, ErrDuplicateCredential
		}
		return s.Credential(ctx, actor, instanceID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Credential{}, err
	}
	secret, err := s.Vault.Put(ctx, actor, secrets.Scope{OwnerID: actor.ID}, "netbox_token", "NetBox: "+item.Name, []byte(token))
	if err != nil {
		return Credential{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = s.Vault.DeleteOwned(context.Background(), actor, secret.ID)
		}
	}()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Credential{}, err
	}
	defer tx.Rollback()
	var oldSecret string
	var generation int
	err = tx.QueryRowContext(ctx, `SELECT secret_id,generation FROM netbox_credentials WHERE instance_id=? AND user_id=?`, instanceID, actor.ID).Scan(&oldSecret, &generation)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Credential{}, err
	}
	generation++
	updated := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = tx.ExecContext(ctx, `INSERT INTO netbox_credentials(instance_id,user_id,secret_id,fingerprint,generation,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(instance_id,user_id) DO UPDATE SET secret_id=excluded.secret_id,fingerprint=excluded.fingerprint,generation=excluded.generation,updated_at=excluded.updated_at`, instanceID, actor.ID, secret.ID, fingerprint, generation, updated)
	if err != nil {
		return Credential{}, err
	}
	if oldSecret != "" {
		if _, err = tx.ExecContext(ctx, `DELETE FROM secret_records WHERE id=? AND owner_id=?`, oldSecret, actor.ID); err != nil {
			return Credential{}, err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor_id,action,target_id,created_at) VALUES(?,?,?,?,?)`, uuid.NewString(), actor.ID, "netbox.credential.save", instanceID, updated); err != nil {
		return Credential{}, err
	}
	if err = tx.Commit(); err != nil {
		return Credential{}, err
	}
	committed = true
	return Credential{InstanceID: instanceID, Generation: generation, UpdatedAt: updated}, nil
}
func (s *Service) DeleteCredential(ctx context.Context, actor auth.User, instanceID string) error {
	if _, err := s.instance(ctx, actor, instanceID); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var secretID string
	if err = tx.QueryRowContext(ctx, `SELECT secret_id FROM netbox_credentials WHERE instance_id=? AND user_id=?`, instanceID, actor.ID).Scan(&secretID); errors.Is(err, sql.ErrNoRows) {
		return ErrInvalid
	}
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM netbox_credentials WHERE instance_id=? AND user_id=?`, instanceID, actor.ID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM secret_records WHERE id=? AND owner_id=?`, secretID, actor.ID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor_id,action,target_id,created_at) VALUES(?,?,?,?,?)`, uuid.NewString(), actor.ID, "netbox.credential.delete", instanceID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return tx.Commit()
}

// CredentialValue is for internal adapters only. No HTTP endpoint returns it.
func (s *Service) CredentialValue(ctx context.Context, actor auth.User, instanceID string) (Instance, Credential, []byte, error) {
	item, err := s.instance(ctx, actor, instanceID)
	if err != nil {
		return Instance{}, Credential{}, nil, err
	}
	var c Credential
	var secretID string
	err = s.DB.QueryRowContext(ctx, `SELECT instance_id,generation,updated_at,secret_id FROM netbox_credentials WHERE instance_id=? AND user_id=?`, instanceID, actor.ID).Scan(&c.InstanceID, &c.Generation, &c.UpdatedAt, &secretID)
	if errors.Is(err, sql.ErrNoRows) {
		return Instance{}, Credential{}, nil, ErrInvalid
	}
	if err != nil {
		return Instance{}, Credential{}, nil, err
	}
	value, err := s.Vault.Get(ctx, actor, secretID)
	if err != nil {
		return Instance{}, Credential{}, nil, err
	}
	return item, c, value, nil
}

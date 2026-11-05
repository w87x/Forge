package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrUnauthorized = errors.New("invalid credentials or expired session")
	ErrForbidden    = errors.New("operation not permitted")
	ErrAlreadySetup = errors.New("initial setup is complete")
	ErrInvalidInput = errors.New("invalid input")
)

type Service struct {
	DB             *sql.DB
	BootstrapToken string
	Now            func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}
func digest(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func (s *Service) SetupNeeded(ctx context.Context) (bool, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n == 0, err
}

// Bootstrap creates the first user and a one-time-displayed token atomically.
func (s *Service) Bootstrap(ctx context.Context, bootstrapToken, username string) (User, string, error) {
	username = strings.TrimSpace(username)
	if len(s.BootstrapToken) < 32 || subtle.ConstantTimeCompare(digest(s.BootstrapToken), digest(bootstrapToken)) != 1 {
		return User{}, "", ErrUnauthorized
	}
	if len(username) < 1 || len(username) > 128 || strings.ContainsAny(username, "\x00\r\n") {
		return User{}, "", ErrInvalidInput
	}
	token, err := randomToken()
	if err != nil {
		return User{}, "", err
	}
	user := User{ID: uuid.NewString(), Username: username, Role: Full}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return User{}, "", err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return User{}, "", err
	}
	if n != 0 {
		return User{}, "", ErrAlreadySetup
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO users(id, username, role, created_at) VALUES(?,?,?,?)`, user.ID, user.Username, user.Role, stamp(s.now())); err != nil {
		return User{}, "", err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO local_tokens(id,user_id,token_hash,created_at) VALUES(?,?,?,?)`, uuid.NewString(), user.ID, digest(token), stamp(s.now())); err != nil {
		return User{}, "", err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO app_metadata(key,value) VALUES('bootstrap_completed_at', ?)`, stamp(s.now())); err != nil {
		return User{}, "", err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor_id,action,target_id,created_at) VALUES(?,?,?,?,?)`, uuid.NewString(), user.ID, "bootstrap", user.ID, stamp(s.now())); err != nil {
		return User{}, "", err
	}
	if err = tx.Commit(); err != nil {
		return User{}, "", err
	}
	return user, token, nil
}

func (s *Service) Authenticate(ctx context.Context, token string) (User, error) {
	if token == "" {
		return User{}, ErrUnauthorized
	}
	var u User
	err := s.DB.QueryRowContext(ctx, `SELECT u.id,u.username,u.role,u.disabled FROM local_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=? AND t.revoked_at IS NULL`, digest(token)).Scan(&u.ID, &u.Username, &u.Role, &u.Disabled)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && u.Disabled) {
		return User{}, ErrUnauthorized
	}
	if err != nil {
		return User{}, err
	}
	return u, nil
}

func (s *Service) CreateUser(ctx context.Context, actor User, username string, role Role) (User, string, error) {
	if !Allowed(actor, ManageUsers) {
		return User{}, "", ErrForbidden
	}
	username = strings.TrimSpace(username)
	if len(username) < 1 || len(username) > 128 || strings.ContainsAny(username, "\x00\r\n") || (role != Full && role != Readonly) {
		return User{}, "", ErrInvalidInput
	}
	token, err := randomToken()
	if err != nil {
		return User{}, "", err
	}
	u := User{ID: uuid.NewString(), Username: username, Role: role}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return User{}, "", err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO users(id,username,role,created_at) VALUES(?,?,?,?)`, u.ID, u.Username, u.Role, stamp(s.now())); err != nil {
		return User{}, "", fmt.Errorf("create user: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO local_tokens(id,user_id,token_hash,created_at) VALUES(?,?,?,?)`, uuid.NewString(), u.ID, digest(token), stamp(s.now())); err != nil {
		return User{}, "", err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor_id,action,target_id,created_at) VALUES(?,?,?,?,?)`, uuid.NewString(), actor.ID, "user.create", u.ID, stamp(s.now())); err != nil {
		return User{}, "", err
	}
	if err = tx.Commit(); err != nil {
		return User{}, "", err
	}
	return u, token, nil
}

type Session struct {
	Token   string
	CSRF    string
	User    User
	Expires time.Time
}

const absoluteTimeout = 12 * time.Hour
const idleTimeout = time.Hour

func (s *Service) Login(ctx context.Context, token string) (Session, error) {
	u, err := s.Authenticate(ctx, token)
	if err != nil {
		return Session{}, err
	}
	session, err := randomToken()
	if err != nil {
		return Session{}, err
	}
	csrf, err := randomToken()
	if err != nil {
		return Session{}, err
	}
	now := s.now()
	expires := now.Add(absoluteTimeout)
	_, err = s.DB.ExecContext(ctx, `INSERT INTO sessions(id_hash,user_id,csrf_hash,created_at,last_seen_at,expires_at) VALUES(?,?,?,?,?,?)`, digest(session), u.ID, digest(csrf), stamp(now), stamp(now), stamp(expires))
	if err != nil {
		return Session{}, err
	}
	return Session{Token: session, CSRF: csrf, User: u, Expires: expires}, nil
}

func (s *Service) SessionUser(ctx context.Context, token, csrf string, requireCSRF bool) (User, error) {
	if token == "" {
		return User{}, ErrUnauthorized
	}
	var u User
	var csrfHash []byte
	var expires, lastSeen string
	err := s.DB.QueryRowContext(ctx, `SELECT u.id,u.username,u.role,u.disabled,s.csrf_hash,s.expires_at,s.last_seen_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id_hash=?`, digest(token)).Scan(&u.ID, &u.Username, &u.Role, &u.Disabled, &csrfHash, &expires, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && u.Disabled) {
		return User{}, ErrUnauthorized
	}
	if err != nil {
		return User{}, err
	}
	exp, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil {
		return User{}, err
	}
	seen, err := time.Parse(time.RFC3339Nano, lastSeen)
	if err != nil {
		return User{}, err
	}
	if !s.now().Before(exp) || !s.now().Before(seen.Add(idleTimeout)) {
		return User{}, ErrUnauthorized
	}
	if requireCSRF && (csrf == "" || subtle.ConstantTimeCompare(digest(csrf), csrfHash) != 1) {
		return User{}, ErrUnauthorized
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE sessions SET last_seen_at=? WHERE id_hash=?`, stamp(s.now()), digest(token)); err != nil {
		return User{}, err
	}
	return u, nil
}

func (s *Service) Logout(ctx context.Context, session string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash=?`, digest(session))
	return err
}

func (s *Service) Users(ctx context.Context, actor User) ([]User, error) {
	if !Allowed(actor, ManageUsers) {
		return nil, ErrForbidden
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id,username,role,disabled FROM users ORDER BY username,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := make([]User, 0)
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.Disabled); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// EnvironmentAllowed requires both the role and a membership in the target environment.
func (s *Service) EnvironmentAllowed(ctx context.Context, actor User, action Action, environmentID string) (bool, error) {
	if !Allowed(actor, action) || environmentID == "" {
		return false, nil
	}
	var member bool
	err := s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM environment_memberships WHERE user_id=? AND environment_id=?)`, actor.ID, environmentID).Scan(&member)
	return member, err
}

type Environment struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (s *Service) CreateEnvironment(ctx context.Context, actor User, name string) (Environment, error) {
	if !Allowed(actor, ManageUsers) {
		return Environment{}, ErrForbidden
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 || strings.ContainsAny(name, "\x00\r\n") {
		return Environment{}, ErrInvalidInput
	}
	e := Environment{ID: uuid.NewString(), Name: name}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Environment{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO environments(id,name) VALUES(?,?)`, e.ID, e.Name); err != nil {
		return Environment{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO environment_memberships(user_id,environment_id) VALUES(?,?)`, actor.ID, e.ID); err != nil {
		return Environment{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor_id,action,target_id,created_at) VALUES(?,?,?,?,?)`, uuid.NewString(), actor.ID, "environment.create", e.ID, stamp(s.now())); err != nil {
		return Environment{}, err
	}
	if err = tx.Commit(); err != nil {
		return Environment{}, err
	}
	return e, nil
}

func (s *Service) AddEnvironmentMember(ctx context.Context, actor User, environmentID, userID string) error {
	if !Allowed(actor, ManageUsers) {
		return ErrForbidden
	}
	if environmentID == "" || userID == "" {
		return ErrInvalidInput
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var member bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM environment_memberships WHERE user_id=? AND environment_id=?)`, actor.ID, environmentID).Scan(&member); err != nil {
		return err
	}
	if !member {
		return ErrForbidden
	}
	if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO environment_memberships(user_id,environment_id) VALUES(?,?)`, userID, environmentID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor_id,action,target_id,created_at) VALUES(?,?,?,?,?)`, uuid.NewString(), actor.ID, "environment.add_member", environmentID+":"+userID, stamp(s.now())); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) Environments(ctx context.Context, actor User) ([]Environment, error) {
	if !Allowed(actor, View) {
		return nil, ErrForbidden
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT e.id,e.name FROM environments e JOIN environment_memberships m ON m.environment_id=e.id WHERE m.user_id=? ORDER BY e.name,e.id`, actor.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Environment{}
	for rows.Next() {
		var e Environment
		if err = rows.Scan(&e.ID, &e.Name); err != nil {
			return nil, err
		}
		items = append(items, e)
	}
	return items, rows.Err()
}

// RevokeUserTokens also removes existing sessions for that user.
func (s *Service) RevokeUserTokens(ctx context.Context, actor User, userID string) error {
	if !Allowed(actor, ManageUsers) {
		return ErrForbidden
	}
	if userID == "" {
		return ErrInvalidInput
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE local_tokens SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`, stamp(s.now()), userID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrInvalidInput
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, userID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor_id,action,target_id,created_at) VALUES(?,?,?,?,?)`, uuid.NewString(), actor.ID, "user.revoke_tokens", userID, stamp(s.now())); err != nil {
		return err
	}
	return tx.Commit()
}

// IssueToken returns the new token exactly once; only its digest is persisted.
func (s *Service) IssueToken(ctx context.Context, actor User, userID string) (string, error) {
	if !Allowed(actor, ManageUsers) {
		return "", ErrForbidden
	}
	if userID == "" {
		return "", ErrInvalidInput
	}
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var enabled bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=? AND disabled=0)`, userID).Scan(&enabled); err != nil {
		return "", err
	}
	if !enabled {
		return "", ErrInvalidInput
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO local_tokens(id,user_id,token_hash,created_at) VALUES(?,?,?,?)`, uuid.NewString(), userID, digest(token), stamp(s.now())); err != nil {
		return "", err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor_id,action,target_id,created_at) VALUES(?,?,?,?,?)`, uuid.NewString(), actor.ID, "user.issue_token", userID, stamp(s.now())); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return token, nil
}

// Package secrets stores recoverable credentials with authenticated encryption.
package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"forge/internal/auth"
	"github.com/google/uuid"
)

var ErrForbidden = errors.New("secret access denied")

type Scope struct {
	OwnerID       string
	EnvironmentID string
}
type Metadata struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Kind       string `json:"kind"`
	Generation int    `json:"generation"`
}
type Vault struct {
	db             *sql.DB
	aead           cipher.AEAD
	keyID          string
	fingerprintKey []byte
}

func New(db *sql.DB, encodedKey string) (*Vault, error) {
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil || len(key) != 32 {
		return nil, errors.New("FORGE_ENCRYPTION_KEY must be a base64-encoded 32-byte key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(key)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("forge:credential-fingerprint:v1"))
	return &Vault{db: db, aead: aead, keyID: hex.EncodeToString(hash[:8]), fingerprintKey: mac.Sum(nil)}, nil
}

// Fingerprint detects accidental credential reuse without persisting its value.
func (v *Vault) Fingerprint(value []byte) []byte {
	mac := hmac.New(sha256.New, v.fingerprintKey)
	_, _ = mac.Write(value)
	return mac.Sum(nil)
}
func aad(id, kind string, scope Scope) []byte {
	return []byte(id + "\x00" + kind + "\x00" + scope.OwnerID + "\x00" + scope.EnvironmentID)
}
func (v *Vault) authorize(ctx context.Context, actor auth.User, scope Scope) error {
	if actor.Disabled || (scope.OwnerID == "") == (scope.EnvironmentID == "") {
		return ErrForbidden
	}
	if scope.OwnerID != "" {
		if actor.ID == scope.OwnerID && auth.Allowed(actor, auth.ManageOwnCredential) {
			return nil
		}
		return ErrForbidden
	}
	if !auth.Allowed(actor, auth.Operate) {
		return ErrForbidden
	}
	var exists bool
	if err := v.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM environment_memberships WHERE user_id=? AND environment_id=?)`, actor.ID, scope.EnvironmentID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrForbidden
	}
	return nil
}
func (v *Vault) Put(ctx context.Context, actor auth.User, scope Scope, kind, label string, cleartext []byte) (Metadata, error) {
	if err := v.authorize(ctx, actor, scope); err != nil {
		return Metadata{}, err
	}
	if kind == "" || label == "" || len(cleartext) == 0 || len(cleartext) > 64<<10 {
		return Metadata{}, errors.New("invalid secret")
	}
	id := uuid.NewString()
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Metadata{}, err
	}
	ciphertext := v.aead.Seal(nil, nonce, cleartext, aad(id, kind, scope))
	var owner, environment any
	if scope.OwnerID != "" {
		owner = scope.OwnerID
	}
	if scope.EnvironmentID != "" {
		environment = scope.EnvironmentID
	}
	_, err := v.db.ExecContext(ctx, `INSERT INTO secret_records(id,owner_id,environment_id,kind,label,key_id,nonce,ciphertext,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, id, owner, environment, kind, label, v.keyID, nonce, ciphertext, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return Metadata{}, err
	}
	return Metadata{ID: id, Label: label, Kind: kind, Generation: 1}, nil
}
func (v *Vault) Get(ctx context.Context, actor auth.User, id string) ([]byte, error) {
	var scope Scope
	var kind, keyID string
	var nonce, ciphertext []byte
	err := v.db.QueryRowContext(ctx, `SELECT COALESCE(owner_id,''),COALESCE(environment_id,''),kind,key_id,nonce,ciphertext FROM secret_records WHERE id=?`, id).Scan(&scope.OwnerID, &scope.EnvironmentID, &kind, &keyID, &nonce, &ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrForbidden
	}
	if err != nil {
		return nil, err
	}
	if err = v.authorize(ctx, actor, scope); err != nil {
		return nil, err
	}
	if keyID != v.keyID {
		return nil, errors.New("secret encryption key is unavailable")
	}
	if len(nonce) != v.aead.NonceSize() {
		return nil, errors.New("invalid secret nonce")
	}
	cleartext, err := v.aead.Open(nil, nonce, ciphertext, aad(id, kind, scope))
	if err != nil {
		return nil, fmt.Errorf("secret authentication failed: %w", err)
	}
	return cleartext, nil
}

// Replace rotates the contents without changing the identity or ownership.
func (v *Vault) Replace(ctx context.Context, actor auth.User, id string, cleartext []byte) (int, error) {
	if len(cleartext) == 0 || len(cleartext) > 64<<10 {
		return 0, errors.New("invalid secret")
	}
	var scope Scope
	var kind string
	var generation int
	err := v.db.QueryRowContext(ctx, `SELECT COALESCE(owner_id,''),COALESCE(environment_id,''),kind,generation FROM secret_records WHERE id=?`, id).Scan(&scope.OwnerID, &scope.EnvironmentID, &kind, &generation)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrForbidden
	}
	if err != nil {
		return 0, err
	}
	if err = v.authorize(ctx, actor, scope); err != nil {
		return 0, err
	}
	nonce := make([]byte, v.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return 0, err
	}
	ciphertext := v.aead.Seal(nil, nonce, cleartext, aad(id, kind, scope))
	result, err := v.db.ExecContext(ctx, `UPDATE secret_records SET key_id=?,nonce=?,ciphertext=?,generation=generation+1 WHERE id=? AND generation=?`, v.keyID, nonce, ciphertext, id, generation)
	if err != nil {
		return 0, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if n != 1 {
		return 0, errors.New("secret was changed concurrently")
	}
	return generation + 1, nil
}

// ListOwned returns metadata only; cleartext secrets are never sent to the UI.
func (v *Vault) ListOwned(ctx context.Context, actor auth.User) ([]Metadata, error) {
	if !auth.Allowed(actor, auth.ManageOwnCredential) {
		return nil, ErrForbidden
	}
	rows, err := v.db.QueryContext(ctx, `SELECT id,label,kind,generation FROM secret_records WHERE owner_id=? AND NOT EXISTS(SELECT 1 FROM netbox_credentials WHERE secret_id=secret_records.id) ORDER BY label,id`, actor.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Metadata{}
	for rows.Next() {
		var m Metadata
		if err = rows.Scan(&m.ID, &m.Label, &m.Kind, &m.Generation); err != nil {
			return nil, err
		}
		items = append(items, m)
	}
	return items, rows.Err()
}

func (v *Vault) ListEnvironment(ctx context.Context, actor auth.User, environmentID string) ([]Metadata, error) {
	if err := v.authorize(ctx, actor, Scope{EnvironmentID: environmentID}); err != nil {
		return nil, err
	}
	rows, err := v.db.QueryContext(ctx, `SELECT id,label,kind,generation FROM secret_records WHERE environment_id=? ORDER BY label,id`, environmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Metadata{}
	for rows.Next() {
		var m Metadata
		if err = rows.Scan(&m.ID, &m.Label, &m.Kind, &m.Generation); err != nil {
			return nil, err
		}
		items = append(items, m)
	}
	return items, rows.Err()
}

// ListShared returns BMC credential metadata from all legacy scopes without
// moving encrypted records, whose authenticated data includes the old scope.
func (v *Vault) ListShared(ctx context.Context, actor auth.User) ([]Metadata, error) {
	if !auth.Allowed(actor, auth.Operate) {
		return nil, ErrForbidden
	}
	rows, err := v.db.QueryContext(ctx, `SELECT id,label,kind,generation FROM secret_records WHERE environment_id IS NOT NULL ORDER BY label,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Metadata{}
	for rows.Next() {
		var m Metadata
		if err = rows.Scan(&m.ID, &m.Label, &m.Kind, &m.Generation); err != nil {
			return nil, err
		}
		items = append(items, m)
	}
	return items, rows.Err()
}
func (v *Vault) SharedSecret(ctx context.Context, actor auth.User, id string) (Metadata, error) {
	if !auth.Allowed(actor, auth.Operate) {
		return Metadata{}, ErrForbidden
	}
	var m Metadata
	err := v.db.QueryRowContext(ctx, `SELECT id,label,kind,generation FROM secret_records WHERE id=? AND environment_id IS NOT NULL`, id).Scan(&m.ID, &m.Label, &m.Kind, &m.Generation)
	if errors.Is(err, sql.ErrNoRows) {
		return Metadata{}, ErrForbidden
	}
	return m, err
}
func (v *Vault) EnvironmentSecret(ctx context.Context, actor auth.User, environmentID, id string) (Metadata, error) {
	if err := v.authorize(ctx, actor, Scope{EnvironmentID: environmentID}); err != nil {
		return Metadata{}, err
	}
	var m Metadata
	err := v.db.QueryRowContext(ctx, `SELECT id,label,kind,generation FROM secret_records WHERE id=? AND environment_id=?`, id, environmentID).Scan(&m.ID, &m.Label, &m.Kind, &m.Generation)
	if errors.Is(err, sql.ErrNoRows) {
		return Metadata{}, ErrForbidden
	}
	return m, err
}
func (v *Vault) ReplaceOwned(ctx context.Context, actor auth.User, id string, value []byte) (int, error) {
	if !auth.Allowed(actor, auth.ManageOwnCredential) {
		return 0, ErrForbidden
	}
	var owner string
	if err := v.db.QueryRowContext(ctx, `SELECT COALESCE(owner_id,'') FROM secret_records WHERE id=? AND NOT EXISTS(SELECT 1 FROM netbox_credentials WHERE secret_id=secret_records.id)`, id).Scan(&owner); err != nil {
		return 0, ErrForbidden
	}
	if owner != actor.ID {
		return 0, ErrForbidden
	}
	return v.Replace(ctx, actor, id, value)
}
func (v *Vault) DeleteOwned(ctx context.Context, actor auth.User, id string) error {
	if !auth.Allowed(actor, auth.ManageOwnCredential) {
		return ErrForbidden
	}
	result, err := v.db.ExecContext(ctx, `DELETE FROM secret_records WHERE id=? AND owner_id=? AND NOT EXISTS(SELECT 1 FROM netbox_credentials WHERE secret_id=secret_records.id)`, id, actor.ID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrForbidden
	}
	return nil
}

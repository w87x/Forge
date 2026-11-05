// Package inspection coordinates read-only, actor-scoped Redfish observations.
package inspection

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"

	"forge/internal/auth"
	"forge/internal/inventory"
	"forge/internal/jobs"
	"forge/internal/netbox"
	"forge/internal/profiles"
	"forge/internal/redfish"
	"forge/internal/secrets"
	"github.com/google/uuid"
)

var ErrInvalid = errors.New("invalid inspection request")
var ErrForbidden = errors.New("inspection access denied")
var ErrUnsupported = errors.New("this connection profile requires a BMC address source not yet supported")

type Request struct {
	SelectionID string `json:"selection_id"`
	DeviceID    int64  `json:"device_id"`
	ProfileID   string `json:"profile_id"`
	Revision    int    `json:"revision"`
	BMCIP       string `json:"bmc_ip"`
}
type input struct {
	Request        Request        `json:"request"`
	SnapshotID     string         `json:"snapshot_id"`
	ServerID       string         `json:"server_id"`
	Serial         string         `json:"serial"`
	ProfileHash    string         `json:"profile_hash"`
	SecretVersions map[string]int `json:"secret_versions"`
}
type Record struct {
	ID             string              `json:"id"`
	JobID          string              `json:"job_id"`
	ServerID       string              `json:"server_id"`
	DeviceID       int64               `json:"device_id"`
	BMCIP          string              `json:"bmc_ip"`
	DeclaredSerial string              `json:"declared_serial"`
	IdentityStatus string              `json:"identity_status"`
	Observed       redfish.Observation `json:"observed"`
	CollectedAt    time.Time           `json:"collected_at"`
}
type Service struct {
	DB        *sql.DB
	Auth      *auth.Service
	Inventory *inventory.Service
	NetBox    *netbox.Service
	Profiles  *profiles.Service
	Vault     *secrets.Vault
	Jobs      *jobs.Store
	Redfish   *redfish.Client
	Enabled   bool
}

func (s *Service) resolve(ctx context.Context, actor auth.User, r Request) (input, profiles.Connection, error) {
	if !s.Enabled {
		return input{}, profiles.Connection{}, ErrUnsupported
	}
	if !auth.Allowed(actor, auth.Operate) || r.SelectionID == "" || r.ProfileID == "" || r.DeviceID <= 0 || r.Revision < 1 {
		return input{}, profiles.Connection{}, ErrForbidden
	}
	ip, err := netip.ParseAddr(r.BMCIP)
	if err != nil || !s.Redfish.Permits(ip) {
		return input{}, profiles.Connection{}, redfish.ErrNotAllowed
	}
	r.BMCIP = ip.String()
	selection, err := s.Inventory.Selection(ctx, actor, r.SelectionID)
	if err != nil {
		return input{}, profiles.Connection{}, err
	}
	selected := false
	for _, id := range selection.DeviceIDs {
		if id == r.DeviceID {
			selected = true
			break
		}
	}
	if !selected {
		return input{}, profiles.Connection{}, ErrInvalid
	}
	snap, err := s.Inventory.Snapshot(ctx, actor, selection.SnapshotID)
	if err != nil {
		return input{}, profiles.Connection{}, err
	}
	var device inventory.Device
	found := false
	for _, d := range snap.Devices {
		if d.ID == r.DeviceID {
			device = d
			found = true
			break
		}
	}
	if !found {
		return input{}, profiles.Connection{}, ErrInvalid
	}
	_, err = s.NetBox.Instance(ctx, actor, snap.InstanceID)
	if err != nil {
		return input{}, profiles.Connection{}, err
	}
	_, err = s.Profiles.Get(ctx, actor, r.ProfileID)
	if err != nil {
		return input{}, profiles.Connection{}, err
	}
	revision, err := s.Profiles.Revision(ctx, actor, r.ProfileID, r.Revision)
	if err != nil {
		return input{}, profiles.Connection{}, err
	}
	conf := revision.Content
	if err = conf.Validate(); err != nil {
		return input{}, profiles.Connection{}, err
	}
	if conf.AddressSource != "explicit" {
		return input{}, profiles.Connection{}, ErrUnsupported
	}
	if _, err = conf.DeviceValue(r.BMCIP, device.Serial); err != nil {
		return input{}, profiles.Connection{}, err
	}
	versions := map[string]int{}
	for _, id := range []string{conf.StaticSecretID, conf.PrefixSecretID, conf.SuffixSecretID} {
		if id != "" {
			m, err := s.Vault.SharedSecret(ctx, actor, id)
			if err != nil {
				return input{}, profiles.Connection{}, ErrForbidden
			}
			versions[id] = m.Generation
		}
	}
	return input{Request: r, SnapshotID: snap.ID, ServerID: device.ForgeID, Serial: device.Serial, ProfileHash: revision.Hash, SecretVersions: versions}, conf, nil
}
func (s *Service) Submit(ctx context.Context, actor auth.User, key string, r Request) (jobs.Job, bool, error) {
	if key == "" || len(key) > 128 {
		return jobs.Job{}, false, ErrInvalid
	}
	if !auth.Allowed(actor, auth.Operate) {
		return jobs.Job{}, false, ErrForbidden
	}
	if _, err := s.Inventory.Selection(ctx, actor, r.SelectionID); err != nil {
		return jobs.Job{}, false, err
	}
	requestBytes, err := json.Marshal(r)
	if err != nil {
		return jobs.Job{}, false, err
	}
	requestHash := sha256.Sum256(requestBytes)
	bodyHash := hex.EncodeToString(requestHash[:])
	if existing, found, err := s.Jobs.FindIdempotent(ctx, actor.ID, "redfish.inspect", key, bodyHash); err != nil {
		return jobs.Job{}, false, err
	} else if found {
		return existing, false, nil
	}
	in, _, err := s.resolve(ctx, actor, r)
	if err != nil {
		return jobs.Job{}, false, err
	}
	data, err := json.Marshal(in)
	if err != nil {
		return jobs.Job{}, false, err
	}
	return s.Jobs.CreateIdempotentInput(ctx, actor.ID, "redfish.inspect", key, bodyHash, "redfish.inspect", time.Now().Add(10*time.Minute), []string{"Inspect system and BIOS"}, data)
}
func sameInput(a, b input) bool {
	if a.Request != b.Request || a.SnapshotID != b.SnapshotID || a.ServerID != b.ServerID || a.Serial != b.Serial || a.ProfileHash != b.ProfileHash || len(a.SecretVersions) != len(b.SecretVersions) {
		return false
	}
	for k, v := range a.SecretVersions {
		if b.SecretVersions[k] != v {
			return false
		}
	}
	return true
}

func (s *Service) RunJob(ctx context.Context, job jobs.Job, worker string) error {
	var actor auth.User
	err := s.DB.QueryRowContext(ctx, `SELECT id,username,role,disabled FROM users WHERE id=?`, job.ActorID).Scan(&actor.ID, &actor.Username, &actor.Role, &actor.Disabled)
	if err != nil {
		return err
	}
	if !auth.Allowed(actor, auth.Operate) {
		return ErrForbidden
	}
	data, err := s.Jobs.Input(ctx, job.ID)
	if err != nil {
		return err
	}
	var stored input
	if err = json.Unmarshal(data, &stored); err != nil {
		return ErrInvalid
	}
	resolved, conf, err := s.resolve(ctx, actor, stored.Request)
	if err != nil {
		return err
	}
	if !sameInput(stored, resolved) {
		return inventory.ErrStale
	}
	var existing string
	err = s.DB.QueryRowContext(ctx, `SELECT id FROM observations WHERE job_id=?`, job.ID).Scan(&existing)
	if err == nil {
		return s.Jobs.CompleteLocalStep(ctx, job.ID, worker, job.Generation, 0)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	p, err := s.Profiles.Get(ctx, actor, stored.Request.ProfileID)
	if err != nil {
		return err
	}
	password, err := s.Profiles.Password(ctx, actor, p.EnvironmentID, conf, stored.Request.BMCIP, stored.Serial)
	if err != nil {
		return err
	}
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()
	address, err := netip.ParseAddr(stored.Request.BMCIP)
	if err != nil {
		return ErrInvalid
	}
	port := conf.Port
	if port == 0 {
		port = 443
	}
	readCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	observed, err := s.Redfish.Inspect(readCtx, address, port, conf.Username, password)
	if err != nil {
		return err
	}
	current, _, err := s.resolve(ctx, actor, stored.Request)
	if err != nil {
		return err
	}
	if !sameInput(stored, current) {
		return inventory.ErrStale
	}
	identity := "unknown"
	if strings.TrimSpace(stored.Serial) != "" && strings.TrimSpace(observed.Serial) != "" {
		if strings.TrimSpace(stored.Serial) == strings.TrimSpace(observed.Serial) {
			identity = "match"
		} else {
			identity = "mismatch"
		}
	}
	record := Record{ID: uuid.NewString(), JobID: job.ID, ServerID: stored.ServerID, DeviceID: stored.Request.DeviceID, BMCIP: stored.Request.BMCIP, DeclaredSerial: stored.Serial, IdentityStatus: identity, Observed: observed, CollectedAt: time.Now().UTC()}
	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for id, expected := range stored.SecretVersions {
		var generation int
		err = tx.QueryRowContext(ctx, `SELECT generation FROM secret_records WHERE id=? AND environment_id IS NOT NULL`, id).Scan(&generation)
		if err != nil || generation != expected {
			return inventory.ErrStale
		}
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO observations(id,actor_id,job_id,server_id,selection_id,profile_id,profile_revision,management_address,observed_json,collected_at_ns) SELECT ?,?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM inventory_selections x JOIN inventory_snapshots snap ON snap.id=x.snapshot_id JOIN netbox_credentials c ON c.instance_id=snap.instance_id AND c.user_id=x.actor_id AND c.generation=snap.credential_generation JOIN netbox_instances n ON n.id=snap.instance_id JOIN environment_memberships m ON m.environment_id=n.environment_id AND m.user_id=x.actor_id JOIN users u ON u.id=x.actor_id AND u.role='full' AND u.disabled=0 WHERE x.id=? AND x.actor_id=? AND snap.expires_at_ns>?) AND EXISTS(SELECT 1 FROM jobs WHERE id=? AND status='running' AND lease_owner=? AND lease_generation=? AND lease_until_ns>?) ON CONFLICT(job_id) DO NOTHING`, record.ID, actor.ID, job.ID, stored.ServerID, stored.Request.SelectionID, stored.Request.ProfileID, stored.Request.Revision, stored.Request.BMCIP, string(payload), record.CollectedAt.UnixNano(), stored.Request.SelectionID, actor.ID, time.Now().UnixNano(), job.ID, worker, job.Generation, time.Now().UnixNano())
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return inventory.ErrStale
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return s.Jobs.CompleteLocalStep(ctx, job.ID, worker, job.Generation, 0)
}
func (s *Service) Get(ctx context.Context, actor auth.User, jobID string) (Record, error) {
	var owner, selectionID, payload, instanceID string
	err := s.DB.QueryRowContext(ctx, `SELECT o.actor_id,o.selection_id,o.observed_json,s.instance_id FROM observations o JOIN inventory_selections x ON x.id=o.selection_id JOIN inventory_snapshots s ON s.id=x.snapshot_id WHERE o.job_id=?`, jobID).Scan(&owner, &selectionID, &payload, &instanceID)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrInvalid
	}
	if err != nil {
		return Record{}, err
	}
	if owner != actor.ID {
		return Record{}, ErrForbidden
	}
	selection, err := s.Inventory.Selection(ctx, actor, selectionID)
	if err != nil {
		return Record{}, ErrForbidden
	}
	var record Record
	if err = json.Unmarshal([]byte(payload), &record); err != nil {
		return Record{}, err
	}
	selected := false
	for _, id := range selection.DeviceIDs {
		if id == record.DeviceID {
			selected = true
			break
		}
	}
	if !selected {
		return Record{}, ErrForbidden
	}
	if _, err = s.Inventory.Snapshot(ctx, actor, selection.SnapshotID); err != nil {
		if !errors.Is(err, inventory.ErrStale) {
			return Record{}, err
		}
		// Selection already checked the original credential generation. An
		// expired snapshot requires a fresh visibility check with that token.
		if err = s.NetBox.DeviceVisible(ctx, actor, instanceID, record.DeviceID); err != nil {
			return Record{}, err
		}
		if _, err = s.Inventory.Selection(ctx, actor, selectionID); err != nil {
			return Record{}, err
		}
	}
	return record, nil
}

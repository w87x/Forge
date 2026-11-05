// Package inventory stores actor-scoped snapshots of read-only NetBox pages.
package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"forge/internal/auth"
	"forge/internal/netbox"
	"github.com/google/uuid"
)

var ErrNotVisible = errors.New("inventory snapshot is not visible")
var ErrStale = errors.New("inventory snapshot is stale or its credential changed")
var ErrInvalid = errors.New("invalid inventory selection")

type Device struct {
	netbox.Device
	ForgeID string `json:"forge_id"`
}
type Snapshot struct {
	ID         string              `json:"id"`
	InstanceID string              `json:"instance_id"`
	Filter     netbox.DeviceFilter `json:"filter"`
	Devices    []Device            `json:"devices"`
	Count      int                 `json:"count"`
	HasMore    bool                `json:"has_more"`
	FetchedAt  time.Time           `json:"fetched_at"`
	ExpiresAt  time.Time           `json:"expires_at"`
}
type Selection struct {
	ID         string  `json:"id"`
	SnapshotID string  `json:"snapshot_id"`
	DeviceIDs  []int64 `json:"device_ids"`
}
type Service struct {
	DB     *sql.DB
	NetBox *netbox.Service
	Now    func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) Refresh(ctx context.Context, actor auth.User, instanceID string, filter netbox.DeviceFilter) (Snapshot, error) {
	credential, err := s.NetBox.Credential(ctx, actor, instanceID)
	if err != nil {
		return Snapshot{}, err
	}
	page, err := s.NetBox.Devices(ctx, actor, instanceID, filter)
	if err != nil {
		return Snapshot{}, err
	}
	now := s.now()
	snap := Snapshot{ID: uuid.NewString(), InstanceID: instanceID, Filter: filter, Devices: make([]Device, 0, len(page.Results)), Count: page.Count, HasMore: page.HasMore, FetchedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Snapshot{}, err
	}
	defer tx.Rollback()
	var current bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM netbox_credentials c JOIN netbox_instances n ON n.id=c.instance_id JOIN environment_memberships m ON m.environment_id=n.environment_id AND m.user_id=c.user_id JOIN users u ON u.id=c.user_id WHERE c.instance_id=? AND c.user_id=? AND c.generation=? AND u.disabled=0)`, instanceID, actor.ID, credential.Generation).Scan(&current)
	if err != nil {
		return Snapshot{}, err
	}
	if !current {
		return Snapshot{}, ErrStale
	}
	for _, d := range page.Results {
		id := uuid.NewString()
		_, err = tx.ExecContext(ctx, `INSERT INTO servers(id,instance_id,netbox_device_id,name,last_seen_at) VALUES(?,?,?,?,?) ON CONFLICT(instance_id,netbox_device_id) DO UPDATE SET name=excluded.name,last_seen_at=excluded.last_seen_at`, id, instanceID, d.ID, d.Name, now.Format(time.RFC3339Nano))
		if err != nil {
			return Snapshot{}, err
		}
		if err = tx.QueryRowContext(ctx, `SELECT id FROM servers WHERE instance_id=? AND netbox_device_id=?`, instanceID, d.ID).Scan(&id); err != nil {
			return Snapshot{}, err
		}
		snap.Devices = append(snap.Devices, Device{Device: d, ForgeID: id})
	}
	filterJSON, err := json.Marshal(filter)
	if err != nil {
		return Snapshot{}, err
	}
	pageJSON, err := json.Marshal(snap)
	if err != nil {
		return Snapshot{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO inventory_snapshots(id,instance_id,actor_id,credential_generation,filter_json,page_json,fetched_at_ns,expires_at_ns) VALUES(?,?,?,?,?,?,?,?)`, snap.ID, instanceID, actor.ID, credential.Generation, string(filterJSON), string(pageJSON), now.UnixNano(), snap.ExpiresAt.UnixNano())
	if err != nil {
		return Snapshot{}, err
	}
	if err = tx.Commit(); err != nil {
		return Snapshot{}, err
	}
	return snap, nil
}
func (s *Service) Snapshot(ctx context.Context, actor auth.User, id string) (Snapshot, error) {
	var instanceID, owner, payload string
	var generation, expires int64
	err := s.DB.QueryRowContext(ctx, `SELECT instance_id,actor_id,credential_generation,page_json,expires_at_ns FROM inventory_snapshots WHERE id=?`, id).Scan(&instanceID, &owner, &generation, &payload, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, ErrNotVisible
	}
	if err != nil {
		return Snapshot{}, err
	}
	if owner != actor.ID {
		return Snapshot{}, ErrNotVisible
	}
	credential, err := s.NetBox.Credential(ctx, actor, instanceID)
	if err != nil {
		return Snapshot{}, ErrNotVisible
	}
	if int64(credential.Generation) != generation || s.now().UnixNano() >= expires {
		return Snapshot{}, ErrStale
	}
	var snap Snapshot
	if err = json.Unmarshal([]byte(payload), &snap); err != nil {
		return Snapshot{}, err
	}
	return snap, nil
}
func (s *Service) Select(ctx context.Context, actor auth.User, snapshotID string, ids []int64) (Selection, error) {
	snap, err := s.Snapshot(ctx, actor, snapshotID)
	if err != nil {
		return Selection{}, err
	}
	if len(ids) == 0 || len(ids) > netbox.DevicePageSize {
		return Selection{}, ErrInvalid
	}
	allowed := map[int64]bool{}
	for _, d := range snap.Devices {
		allowed[d.ID] = true
	}
	seen := map[int64]bool{}
	for _, id := range ids {
		if !allowed[id] || seen[id] {
			return Selection{}, ErrInvalid
		}
		seen[id] = true
	}
	selection := Selection{ID: uuid.NewString(), SnapshotID: snapshotID, DeviceIDs: append([]int64(nil), ids...)}
	payload, err := json.Marshal(selection.DeviceIDs)
	if err != nil {
		return Selection{}, err
	}
	res, err := s.DB.ExecContext(ctx, `INSERT INTO inventory_selections(id,snapshot_id,actor_id,device_ids_json,created_at_ns) SELECT ?,s.id,?, ?,? FROM inventory_snapshots s JOIN netbox_credentials c ON c.instance_id=s.instance_id AND c.user_id=s.actor_id AND c.generation=s.credential_generation JOIN netbox_instances n ON n.id=s.instance_id JOIN environment_memberships m ON m.environment_id=n.environment_id AND m.user_id=s.actor_id JOIN users u ON u.id=s.actor_id AND u.disabled=0 WHERE s.id=? AND s.actor_id=? AND s.expires_at_ns>?`, selection.ID, actor.ID, string(payload), s.now().UnixNano(), snapshotID, actor.ID, s.now().UnixNano())
	if err != nil {
		return Selection{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Selection{}, err
	}
	if n != 1 {
		return Selection{}, ErrStale
	}
	return selection, nil
}
func (s *Service) Selection(ctx context.Context, actor auth.User, id string) (Selection, error) {
	var result Selection
	var owner, instanceID, payload string
	var generation int
	err := s.DB.QueryRowContext(ctx, `SELECT x.id,x.snapshot_id,x.actor_id,x.device_ids_json,s.instance_id,s.credential_generation FROM inventory_selections x JOIN inventory_snapshots s ON s.id=x.snapshot_id WHERE x.id=?`, id).Scan(&result.ID, &result.SnapshotID, &owner, &payload, &instanceID, &generation)
	if errors.Is(err, sql.ErrNoRows) {
		return Selection{}, ErrNotVisible
	}
	if err != nil {
		return Selection{}, err
	}
	if owner != actor.ID {
		return Selection{}, ErrNotVisible
	}
	credential, err := s.NetBox.Credential(ctx, actor, instanceID)
	if err != nil {
		return Selection{}, ErrNotVisible
	}
	if credential.Generation != generation {
		return Selection{}, ErrStale
	}
	if err = json.Unmarshal([]byte(payload), &result.DeviceIDs); err != nil {
		return Selection{}, err
	}
	return result, nil
}

// Interfaces returns a single current NetBox page only for a frozen selected
// device, and rechecks the selection after the remote read completes.
func (s *Service) Interfaces(ctx context.Context, actor auth.User, selectionID string, deviceID int64, offset int) (netbox.InterfacePage, error) {
	selection, err := s.Selection(ctx, actor, selectionID)
	if err != nil {
		return netbox.InterfacePage{}, err
	}
	selected := false
	for _, id := range selection.DeviceIDs {
		if id == deviceID {
			selected = true
			break
		}
	}
	if !selected {
		return netbox.InterfacePage{}, ErrNotVisible
	}
	snap, err := s.Snapshot(ctx, actor, selection.SnapshotID)
	if err != nil {
		return netbox.InterfacePage{}, err
	}
	page, err := s.NetBox.Interfaces(ctx, actor, snap.InstanceID, deviceID, offset)
	if err != nil {
		return netbox.InterfacePage{}, err
	}
	if _, err = s.Selection(ctx, actor, selectionID); err != nil {
		return netbox.InterfacePage{}, err
	}
	if _, err = s.Snapshot(ctx, actor, selection.SnapshotID); err != nil {
		return netbox.InterfacePage{}, err
	}
	return page, nil
}

func (s *Service) Addresses(ctx context.Context, actor auth.User, selectionID string, deviceID int64, offset int) (netbox.IPAddressPage, error) {
	selection, err := s.Selection(ctx, actor, selectionID)
	if err != nil {
		return netbox.IPAddressPage{}, err
	}
	selected := false
	for _, id := range selection.DeviceIDs {
		if id == deviceID {
			selected = true
			break
		}
	}
	if !selected {
		return netbox.IPAddressPage{}, ErrNotVisible
	}
	snap, err := s.Snapshot(ctx, actor, selection.SnapshotID)
	if err != nil {
		return netbox.IPAddressPage{}, err
	}
	page, err := s.NetBox.Addresses(ctx, actor, snap.InstanceID, deviceID, offset)
	if err != nil {
		return netbox.IPAddressPage{}, err
	}
	if _, err = s.Selection(ctx, actor, selectionID); err != nil {
		return netbox.IPAddressPage{}, err
	}
	if _, err = s.Snapshot(ctx, actor, selection.SnapshotID); err != nil {
		return netbox.IPAddressPage{}, err
	}
	return page, nil
}

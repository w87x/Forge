package network

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"time"

	"forge/internal/auth"
	"forge/internal/inventory"
	"forge/internal/netbox"
	"github.com/google/uuid"
)

type SavedImport struct {
	ID                     string            `json:"id"`
	ProfileID              string            `json:"profile_id"`
	Revision               int               `json:"revision"`
	Bindings               []HostBinding     `json:"bindings"`
	Addresses              []ResolvedAddress `json:"addresses"`
	SourceHash             string            `json:"source_hash"`
	ParserVersion          int               `json:"parser_version"`
	CreatedAt              string            `json:"created_at"`
	NetBoxConflictsChecked bool              `json:"netbox_conflicts_checked"`
}
type ImportService struct {
	DB        *sql.DB
	Inventory *inventory.Service
	NetBox    *netbox.Service
}

func canonicalIDs(ids []int64) string {
	c := append([]int64(nil), ids...)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	data, _ := json.Marshal(c)
	return string(data)
}

// Save writes only selected bindings and resolved addresses, never the source
// document or unselected host entries. The insert rechecks the original scope.
func (s *ImportService) Save(ctx context.Context, actor auth.User, selection inventory.Selection, instance netbox.Instance, profileID string, revision int, bindings []HostBinding, addresses []ResolvedAddress, hash string, parserVersion int) (SavedImport, error) {
	if !auth.Allowed(actor, auth.Operate) || len(bindings) == 0 || len(addresses) == 0 || len(hash) != 64 || parserVersion < 1 {
		return SavedImport{}, ErrInvalid
	}
	allowed := map[int64]bool{}
	for _, id := range selection.DeviceIDs {
		allowed[id] = true
	}
	seen := map[int64]bool{}
	for _, b := range bindings {
		if !allowed[b.DeviceID] || seen[b.DeviceID] || b.Key == "" {
			return SavedImport{}, ErrInvalid
		}
		seen[b.DeviceID] = true
	}
	if len(seen) != len(allowed) {
		return SavedImport{}, ErrInvalid
	}
	for _, address := range addresses {
		if !allowed[address.DeviceID] {
			return SavedImport{}, ErrInvalid
		}
	}
	bindJSON, err := json.Marshal(bindings)
	if err != nil {
		return SavedImport{}, err
	}
	addressJSON, err := json.Marshal(addresses)
	if err != nil {
		return SavedImport{}, err
	}
	item := SavedImport{ID: uuid.NewString(), ProfileID: profileID, Revision: revision, Bindings: bindings, Addresses: addresses, SourceHash: hash, ParserVersion: parserVersion, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	res, err := s.DB.ExecContext(ctx, `INSERT INTO allocation_imports(id,actor_id,instance_id,selection_id,profile_id,profile_revision,device_ids_json,bindings_json,addresses_json,source_hash,parser_version,created_at) SELECT ?,?,?,?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM inventory_selections x JOIN inventory_snapshots snap ON snap.id=x.snapshot_id JOIN netbox_credentials c ON c.instance_id=snap.instance_id AND c.user_id=x.actor_id AND c.generation=snap.credential_generation JOIN netbox_instances n ON n.id=snap.instance_id JOIN environment_memberships m ON m.environment_id=n.environment_id AND m.user_id=x.actor_id JOIN users u ON u.id=x.actor_id AND u.disabled=0 AND u.role='full' JOIN network_profiles p ON p.id=? JOIN network_profile_revisions r ON r.profile_id=p.id AND r.revision=? WHERE x.id=? AND x.actor_id=? AND snap.instance_id=? AND snap.expires_at_ns>?)`, item.ID, actor.ID, instance.ID, selection.ID, profileID, revision, canonicalIDs(selection.DeviceIDs), string(bindJSON), string(addressJSON), hash, parserVersion, item.CreatedAt, profileID, revision, selection.ID, actor.ID, instance.ID, time.Now().UnixNano())
	if err != nil {
		return SavedImport{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return SavedImport{}, err
	}
	if n != 1 {
		return SavedImport{}, ErrForbidden
	}
	return item, nil
}

// List requires a fresh selection proving visibility of exactly the same
// devices. Reselecting after a key rotation is supported without sharing data
// between operators or exposing entries for a narrower selection.
func (s *ImportService) List(ctx context.Context, actor auth.User, selectionID string) ([]SavedImport, error) {
	selection, err := s.Inventory.Selection(ctx, actor, selectionID)
	if err != nil {
		return nil, err
	}
	snap, err := s.Inventory.Snapshot(ctx, actor, selection.SnapshotID)
	if err != nil {
		return nil, err
	}
	if _, err = s.NetBox.Instance(ctx, actor, snap.InstanceID); err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id,profile_id,profile_revision,bindings_json,addresses_json,source_hash,parser_version,created_at FROM allocation_imports WHERE actor_id=? AND instance_id=? AND device_ids_json=? AND EXISTS(SELECT 1 FROM inventory_snapshots snap JOIN netbox_credentials c ON c.instance_id=snap.instance_id AND c.user_id=snap.actor_id AND c.generation=snap.credential_generation JOIN netbox_instances n ON n.id=snap.instance_id JOIN environment_memberships m ON m.environment_id=n.environment_id AND m.user_id=snap.actor_id JOIN users u ON u.id=snap.actor_id AND u.disabled=0 WHERE snap.id=? AND snap.actor_id=? AND snap.expires_at_ns>?) ORDER BY created_at DESC,id DESC LIMIT 100`, actor.ID, snap.InstanceID, canonicalIDs(selection.DeviceIDs), selection.SnapshotID, actor.ID, time.Now().UnixNano())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []SavedImport{}
	for rows.Next() {
		var item SavedImport
		var bindings, addresses string
		if err = rows.Scan(&item.ID, &item.ProfileID, &item.Revision, &bindings, &addresses, &item.SourceHash, &item.ParserVersion, &item.CreatedAt); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(bindings), &item.Bindings); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(addresses), &item.Addresses); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

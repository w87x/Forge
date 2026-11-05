// Package audit composes immutable, read-only results from existing evidence.
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"forge/internal/auth"
	"forge/internal/bios"
	"forge/internal/compliance"
	"forge/internal/inspection"
	"forge/internal/network"
	"github.com/google/uuid"
)

var ErrForbidden = errors.New("audit access denied")
var ErrInvalid = errors.New("audit inputs do not describe the same device")

type Request struct {
	HardwareAuditID string `json:"hardware_audit_id"`
	NetworkAuditID  string `json:"network_audit_id"`
	SelectionID     string `json:"selection_id"`
	BIOSProfileID   string `json:"bios_profile_id"`
	BIOSRevision    int    `json:"bios_revision"`
}
type Result struct {
	Status             string              `json:"status"`
	Hardware           compliance.Result   `json:"hardware"`
	Network            network.AuditResult `json:"network"`
	HardwareProfileID  string              `json:"hardware_profile_id"`
	HardwareRevision   int                 `json:"hardware_revision"`
	NetworkProfileID   string              `json:"network_profile_id"`
	NetworkRevision    int                 `json:"network_revision"`
	AllocationHash     string              `json:"allocation_hash"`
	BIOS               *bios.Comparison    `json:"bios,omitempty"`
	BIOSProfileID      string              `json:"bios_profile_id,omitempty"`
	BIOSRevision       int                 `json:"bios_revision,omitempty"`
	HardwareEvidenceAt time.Time           `json:"hardware_evidence_at"`
	NetworkCheckedAt   string              `json:"network_checked_at"`
	Freshness          []string            `json:"freshness"`
}
type Record struct {
	ID               string   `json:"id"`
	HardwareAuditID  string   `json:"hardware_audit_id"`
	NetworkAuditID   string   `json:"network_audit_id"`
	JobID            string   `json:"job_id"`
	CreatedAt        string   `json:"created_at"`
	Result           *Result  `json:"result,omitempty"`
	CurrentFreshness []string `json:"current_freshness"`
}
type Service struct {
	DB          *sql.DB
	Hardware    *compliance.Service
	Network     *network.ImportService
	BIOS        *bios.Service
	Inspections *inspection.Service
}

func freshnessAt(hardware time.Time, networkTime string, now time.Time) []string {
	issues := []string{}
	n, err := time.Parse(time.RFC3339Nano, networkTime)
	if err != nil || n.After(now.Add(time.Minute)) || now.Sub(n) > 5*time.Minute {
		issues = append(issues, "Network evidence is older than five minutes or has an invalid timestamp")
	}
	if hardware.IsZero() || hardware.After(now.Add(time.Minute)) || now.Sub(hardware) > 24*time.Hour {
		issues = append(issues, "Hardware evidence is older than 24 hours or has an invalid timestamp")
	}
	return issues
}

func (s *Service) Run(ctx context.Context, actor auth.User, request Request) (Record, error) {
	if !auth.Allowed(actor, auth.Operate) {
		return Record{}, ErrForbidden
	}
	if request.HardwareAuditID == "" || request.NetworkAuditID == "" || request.SelectionID == "" || (request.BIOSProfileID == "") != (request.BIOSRevision == 0) || request.BIOSRevision < 0 {
		return Record{}, ErrInvalid
	}
	hw, err := s.Hardware.GetAudit(ctx, actor, request.HardwareAuditID)
	if err != nil {
		return Record{}, err
	}
	net, err := s.Network.GetAudit(ctx, actor, request.SelectionID, request.NetworkAuditID)
	if err != nil {
		return Record{}, err
	}
	observed, err := s.Inspections.Get(ctx, actor, hw.JobID)
	if err != nil {
		return Record{}, err
	}
	if hw.Result == nil || net.Result == nil || observed.DeviceID != net.DeviceID {
		return Record{}, ErrInvalid
	}
	var observedInstance, networkInstance, networkProfileID, allocationHash string
	var networkRevision int
	err = s.DB.QueryRowContext(ctx, `SELECT instance_id FROM servers WHERE id=?`, observed.ServerID).Scan(&observedInstance)
	if err != nil {
		return Record{}, err
	}
	err = s.DB.QueryRowContext(ctx, `SELECT i.instance_id,i.profile_id,i.profile_revision,i.source_hash FROM network_audits n JOIN allocation_imports i ON i.id=n.import_id WHERE n.id=? AND n.actor_id=?`, net.ID, actor.ID).Scan(&networkInstance, &networkProfileID, &networkRevision, &allocationHash)
	if err != nil {
		return Record{}, err
	}
	if observedInstance != networkInstance {
		return Record{}, ErrInvalid
	}
	now := time.Now().UTC()
	result := Result{Status: "pass", Hardware: *hw.Result, Network: *net.Result, HardwareProfileID: hw.ProfileID, HardwareRevision: hw.Revision, NetworkProfileID: networkProfileID, NetworkRevision: networkRevision, AllocationHash: allocationHash, HardwareEvidenceAt: observed.CollectedAt, NetworkCheckedAt: net.CreatedAt, Freshness: []string{}}
	if request.BIOSProfileID != "" {
		comparison, err := s.BIOS.CompareJob(ctx, actor, request.BIOSProfileID, request.BIOSRevision, hw.JobID)
		if err != nil {
			return Record{}, err
		}
		result.BIOS = &comparison
		result.BIOSProfileID = request.BIOSProfileID
		result.BIOSRevision = request.BIOSRevision
	}
	result.Freshness = freshnessAt(observed.CollectedAt, net.CreatedAt, now)
	combine := func(status string) {
		if status == "fail" {
			result.Status = "fail"
		} else if status != "pass" && result.Status != "fail" {
			result.Status = "unknown"
		}
	}
	combine(result.Hardware.Status)
	combine(result.Network.Status)
	if result.BIOS != nil {
		combine(result.BIOS.Status)
	}
	if len(result.Freshness) > 0 {
		combine("unknown")
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return Record{}, err
	}
	item := Record{ID: uuid.NewString(), HardwareAuditID: hw.ID, NetworkAuditID: net.ID, JobID: hw.JobID, CreatedAt: now.Format(time.RFC3339Nano), Result: &result, CurrentFreshness: result.Freshness}
	res, err := s.DB.ExecContext(ctx, `INSERT INTO combined_audits(id,actor_id,hardware_audit_id,network_audit_id,job_id,result_json,created_at) SELECT ?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM hardware_audits h JOIN observations o ON o.job_id=h.job_id AND o.actor_id=h.actor_id JOIN servers server ON server.id=o.server_id JOIN inventory_selections hx ON hx.id=o.selection_id JOIN inventory_snapshots hs ON hs.id=hx.snapshot_id JOIN netbox_credentials hc ON hc.instance_id=hs.instance_id AND hc.user_id=hx.actor_id AND hc.generation=hs.credential_generation JOIN network_audits na ON na.id=? AND na.actor_id=h.actor_id JOIN allocation_imports ni ON ni.id=na.import_id JOIN inventory_selections x ON x.id=? AND x.actor_id=h.actor_id JOIN inventory_snapshots snap ON snap.id=x.snapshot_id AND snap.instance_id=ni.instance_id JOIN netbox_credentials c ON c.instance_id=snap.instance_id AND c.user_id=x.actor_id AND c.generation=snap.credential_generation JOIN netbox_instances n ON n.id=ni.instance_id JOIN environment_memberships m ON m.user_id=x.actor_id AND m.environment_id=n.environment_id JOIN users u ON u.id=h.actor_id AND u.role='full' AND u.disabled=0 WHERE h.id=? AND h.actor_id=? AND server.instance_id=ni.instance_id AND server.netbox_device_id=na.device_id AND snap.expires_at_ns>?)`, item.ID, actor.ID, hw.ID, net.ID, hw.JobID, string(payload), item.CreatedAt, net.ID, request.SelectionID, hw.ID, actor.ID, time.Now().UnixNano())
	if err != nil {
		return Record{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Record{}, err
	}
	if n != 1 {
		return Record{}, ErrForbidden
	}
	return item, nil
}
func (s *Service) List(ctx context.Context, a auth.User) ([]Record, error) {
	if !auth.Allowed(a, auth.View) {
		return nil, ErrForbidden
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id,hardware_audit_id,network_audit_id,job_id,created_at FROM combined_audits WHERE actor_id=? ORDER BY created_at DESC,id DESC LIMIT 100`, a.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Record{}
	for rows.Next() {
		var item Record
		if err = rows.Scan(&item.ID, &item.HardwareAuditID, &item.NetworkAuditID, &item.JobID, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
func (s *Service) Get(ctx context.Context, a auth.User, id, selectionID string) (Record, error) {
	if !auth.Allowed(a, auth.View) {
		return Record{}, ErrForbidden
	}
	var item Record
	var payload string
	err := s.DB.QueryRowContext(ctx, `SELECT id,hardware_audit_id,network_audit_id,job_id,created_at,result_json FROM combined_audits WHERE id=? AND actor_id=?`, id, a.ID).Scan(&item.ID, &item.HardwareAuditID, &item.NetworkAuditID, &item.JobID, &item.CreatedAt, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrForbidden
	}
	if err != nil {
		return Record{}, err
	}
	if _, err = s.Hardware.GetAudit(ctx, a, item.HardwareAuditID); err != nil {
		return Record{}, err
	}
	if _, err = s.Network.GetAudit(ctx, a, selectionID, item.NetworkAuditID); err != nil {
		return Record{}, err
	}
	item.Result = &Result{}
	if err = json.Unmarshal([]byte(payload), item.Result); err != nil {
		return Record{}, err
	}
	item.CurrentFreshness = freshnessAt(item.Result.HardwareEvidenceAt, item.Result.NetworkCheckedAt, time.Now().UTC())
	return item, nil
}

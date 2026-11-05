package bios

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"forge/internal/auth"
	"forge/internal/inspection"
	"forge/internal/inventory"
	"forge/internal/netbox"
	"forge/internal/redfish"
	"forge/internal/secrets"
	"forge/internal/store/sqlite"
)

func TestPersistedProfilesCapturePublishAndCompare(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a := &auth.Service{DB: db.DB, BootstrapToken: strings.Repeat("x", 32)}
	owner, _, err := a.Bootstrap(ctx, strings.Repeat("x", 32), "owner")
	if err != nil {
		t.Fatal(err)
	}
	env, err := a.CreateEnvironment(ctx, owner, "lab")
	if err != nil {
		t.Fatal(err)
	}
	readonly, _, err := a.CreateUser(ctx, owner, "reader", auth.Readonly)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.AddEnvironmentMember(ctx, owner, env.ID, readonly.ID); err != nil {
		t.Fatal(err)
	}
	vault, err := secrets.New(db.DB, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32))))
	if err != nil {
		t.Fatal(err)
	}
	nb := &netbox.Service{DB: db.DB, Auth: a, Vault: vault, AllowHTTP: true}
	instance, err := nb.CreateInstance(ctx, owner, env.ID, "nb", "http://localhost")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := nb.SaveCredential(ctx, owner, instance.ID, "key")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	snap := inventory.Snapshot{ID: "snap", InstanceID: instance.ID, FetchedAt: now, ExpiresAt: now.Add(time.Hour), Devices: []inventory.Device{{Device: netbox.Device{ID: 1, Name: "host"}, ForgeID: "server"}}}
	payload, _ := json.Marshal(snap)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.DB.ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO servers(id,instance_id,netbox_device_id,name,last_seen_at) VALUES('server',?,1,'host','now')`, instance.ID)
	exec(`INSERT INTO inventory_snapshots(id,instance_id,actor_id,credential_generation,filter_json,page_json,fetched_at_ns,expires_at_ns) VALUES('snap',?,?,?,'{}',?,?,?)`, instance.ID, owner.ID, cred.Generation, string(payload), now.UnixNano(), now.Add(time.Hour).UnixNano())
	exec(`INSERT INTO inventory_selections(id,snapshot_id,actor_id,device_ids_json,created_at_ns) VALUES('selection','snap',?,'[1]',?)`, owner.ID, now.UnixNano())
	exec(`INSERT INTO profiles(id,environment_id,name,kind,draft_json,created_at) VALUES('connection',?,'connection','connection','{}','now')`, env.ID)
	exec(`INSERT INTO profile_revisions(profile_id,revision,content_json,content_hash,actor_id,published_at) VALUES('connection',1,'{}','hash',?,'now')`, owner.ID)
	exec(`INSERT INTO jobs(id,kind,actor_id,input_hash,status,next_attempt_ns,deadline_ns,created_ns) VALUES('job','redfish.inspect',?,'hash','succeeded',0,?,?)`, owner.ID, now.Add(time.Hour).UnixNano(), now.UnixNano())
	observed := redfish.Observation{Manufacturer: "Vendor", Model: "A", BIOSVersion: "1", BIOSRegistry: "reg", BIOSRegistryHash: strings.Repeat("a", 64), BIOSRegistryCoverage: "available", BIOSCoverage: "available", BIOSAttributeTypes: map[string]string{"Virtualization": "Enumeration"}, BIOSAttributes: map[string]any{"Virtualization": "Enabled"}}
	record := inspection.Record{ID: "obs", JobID: "job", DeviceID: 1, ServerID: "server", IdentityStatus: "match", Observed: observed, CollectedAt: now}
	data, _ := json.Marshal(record)
	exec(`INSERT INTO observations(id,actor_id,job_id,server_id,selection_id,profile_id,profile_revision,management_address,observed_json,collected_at_ns) VALUES('obs',?,'job','server','selection','connection',1,'127.0.0.1',?,?)`, owner.ID, string(data), now.UnixNano())
	inv := &inventory.Service{DB: db.DB, NetBox: nb}
	is := &inspection.Service{DB: db.DB, Auth: a, Inventory: inv, NetBox: nb}
	svc := &Service{DB: db.DB, Auth: a, Inspections: is}
	p, err := svc.Create(ctx, owner, "baseline", "job", []string{"Virtualization"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Publish(ctx, readonly, p.ID, p.RowVersion); !errors.Is(err, ErrForbidden) {
		t.Fatalf("readonly published: %v", err)
	}
	r1, err := svc.Publish(ctx, owner, p.ID, p.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Publish(ctx, owner, p.ID, p.RowVersion); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale publish: %v", err)
	}
	if got, err := svc.CompareJob(ctx, owner, p.ID, 1, "job"); err != nil || got.Status != "pass" {
		t.Fatalf("compare: %+v %v", got, err)
	}
	record.Observed.BIOSAttributes["Virtualization"] = "Disabled"
	record.Observed.PendingCoverage = "available"
	record.Observed.PendingAttributes = map[string]any{"Virtualization": "Enabled"}
	data, _ = json.Marshal(record)
	exec(`UPDATE observations SET observed_json=? WHERE job_id='job'`, string(data))
	got, err := svc.CompareJob(ctx, owner, p.ID, 1, "job")
	if err != nil || got.Status != "fail" || got.Findings[0].PendingStatus != "matches" {
		t.Fatalf("pending: %+v %v", got, err)
	}
	p, err = svc.Get(ctx, owner, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	p, err = svc.AddVariant(ctx, owner, p.ID, p.RowVersion, "job", []string{"Virtualization"})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := svc.Publish(ctx, owner, p.ID, p.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	old, err := svc.Revision(ctx, owner, p.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if old.Variants[0].Attributes["Virtualization"] != "Enabled" || r1.Hash == r2.Hash || r2.Variants[0].Attributes["Virtualization"] != "Disabled" {
		t.Fatal("revision was not immutable")
	}
	if _, err = svc.CompareJob(ctx, readonly, p.ID, 1, "job"); err == nil {
		t.Fatal("reader accessed another operator's observation")
	}
	p, err = svc.Get(ctx, owner, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	oldVersion := p.RowVersion
	p, err = svc.RemoveVariant(ctx, owner, p.ID, p.RowVersion, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.RemoveVariant(ctx, owner, p.ID, oldVersion, 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale delete: %v", err)
	}
	if _, err = svc.Publish(ctx, owner, p.ID, p.RowVersion); !errors.Is(err, ErrInvalid) {
		t.Fatalf("published empty draft: %v", err)
	}
	if old, err = svc.Revision(ctx, owner, p.ID, 1); err != nil || old.Variants[0].Attributes["Virtualization"] != "Enabled" {
		t.Fatal("published variant was changed")
	}
	record.CollectedAt = now.Add(-25 * time.Hour)
	data, _ = json.Marshal(record)
	exec(`UPDATE observations SET observed_json=? WHERE job_id='job'`, string(data))
	if got, err = svc.CompareJob(ctx, owner, p.ID, 1, "job"); err != nil || got.Status != "unknown" {
		t.Fatalf("old result passed: %+v %v", got, err)
	}
}

package cabling

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"forge/internal/auth"
	"forge/internal/store/sqlite"
)

func TestCablingProfileLifecycle(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a := &auth.Service{DB: db.DB, BootstrapToken: strings.Repeat("x", 32)}
	owner, _, err := a.Bootstrap(ctx, strings.Repeat("x", 32), "owner")
	if err != nil {
		t.Fatal(err)
	}
	reader, _, err := a.CreateUser(ctx, owner, "reader", auth.Readonly)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.DB.ExecContext(ctx, `INSERT INTO netbox_instances(id,environment_id,name,base_url,created_at) VALUES('nb',?,'nb','https://nb.test','now')`, auth.SharedWorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{DB: db.DB}
	p, err := svc.Create(ctx, owner, "rack uplinks")
	if err != nil {
		t.Fatal(err)
	}
	if items, err := svc.List(ctx, reader); err != nil || len(items) != 0 {
		t.Fatalf("draft visible to reader: %+v %v", items, err)
	}
	if _, err = svc.Publish(ctx, owner, p.ID, p.RowVersion); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty published: %v", err)
	}
	draft := Profile{NetBoxInstanceID: "nb", Switches: []Switch{{DeviceID: 11, Fabric: "a"}, {DeviceID: 12, Fabric: "b"}}, DistinctSwitches: true, Requirements: []RequirementSpec{{ID: "uplink", SpeedMbps: 25000, Media: "sfp28", PortRole: "uplink"}}}
	p, err = svc.Update(ctx, owner, p.ID, p.RowVersion, draft)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Update(ctx, owner, p.ID, p.RowVersion-1, draft); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update: %v", err)
	}
	if _, err = svc.Update(ctx, reader, p.ID, p.RowVersion, draft); !errors.Is(err, ErrForbidden) {
		t.Fatalf("readonly update: %v", err)
	}
	rev, err := svc.Publish(ctx, owner, p.ID, p.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	if rev.Number != 1 || rev.NetBoxReferencesVerified {
		t.Fatalf("revision: %+v", rev)
	}
	visible, err := svc.Get(ctx, reader, p.ID)
	if err != nil || visible.Draft != nil || visible.Published == nil || visible.Published.Switches[0].DeviceID != 11 {
		t.Fatalf("published view %+v %v", visible, err)
	}
	current, err := svc.Get(ctx, owner, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	draft.Switches[0].DeviceID = 99
	current, err = svc.Update(ctx, owner, p.ID, current.RowVersion, draft)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Publish(ctx, owner, p.ID, current.RowVersion); err != nil {
		t.Fatal(err)
	}
	old, err := svc.Revision(ctx, reader, p.ID, 1)
	if err != nil || old.Profile.Switches[0].DeviceID != 11 {
		t.Fatalf("revision changed: %+v %v", old, err)
	}
}

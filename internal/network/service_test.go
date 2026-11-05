package network

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"forge/internal/auth"
	"forge/internal/store/sqlite"
)

func TestNetworkProfileDraftAndImmutableRevision(t *testing.T) {
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
	env, err := a.CreateEnvironment(ctx, owner, "lab")
	if err != nil {
		t.Fatal(err)
	}
	reader, _, err := a.CreateUser(ctx, owner, "reader", auth.Readonly)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.AddEnvironmentMember(ctx, owner, env.ID, reader.ID); err != nil {
		t.Fatal(err)
	}
	s := Service{DB: db.DB, Auth: a}
	p, err := s.Create(ctx, owner, env.ID, "network")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Get(ctx, reader, p.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("draft visible: %v", err)
	}
	if _, issues, err := s.Publish(ctx, owner, p.ID, p.RowVersion); !errors.Is(err, ErrInvalid) || len(issues) == 0 {
		t.Fatalf("empty published: %v %+v", err, issues)
	}
	g := exampleGraph()
	g.NetBoxInstanceID = ""
	g.Networks[0].VRFID = ""
	p, err = s.Update(ctx, owner, p.ID, p.RowVersion, g)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Update(ctx, owner, p.ID, 1, g); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale draft: %v", err)
	}
	r1, issues, err := s.Publish(ctx, owner, p.ID, p.RowVersion)
	if err != nil || len(issues) > 0 || r1.NetBoxReferencesVerified {
		t.Fatalf("publish: %+v %+v %v", r1, issues, err)
	}
	visible, err := s.Get(ctx, reader, p.ID)
	if err != nil || visible.Draft != nil || visible.Published == nil {
		t.Fatalf("reader: %+v %v", visible, err)
	}
	if _, err = s.Update(ctx, reader, p.ID, visible.RowVersion, g); !errors.Is(err, ErrForbidden) {
		t.Fatalf("reader update: %v", err)
	}
	p, err = s.Get(ctx, owner, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	g.Nodes[0].OSName = "renamed"
	p, err = s.Update(ctx, owner, p.ID, p.RowVersion, g)
	if err != nil {
		t.Fatal(err)
	}
	r2, _, err := s.Publish(ctx, owner, p.ID, p.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	old, err := s.Revision(ctx, reader, p.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if old.Graph.Nodes[0].OSName != "eno1" || r1.Hash == r2.Hash {
		t.Fatal("revision changed with draft")
	}
}

func TestProfileRequiresExistingNetBoxForVRFReferences(t *testing.T) {
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
	s := Service{DB: db.DB, Auth: a}
	p, err := s.Create(ctx, owner, auth.SharedWorkspaceID, "scoped")
	if err != nil {
		t.Fatal(err)
	}
	g := exampleGraph()
	p, err = s.Update(ctx, owner, p.ID, p.RowVersion, g)
	if err != nil {
		t.Fatal(err)
	}
	if _, issues, err := s.Publish(ctx, owner, p.ID, p.RowVersion); !errors.Is(err, ErrInvalid) || len(issues) == 0 {
		t.Fatalf("unknown connection: %v %+v", err, issues)
	}
	if _, err = db.DB.Exec(`INSERT INTO netbox_instances(id,environment_id,name,base_url,created_at) VALUES('nb',?,'nb','https://netbox.test','now')`, auth.SharedWorkspaceID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Publish(ctx, owner, p.ID, p.RowVersion); err != nil {
		t.Fatalf("valid connection: %v", err)
	}
}

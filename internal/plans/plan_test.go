package plans

import (
	"errors"
	"testing"
)

func validPlan() Plan {
	return Plan{Actions: []Action{{ID: "interface", Kind: "create_interface", DeviceID: 1, InterfaceName: "bond0", InterfaceType: "lag"}, {ID: "address", Kind: "create_ip", DeviceID: 1, InterfaceName: "bond0", Address: "192.0.2.1/24", Dependencies: []string{"interface"}}, {ID: "primary", Kind: "set_primary_ip", DeviceID: 1, Address: "192.0.2.1/24", Dependencies: []string{"address"}}}}
}
func TestSelectionRequiresPrerequisites(t *testing.T) {
	p := validPlan()
	if err := Validate(p); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSelection(p, []string{"primary"}); !errors.Is(err, ErrDependency) {
		t.Fatalf("missing prerequisites: %v", err)
	}
	if err := ValidateSelection(p, []string{"interface", "address", "primary"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSelection(p, []string{"interface", "other"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown action: %v", err)
	}
}
func TestDigestStableAndBoundToFields(t *testing.T) {
	p := validPlan()
	first, err := Digest(p)
	if err != nil {
		t.Fatal(err)
	}
	p.Actions[0], p.Actions[2] = p.Actions[2], p.Actions[0]
	second, err := Digest(p)
	if err != nil || first != second {
		t.Fatalf("order changed digest: %v", err)
	}
	p.Actions[0].Address = "192.0.2.2/24"
	p.Actions[1].Address = "192.0.2.2/24"
	third, err := Digest(p)
	if err != nil || third == first {
		t.Fatalf("changed content: %v", err)
	}
}
func TestInvalidActionPlans(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Plan)
	}{
		{"cycle", func(p *Plan) { p.Actions[0].Dependencies = []string{"primary"} }},
		{"missing interface dependency", func(p *Plan) { p.Actions[1].Dependencies = nil }},
		{"missing address dependency", func(p *Plan) { p.Actions[2].Dependencies = nil }},
		{"unknown kind", func(p *Plan) { p.Actions[0].Kind = "delete_interface" }},
		{"wrong device", func(p *Plan) { p.Actions[1].DeviceID = 2 }},
		{"bad address", func(p *Plan) { p.Actions[1].Address = "invalid" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validPlan()
			tt.mutate(&p)
			if err := Validate(p); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid plan accepted: %v", err)
			}
		})
	}
}

func TestSelectionDigestAndOrdering(t *testing.T) {
	p := validPlan()
	a, err := SelectionDigest(p, []string{"primary", "interface", "address"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := SelectionDigest(p, []string{"address", "primary", "interface"})
	if err != nil || a != b {
		t.Fatalf("order changed selection digest: %s %v", b, err)
	}
	c, err := SelectionDigest(p, []string{"interface"})
	if err != nil || a == c {
		t.Fatalf("selection was not bound: %s %v", c, err)
	}
	if _, err := SelectionDigest(p, []string{"primary"}); !errors.Is(err, ErrDependency) {
		t.Fatalf("missing dependency accepted: %v", err)
	}
	ordered, err := OrderedSelection(p, []string{"primary", "address", "interface"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ordered) != 3 || ordered[0].ID != "interface" || ordered[1].ID != "address" || ordered[2].ID != "primary" {
		t.Fatalf("wrong ordering: %+v", ordered)
	}
	ordered[1].Dependencies[0] = "mutated"
	if p.Actions[1].Dependencies[0] != "interface" {
		t.Fatal("result aliases plan")
	}
}

func TestRejectAmbiguousTargets(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Plan)
	}{
		{"duplicate interface", func(p *Plan) { a := p.Actions[0]; a.ID = "duplicate"; p.Actions = append(p.Actions, a) }},
		{"duplicate ip with another prefix", func(p *Plan) {
			a := p.Actions[1]
			a.ID = "duplicate"
			a.Address = "192.0.2.1/32"
			p.Actions = append(p.Actions, a)
		}},
		{"two primary addresses of same family", func(p *Plan) { a := p.Actions[2]; a.ID = "duplicate"; p.Actions = append(p.Actions, a) }},
		{"create and existing interface", func(p *Plan) { p.Actions[1].ExistingInterfaceID = 12 }},
		{"create and existing ip", func(p *Plan) { p.Actions[2].ExistingIPID = 13 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validPlan()
			tt.mutate(&p)
			if err := Validate(p); !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted ambiguous plan: %v", err)
			}
		})
	}
}

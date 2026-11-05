package cabling

import "testing"

func port(id, sw, rack int64, fabric string) Port {
	return Port{ID: id, SwitchID: sw, RackID: rack, SiteID: 1, Physical: true, OccupancyKnown: true, SpeedMbps: 10000, Media: "sfp+", Role: "server", Fabric: fabric}
}
func TestMatchingRespectsConstraintsAndAvoidsGreedyTrap(t *testing.T) {
	p := Policy{SiteID: 1, SourceRackID: 10, RackRanks: map[int64]int{20: 1}, DistinctSwitches: true}
	req := []Requirement{{ID: "any", SpeedMbps: 10000, Media: "sfp+", PortRole: "server"}, {ID: "fabric-a", SpeedMbps: 10000, Media: "sfp+", PortRole: "server", Fabric: "a"}}
	result, err := Match(p, req, []Port{port(1, 1, 10, "a"), port(2, 2, 20, "b")})
	if err != nil || len(result.Assignments) != 2 || result.Assignments[0].Port.ID != 2 || result.Assignments[1].Port.ID != 1 {
		t.Fatalf("matching: %+v %v", result, err)
	}
}
func TestMatchingExcludesUnknownAndOccupiedPorts(t *testing.T) {
	base := port(1, 1, 10, "a")
	unknown := base
	unknown.ID = 2
	unknown.OccupancyKnown = false
	occupied := base
	occupied.ID = 3
	occupied.Occupied = true
	reserved := base
	reserved.ID = 4
	reserved.Reserved = true
	logical := base
	logical.ID = 5
	logical.Physical = false
	breakout := base
	breakout.ID = 6
	breakout.Breakout = true
	result, err := Match(Policy{SiteID: 1, SourceRackID: 10}, []Requirement{{ID: "one", SpeedMbps: 10000, Media: "sfp+", PortRole: "server"}}, []Port{unknown, occupied, reserved, logical, breakout, base})
	if err != nil || len(result.Assignments) != 1 || result.Assignments[0].Port.ID != 1 {
		t.Fatalf("unsafe match: %+v %v", result, err)
	}
}
func TestMatchingRequiresExplicitLocationFallback(t *testing.T) {
	req := []Requirement{{ID: "one", SpeedMbps: 10000, Media: "sfp+", PortRole: "server"}}
	p := Policy{SiteID: 1, SourceRackID: 10}
	ports := []Port{port(1, 1, 20, "a")}
	result, err := Match(p, req, ports)
	if err != nil || len(result.Unsatisfied) != 1 {
		t.Fatalf("unapproved fallback: %+v %v", result, err)
	}
	p.AllowSameSite = true
	result, err = Match(p, req, ports)
	if err != nil || len(result.Assignments) != 1 || result.Assignments[0].Reason != "same-site fallback" {
		t.Fatalf("fallback: %+v %v", result, err)
	}
}

func TestRejectedPortsExplainIncompleteEvidence(t *testing.T) {
	p := port(7, 1, 10, "a")
	p.OccupancyKnown = false
	result, err := Match(Policy{SiteID: 1, SourceRackID: 10}, []Requirement{{ID: "uplink", SpeedMbps: 10000, Media: "sfp+", PortRole: "server"}}, []Port{p})
	if err != nil || len(result.Assignments) != 0 || len(result.Rejected) != 1 || result.Rejected[0].PortID != 7 || result.Rejected[0].Reason != "occupancy unknown" {
		t.Fatalf("unexpected explanation: %+v %v", result, err)
	}
}

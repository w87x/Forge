package cabling

import (
	"errors"
	"testing"
)

func TestCablingProfileResolveAndValidation(t *testing.T) {
	p := Profile{NetBoxInstanceID: "nb", Switches: []Switch{{DeviceID: 1, Fabric: "a"}, {DeviceID: 2, Fabric: "b"}}, PreferredRacks: []int64{12, 11}, DistinctFabrics: true, Requirements: []RequirementSpec{{ID: "uplink", SpeedMbps: 10000, Media: "sfp+", PortRole: "server", Fabric: "a"}}}
	policy, req, err := ResolvePolicy(p, 1, 11)
	if err != nil || policy.RackRanks[12] != 1 || len(policy.RackRanks) != 1 || len(req) != 1 {
		t.Fatalf("resolution: %+v %+v %v", policy, req, err)
	}
	p.Switches = append(p.Switches, p.Switches[0])
	if !errors.Is(ValidateProfile(p), ErrInvalid) {
		t.Fatal("duplicate switch accepted")
	}
	p.Switches = p.Switches[:2]
	p.Requirements[0].Fabric = "missing"
	if !errors.Is(ValidateProfile(p), ErrInvalid) {
		t.Fatal("unknown fabric accepted")
	}
}

func TestResolvedPolicyOnlyUsesSelectedSwitchAndFabric(t *testing.T) {
	p := Profile{NetBoxInstanceID: "nb", Switches: []Switch{{DeviceID: 1, Fabric: "a"}}, Requirements: []RequirementSpec{{ID: "up", SpeedMbps: 10000, Media: "sfp+", PortRole: "server", Fabric: "a"}}}
	policy, req, err := ResolvePolicy(p, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	a := port(1, 1, 10, "wrong")
	b := port(2, 2, 10, "a")
	result, err := Match(policy, req, []Port{a, b})
	if err != nil || len(result.Assignments) != 1 || result.Assignments[0].Port.ID != 1 || result.Assignments[0].Port.Fabric != "a" {
		t.Fatalf("policy not enforced: %+v %v", result, err)
	}
}

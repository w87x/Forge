package cabling

import (
	"fmt"
	"strings"
)

// Profile is operator-authored cabling intent. Switches and racks are scoped to
// one NetBox connection; the identifiers remain unverified until looked up
// with the current operator's key.
type Profile struct {
	NetBoxInstanceID string            `json:"netbox_instance_id"`
	Switches         []Switch          `json:"switches"`
	PreferredRacks   []int64           `json:"preferred_racks"`
	AllowSameSite    bool              `json:"allow_same_site"`
	DistinctSwitches bool              `json:"distinct_switches"`
	DistinctFabrics  bool              `json:"distinct_fabrics"`
	Requirements     []RequirementSpec `json:"requirements"`
}
type Switch struct {
	DeviceID int64  `json:"device_id"`
	Fabric   string `json:"fabric"`
}
type RequirementSpec struct {
	ID        string `json:"id"`
	SpeedMbps int    `json:"speed_mbps"`
	Media     string `json:"media"`
	PortRole  string `json:"port_role"`
	Fabric    string `json:"fabric"`
}

// ValidateProfile checks local shape only. It never asserts device visibility,
// switch capability, port availability, rack location or cable state.
func ValidateProfile(p Profile) error {
	validText := func(s string) bool { return len(s) <= 128 && !strings.ContainsAny(s, "\x00\r\n") }
	if p.NetBoxInstanceID == "" || !validText(p.NetBoxInstanceID) {
		return fmt.Errorf("%w: choose a NetBox connection", ErrInvalid)
	}
	if len(p.Switches) == 0 || len(p.Switches) > 256 {
		return fmt.Errorf("%w: add 1–256 switches", ErrInvalid)
	}
	if len(p.PreferredRacks) > 256 {
		return fmt.Errorf("%w: at most 256 preferred racks are supported", ErrInvalid)
	}
	if len(p.Requirements) == 0 || len(p.Requirements) > 8 {
		return fmt.Errorf("%w: add 1–8 port requirements", ErrInvalid)
	}
	switches := map[int64]bool{}
	fabrics := map[string]bool{}
	for _, s := range p.Switches {
		if s.DeviceID <= 0 || switches[s.DeviceID] || !validText(s.Fabric) || (p.DistinctFabrics && strings.TrimSpace(s.Fabric) == "") {
			return fmt.Errorf("%w: switch IDs must be positive and unique; distinct fabrics require a fabric for every switch", ErrInvalid)
		}
		switches[s.DeviceID] = true
		if s.Fabric != "" {
			fabrics[s.Fabric] = true
		}
	}
	racks := map[int64]bool{}
	for _, id := range p.PreferredRacks {
		if id <= 0 || racks[id] {
			return fmt.Errorf("%w: preferred rack IDs must be positive and unique", ErrInvalid)
		}
		racks[id] = true
	}
	ids := map[string]bool{}
	for _, r := range p.Requirements {
		if strings.TrimSpace(r.ID) == "" || ids[r.ID] || r.SpeedMbps <= 0 || r.SpeedMbps > 100000000 || strings.TrimSpace(r.Media) == "" || strings.TrimSpace(r.PortRole) == "" || !validText(r.ID) || !validText(r.Media) || !validText(r.PortRole) || !validText(r.Fabric) {
			return fmt.Errorf("%w: each port requirement needs a unique name, speed, media and role", ErrInvalid)
		}
		if r.Fabric != "" && !fabrics[r.Fabric] {
			return fmt.Errorf("%w: requirement fabric is not assigned to a switch", ErrInvalid)
		}
		ids[r.ID] = true
	}
	return nil
}

// ResolvePolicy applies explicit rack ordering after the source rack. NetBox
// evidence must separately establish the source site and rack before calling.
func ResolvePolicy(p Profile, siteID, sourceRackID int64) (Policy, []Requirement, error) {
	if err := ValidateProfile(p); err != nil {
		return Policy{}, nil, err
	}
	if siteID <= 0 || sourceRackID <= 0 {
		return Policy{}, nil, ErrInvalid
	}
	ranks := map[int64]int{}
	for i, id := range p.PreferredRacks {
		if id != sourceRackID {
			ranks[id] = i + 1
		}
	}
	allowed := make(map[int64]bool, len(p.Switches))
	fabrics := make(map[int64]string, len(p.Switches))
	for _, s := range p.Switches {
		allowed[s.DeviceID] = true
		fabrics[s.DeviceID] = s.Fabric
	}
	policy := Policy{SiteID: siteID, SourceRackID: sourceRackID, RackRanks: ranks, AllowSameSite: p.AllowSameSite, DistinctSwitches: p.DistinctSwitches, DistinctFabrics: p.DistinctFabrics, AllowedSwitches: allowed, SwitchFabrics: fabrics}
	requirements := make([]Requirement, 0, len(p.Requirements))
	for _, r := range p.Requirements {
		requirements = append(requirements, Requirement{ID: r.ID, SpeedMbps: r.SpeedMbps, Media: r.Media, PortRole: r.PortRole, Fabric: r.Fabric})
	}
	return policy, requirements, nil
}

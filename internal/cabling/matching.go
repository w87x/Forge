// Package cabling provides read-only, bounded cable candidate matching.
package cabling

import (
	"errors"
	"sort"
)

var ErrInvalid = errors.New("invalid cabling request")
var ErrSearchLimit = errors.New("cabling search limit reached")

type Requirement struct {
	ID        string
	SpeedMbps int
	Media     string
	PortRole  string
	Fabric    string
}
type Port struct {
	ID              int64
	SwitchID        int64
	RackID          int64
	SiteID          int64
	Name            string
	Fabric          string
	SpeedMbps       int
	Media           string
	Role            string
	Physical        bool
	Breakout        bool
	OccupancyKnown  bool
	Occupied        bool
	MarkedConnected bool
	Reserved        bool
}

// RackRanks contains explicit operator-configured ranks. The source rack is
// always rank zero; same-site fallback is considered only when enabled.
type Policy struct {
	SiteID           int64
	SourceRackID     int64
	RackRanks        map[int64]int
	AllowSameSite    bool
	DistinctSwitches bool
	DistinctFabrics  bool
	AllowedSwitches  map[int64]bool
	SwitchFabrics    map[int64]string
}
type Assignment struct {
	RequirementID string
	Port          Port
	Rank          int
	Reason        string
}
type Result struct {
	Assignments []Assignment
	Unsatisfied []string
	// Rejected records the first applicable eligibility reason per port and
	// requirement. Cross-requirement redundancy constraints are evaluated later.
	Rejected []Rejection
}
type Rejection struct {
	RequirementID string
	PortID        int64
	Reason        string
}
type candidate struct {
	port   Port
	rank   int
	reason string
}

func Match(policy Policy, requirements []Requirement, ports []Port) (Result, error) {
	if policy.SiteID <= 0 || policy.SourceRackID <= 0 || len(requirements) == 0 || len(requirements) > 8 || len(ports) > 256 {
		return Result{}, ErrInvalid
	}
	for id, rank := range policy.RackRanks {
		if id <= 0 || rank <= 0 || rank >= 1000000 {
			return Result{}, ErrInvalid
		}
	}
	seenReq := map[string]bool{}
	seenPort := map[int64]bool{}
	for _, r := range requirements {
		if r.ID == "" || seenReq[r.ID] || r.SpeedMbps <= 0 || r.Media == "" || r.PortRole == "" {
			return Result{}, ErrInvalid
		}
		seenReq[r.ID] = true
	}
	for _, p := range ports {
		if p.ID <= 0 || p.SwitchID <= 0 || p.SiteID <= 0 || seenPort[p.ID] {
			return Result{}, ErrInvalid
		}
		seenPort[p.ID] = true
	}
	candidates := make([][]candidate, len(requirements))
	rejected := []Rejection{}
	for i, r := range requirements {
		for _, p := range ports {
			if policy.SwitchFabrics != nil {
				p.Fabric = policy.SwitchFabrics[p.SwitchID]
			}
			reason := ""
			switch {
			case policy.AllowedSwitches != nil && !policy.AllowedSwitches[p.SwitchID]:
				reason = "switch not selected"
			case p.SiteID != policy.SiteID:
				reason = "different site"
			case !p.Physical:
				reason = "not a physical port"
			case p.Breakout:
				reason = "breakout not supported"
			case !p.OccupancyKnown:
				reason = "occupancy unknown"
			case p.Occupied || p.MarkedConnected:
				reason = "occupied or marked connected"
			case p.Reserved:
				reason = "reserved"
			case p.SpeedMbps != r.SpeedMbps:
				reason = "speed mismatch"
			case p.Media != r.Media:
				reason = "media mismatch"
			case p.Role != r.PortRole:
				reason = "role mismatch"
			case r.Fabric != "" && p.Fabric != r.Fabric:
				reason = "fabric mismatch"
			case policy.DistinctFabrics && p.Fabric == "":
				reason = "fabric unknown"
			}
			if reason != "" {
				rejected = append(rejected, Rejection{r.ID, p.ID, reason})
				continue
			}
			rank, reason := 0, "same rack"
			if p.RackID != policy.SourceRackID {
				n, ok := policy.RackRanks[p.RackID]
				if ok {
					rank = n
					reason = "configured rack preference"
				} else if policy.AllowSameSite {
					rank = 1000000
					reason = "same-site fallback"
				} else {
					rejected = append(rejected, Rejection{r.ID, p.ID, "rack not permitted"})
					continue
				}
			}
			candidates[i] = append(candidates[i], candidate{p, rank, reason})
		}
		sort.Slice(candidates[i], func(a, b int) bool {
			x, y := candidates[i][a], candidates[i][b]
			if x.rank != y.rank {
				return x.rank < y.rank
			}
			if x.port.SwitchID != y.port.SwitchID {
				return x.port.SwitchID < y.port.SwitchID
			}
			return x.port.ID < y.port.ID
		})
	}
	// Search constrained requirements first, so a tempting same-rack port cannot
	// consume the only valid candidate for another requirement.
	order := make([]int, len(requirements))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool { return len(candidates[order[i]]) < len(candidates[order[j]]) })
	chosen := make([]candidate, len(requirements))
	usedPorts := map[int64]bool{}
	usedSwitch := map[int64]bool{}
	usedFabric := map[string]bool{}
	visits := 0
	limit := false
	var search func(int) bool
	search = func(depth int) bool {
		if depth == len(order) {
			return true
		}
		for _, c := range candidates[order[depth]] {
			visits++
			if visits > 100000 {
				limit = true
				return false
			}
			p := c.port
			if usedPorts[p.ID] || (policy.DistinctSwitches && usedSwitch[p.SwitchID]) || (policy.DistinctFabrics && usedFabric[p.Fabric]) {
				continue
			}
			usedPorts[p.ID] = true
			usedSwitch[p.SwitchID] = true
			usedFabric[p.Fabric] = true
			chosen[order[depth]] = c
			if search(depth + 1) {
				return true
			}
			delete(usedPorts, p.ID)
			delete(usedSwitch, p.SwitchID)
			delete(usedFabric, p.Fabric)
			if limit {
				return false
			}
		}
		return false
	}
	if !search(0) {
		if limit {
			return Result{}, ErrSearchLimit
		}
		out := Result{Unsatisfied: make([]string, len(requirements)), Rejected: rejected}
		for i, r := range requirements {
			out.Unsatisfied[i] = r.ID
		}
		return out, nil
	}
	out := Result{Assignments: make([]Assignment, len(requirements)), Unsatisfied: []string{}, Rejected: rejected}
	for i, r := range requirements {
		c := chosen[i]
		out.Assignments[i] = Assignment{r.ID, c.port, c.rank, c.reason}
	}
	return out, nil
}

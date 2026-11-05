// Package plans models reviewable changes. It does not execute them.
package plans

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

var ErrInvalid = errors.New("invalid action plan")
var ErrDependency = errors.New("selected actions are missing prerequisites")

// Action contains only bounded, typed fields. No arbitrary URL, shell command,
// HTTP method or opaque JSON body can enter an execution plan.
type Action struct {
	ID                  string   `json:"id"`
	Kind                string   `json:"kind"`
	DeviceID            int64    `json:"device_id"`
	InterfaceName       string   `json:"interface_name,omitempty"`
	InterfaceType       string   `json:"interface_type,omitempty"`
	ExistingInterfaceID int64    `json:"existing_interface_id,omitempty"`
	ExistingIPID        int64    `json:"existing_ip_id,omitempty"`
	Address             string   `json:"address,omitempty"`
	VRFID               *int64   `json:"vrf_id,omitempty"`
	Dependencies        []string `json:"dependencies"`
}
type Plan struct {
	Actions []Action `json:"actions"`
}

func Validate(p Plan) error {
	if len(p.Actions) == 0 || len(p.Actions) > 500 {
		return ErrInvalid
	}
	ids := map[string]Action{}
	interfaces := map[string]bool{}
	addresses := map[string]bool{}
	primary := map[string]bool{}
	for _, a := range p.Actions {
		if a.ID == "" || len(a.ID) > 128 || strings.ContainsAny(a.ID, "\x00\r\n") || a.DeviceID <= 0 || len(a.Dependencies) > 100 {
			return ErrInvalid
		}
		if _, ok := ids[a.ID]; ok {
			return ErrInvalid
		}
		ids[a.ID] = a
		if len(a.InterfaceName) > 128 || strings.ContainsAny(a.InterfaceName, "\x00\r\n") || len(a.InterfaceType) > 64 || strings.ContainsAny(a.InterfaceType, "\x00\r\n") {
			return ErrInvalid
		}
		if (a.VRFID != nil && *a.VRFID <= 0) || a.ExistingInterfaceID < 0 || a.ExistingIPID < 0 {
			return ErrInvalid
		}
		switch a.Kind {
		case "create_interface":
			if a.InterfaceName == "" || a.InterfaceType == "" || a.Address != "" || a.VRFID != nil || a.ExistingInterfaceID != 0 || a.ExistingIPID != 0 {
				return ErrInvalid
			}
			key := strconv.FormatInt(a.DeviceID, 10) + "\x00" + a.InterfaceName
			if interfaces[key] {
				return ErrInvalid
			}
			interfaces[key] = true
		case "create_ip":
			if a.InterfaceName == "" || a.InterfaceType != "" || a.ExistingIPID != 0 {
				return ErrInvalid
			}
			prefix, err := netip.ParsePrefix(a.Address)
			if err != nil {
				return ErrInvalid
			}
			vrf := "global"
			if a.VRFID != nil {
				vrf = strconv.FormatInt(*a.VRFID, 10)
			}
			key := prefix.Addr().String() + "\x00" + vrf
			if addresses[key] {
				return ErrInvalid
			}
			addresses[key] = true
		case "set_primary_ip":
			if a.InterfaceName != "" || a.InterfaceType != "" || a.VRFID != nil || a.ExistingInterfaceID != 0 {
				return ErrInvalid
			}
			prefix, err := netip.ParsePrefix(a.Address)
			if err != nil {
				return ErrInvalid
			}
			family := "6"
			if prefix.Addr().Is4() {
				family = "4"
			}
			key := strconv.FormatInt(a.DeviceID, 10) + "\x00" + family
			if primary[key] {
				return ErrInvalid
			}
			primary[key] = true
		default:
			return ErrInvalid
		}
	}
	for _, a := range p.Actions {
		seen := map[string]bool{}
		for _, d := range a.Dependencies {
			if d == a.ID || seen[d] {
				return ErrInvalid
			}
			seen[d] = true
			other, ok := ids[d]
			if !ok || other.DeviceID != a.DeviceID {
				return ErrInvalid
			}
		}
	}
	for _, a := range p.Actions {
		if a.Kind == "create_ip" && a.ExistingInterfaceID > 0 && interfaces[strconv.FormatInt(a.DeviceID, 10)+"\x00"+a.InterfaceName] {
			return ErrInvalid
		}
		if a.Kind == "set_primary_ip" && a.ExistingIPID > 0 {
			// Reject ambiguity even when the create action is not an explicit
			// dependency: the same plan must not refer to a new and an existing
			// address as if they were interchangeable.
			primaryAddr, _ := netip.ParsePrefix(a.Address)
			for _, d := range p.Actions {
				if d.Kind != "create_ip" || d.DeviceID != a.DeviceID {
					continue
				}
				createdAddr, _ := netip.ParsePrefix(d.Address)
				if createdAddr.Addr() == primaryAddr.Addr() {
					return ErrInvalid
				}
			}
		}
		if a.Kind == "create_ip" && a.ExistingInterfaceID == 0 {
			found := false
			for _, id := range a.Dependencies {
				d := ids[id]
				if d.Kind == "create_interface" && d.InterfaceName == a.InterfaceName {
					found = true
				}
			}
			if !found {
				return ErrInvalid
			}
		}
		if a.Kind == "set_primary_ip" && a.ExistingIPID == 0 {
			found := false
			for _, id := range a.Dependencies {
				d := ids[id]
				if d.Kind == "create_ip" && d.Address == a.Address {
					found = true
				}
			}
			if !found {
				return ErrInvalid
			}
		}
	}
	state := map[string]int{}
	var visit func(string) bool
	visit = func(id string) bool {
		if state[id] == 1 {
			return false
		}
		if state[id] == 2 {
			return true
		}
		state[id] = 1
		for _, dep := range ids[id].Dependencies {
			if !visit(dep) {
				return false
			}
		}
		state[id] = 2
		return true
	}
	for _, a := range p.Actions {
		if !visit(a.ID) {
			return ErrInvalid
		}
	}
	return nil
}

// Digest canonicalizes order but includes every field and dependency. A future
// approval workflow can bind its authorization to this digest.
func Digest(p Plan) (string, error) {
	if err := Validate(p); err != nil {
		return "", err
	}
	copyPlan := Plan{Actions: append([]Action(nil), p.Actions...)}
	for i := range copyPlan.Actions {
		copyPlan.Actions[i].Dependencies = append([]string{}, copyPlan.Actions[i].Dependencies...)
		sort.Strings(copyPlan.Actions[i].Dependencies)
	}
	sort.Slice(copyPlan.Actions, func(i, j int) bool { return copyPlan.Actions[i].ID < copyPlan.Actions[j].ID })
	data, err := json.Marshal(copyPlan)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

// ValidateSelection rejects unknown IDs and selections without their complete
// prerequisite chain. It never silently adds or executes actions.
func ValidateSelection(p Plan, selected []string) error {
	if err := Validate(p); err != nil {
		return err
	}
	if len(selected) == 0 || len(selected) > len(p.Actions) {
		return ErrInvalid
	}
	byID := map[string]Action{}
	for _, a := range p.Actions {
		byID[a.ID] = a
	}
	chosen := map[string]bool{}
	for _, id := range selected {
		if _, ok := byID[id]; !ok || chosen[id] {
			return ErrInvalid
		}
		chosen[id] = true
	}
	for id := range chosen {
		for _, dep := range byID[id].Dependencies {
			if !chosen[dep] {
				return ErrDependency
			}
		}
	}
	return nil
}

// SelectionDigest binds a selected subset as well as the entire validated plan.
// Approval storage and authorization are intentionally outside this package.
func SelectionDigest(p Plan, selected []string) (string, error) {
	if err := ValidateSelection(p, selected); err != nil {
		return "", err
	}
	planHash, err := Digest(p)
	if err != nil {
		return "", err
	}
	ids := append([]string(nil), selected...)
	sort.Strings(ids)
	encoded, err := json.Marshal(struct {
		Plan     string   `json:"plan"`
		Selected []string `json:"selected"`
	}{planHash, ids})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// OrderedSelection deterministically orders approved actions after their
// prerequisites. It returns a copy and performs no external operations.
func OrderedSelection(p Plan, selected []string) ([]Action, error) {
	if err := ValidateSelection(p, selected); err != nil {
		return nil, err
	}
	byID := map[string]Action{}
	for _, a := range p.Actions {
		byID[a.ID] = a
	}
	ids := append([]string(nil), selected...)
	sort.Strings(ids)
	visited := map[string]bool{}
	result := make([]Action, 0, len(ids))
	var visit func(string)
	visit = func(id string) {
		if visited[id] {
			return
		}
		visited[id] = true
		action := byID[id]
		deps := append([]string(nil), action.Dependencies...)
		sort.Strings(deps)
		for _, dep := range deps {
			visit(dep)
		}
		action.Dependencies = append([]string(nil), action.Dependencies...)
		if action.VRFID != nil {
			vrf := *action.VRFID
			action.VRFID = &vrf
		}
		result = append(result, action)
	}
	for _, id := range ids {
		visit(id)
	}
	return result, nil
}

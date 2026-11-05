package network

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"forge/internal/netbox"
)

type AuditFinding struct {
	Rule          string `json:"rule"`
	Status        string `json:"status"`
	Message       string `json:"message"`
	BlocksInstall bool   `json:"blocks_install"`
	Severity      string `json:"severity"`
	Source        string `json:"source"`
	Subject       string `json:"subject,omitempty"`
	Expected      any    `json:"expected,omitempty"`
	Actual        any    `json:"actual,omitempty"`
}
type AuditResult struct {
	Status   string         `json:"status"`
	Findings []AuditFinding `json:"findings"`
}

// AuditDevice compares selected expected interfaces and addresses with
// currently visible NetBox pages. It cannot prove addresses are free globally
// or that a user can see every competing object. The caller must establish
// that g.NetBoxInstanceID, when set, matches the source of both pages.
func AuditDevice(g Graph, imported SavedImport, deviceID int64, interfaces netbox.InterfacePage, addresses netbox.IPAddressPage, vlanEvidence ...[]netbox.VLAN) AuditResult {
	result := AuditResult{Status: "pass", Findings: []AuditFinding{}}
	add := func(rule, status, message string) {
		severity := "info"
		if status == "fail" {
			severity = "error"
		} else if status == "unknown" {
			severity = "warning"
		}
		source := "netbox"
		if rule == "global_conflicts" || (rule == "vlan" && status == "unknown") {
			source = "not_collected"
		}
		result.Findings = append(result.Findings, AuditFinding{Rule: rule, Status: status, Message: message, BlocksInstall: status != "pass", Severity: severity, Source: source})
		if status == "fail" {
			result.Status = "fail"
		} else if status == "unknown" && result.Status != "fail" {
			result.Status = "unknown"
		}
	}
	detail := func(subject string, expected, actual any) {
		n := len(result.Findings)
		if n > 0 {
			result.Findings[n-1].Subject = subject
			result.Findings[n-1].Expected = expected
			result.Findings[n-1].Actual = actual
		}
	}
	if issues := Validate(g); len(issues) > 0 {
		add("profile", "unknown", "The saved network profile is invalid")
		return result
	}
	byName := map[string][]netbox.Interface{}
	for _, iface := range interfaces.Results {
		byName[iface.Name] = append(byName[iface.Name], iface)
	}
	resolved := map[string]int64{}
	observed := map[string]netbox.Interface{}
	vlans := map[int64]netbox.VLAN{}
	if len(vlanEvidence) > 0 {
		for _, v := range vlanEvidence[0] {
			vlans[v.ID] = v
		}
	}
	for _, node := range g.Nodes {
		if node.NetBoxName == "" {
			add("interface", "unknown", fmt.Sprintf("%s has no NetBox interface name", node.OSName))
			detail(node.OSName, "NetBox interface name", nil)
			continue
		}
		matches := byName[node.NetBoxName]
		if len(matches) != 1 {
			add("interface", "unknown", fmt.Sprintf("NetBox interface %s is missing or ambiguous in the collected evidence", node.NetBoxName))
			detail(node.OSName, node.NetBoxName, nil)
			continue
		}
		resolved[node.ID] = matches[0].ID
		observed[node.ID] = matches[0]
		add("interface", "pass", fmt.Sprintf("NetBox interface %s is present", node.NetBoxName))
		detail(node.OSName, node.NetBoxName, matches[0].Name)
		// The relationship fields alone cannot establish that a bond is a
		// NetBox LAG, or that a physical uplink is not a virtual interface.
		// Other types and bridge/VLAN mappings need version qualification.
		if node.Kind == "bond" || node.Kind == "physical" {
			typ := matches[0].Type
			if typ == "" {
				add("interface_type", "unknown", fmt.Sprintf("NetBox did not provide the type of %s", node.NetBoxName))
				detail(node.NetBoxName, node.Kind, nil)
			} else if node.Kind == "bond" && typ != "lag" {
				add("interface_type", "fail", fmt.Sprintf("NetBox interface %s is not a LAG", node.NetBoxName))
				detail(node.NetBoxName, "lag", typ)
			} else if node.Kind == "bond" {
				add("interface_type", "pass", fmt.Sprintf("NetBox interface %s is a LAG", node.NetBoxName))
				detail(node.NetBoxName, "lag", typ)
			} else if typ == "virtual" || typ == "lag" {
				add("interface_type", "fail", fmt.Sprintf("NetBox interface %s is logical, but the profile requires a physical port", node.NetBoxName))
				detail(node.NetBoxName, "physical port", typ)
			}
		}
		if node.MTU > 0 {
			if !matches[0].MTUKnown {
				add("mtu", "unknown", fmt.Sprintf("NetBox did not provide the MTU for %s", node.NetBoxName))
			} else if matches[0].MTU == nil || *matches[0].MTU != node.MTU {
				add("mtu", "fail", fmt.Sprintf("NetBox MTU for %s differs from %d", node.NetBoxName, node.MTU))
			} else {
				add("mtu", "pass", fmt.Sprintf("NetBox MTU for %s matches %d", node.NetBoxName, node.MTU))
			}
			var actual any
			if matches[0].MTU != nil {
				actual = *matches[0].MTU
			} else if matches[0].MTUKnown {
				actual = "not configured"
			}
			detail(node.NetBoxName, node.MTU, actual)
		}
	}
	for _, node := range g.Nodes {
		parent, ok := observed[node.ID]
		if !ok {
			continue
		}
		switch node.Kind {
		case "bond", "bridge":
			expectedMembers := map[int64]bool{}
			membersResolved := true
			for _, id := range node.Members {
				member, exists := observed[id]
				if !exists {
					membersResolved = false
					add("topology", "unknown", fmt.Sprintf("A member of %s is not visible", node.NetBoxName))
					continue
				}
				expectedMembers[member.ID] = true
				known, actual := member.LAGKnown, member.LAGID
				if node.Kind == "bridge" {
					known, actual = member.BridgeKnown, member.BridgeID
				}
				if !known {
					add("topology", "unknown", fmt.Sprintf("NetBox did not provide the %s relationship for %s", node.Kind, member.Name))
				} else if actual == nil || *actual != parent.ID {
					add("topology", "fail", fmt.Sprintf("%s is not attached to %s %s", member.Name, node.Kind, node.NetBoxName))
				} else {
					add("topology", "pass", fmt.Sprintf("%s is attached to %s %s", member.Name, node.Kind, node.NetBoxName))
				}
				var actualID any
				if actual != nil {
					actualID = *actual
				} else if known {
					actualID = "not attached"
				}
				detail(member.Name, parent.ID, actualID)
			}
			// Positive relationships in the collected evidence can reveal
			// extra members even when the page set is incomplete. Do not
			// propose removal: an operator must review the discrepancy.
			for _, member := range interfaces.Results {
				if !membersResolved {
					break
				}
				known, actual := member.LAGKnown, member.LAGID
				if node.Kind == "bridge" {
					known, actual = member.BridgeKnown, member.BridgeID
				}
				if known && actual != nil && *actual == parent.ID && !expectedMembers[member.ID] {
					add("unexpected_member", "fail", fmt.Sprintf("%s is attached to %s %s but is not listed in the profile", member.Name, node.Kind, node.NetBoxName))
					detail(member.Name, "not a member", parent.ID)
				}
			}
		case "vlan":
			actualParent, exists := observed[node.Parent]
			vlan, visible := vlans[node.NetBoxVLANID]
			if node.NetBoxVLANID == 0 || !visible {
				add("vlan", "unknown", fmt.Sprintf("VLAN ID %d has not been verified in NetBox", node.VLANID))
				detail(node.NetBoxName, node.VLANID, nil)
			} else if vlan.VID != node.VLANID {
				add("vlan", "fail", fmt.Sprintf("NetBox VLAN #%d has a different VLAN ID", node.NetBoxVLANID))
				detail(node.NetBoxName, node.VLANID, vlan.VID)
			} else if !exists {
				add("vlan", "unknown", fmt.Sprintf("Tagged VLANs on the parent of %s are unavailable", node.NetBoxName))
				detail(node.NetBoxName, node.NetBoxVLANID, nil)
			} else if !actualParent.UntaggedVLANKnown {
				add("vlan", "unknown", fmt.Sprintf("Native VLAN on %s was not provided", actualParent.Name))
				detail(node.NetBoxName, "tagged", nil)
			} else if actualParent.UntaggedVLANID != nil && *actualParent.UntaggedVLANID == node.NetBoxVLANID {
				add("vlan", "fail", fmt.Sprintf("VLAN %d is configured as untagged on %s", node.VLANID, actualParent.Name))
				detail(node.NetBoxName, "tagged", "untagged")
			} else if actualParent.Mode == "tagged-all" {
				add("vlan", "pass", fmt.Sprintf("%s permits all tagged VLANs", actualParent.Name))
				detail(node.NetBoxName, node.NetBoxVLANID, "all tagged VLANs")
			} else if actualParent.Mode != "tagged" || !actualParent.TaggedVLANsKnown {
				add("vlan", "unknown", fmt.Sprintf("Tagged VLAN mode or membership on %s is unavailable or unsupported", actualParent.Name))
				detail(node.NetBoxName, node.NetBoxVLANID, nil)
			} else {
				tagged := false
				for _, id := range actualParent.TaggedVLANIDs {
					if id == node.NetBoxVLANID {
						tagged = true
						break
					}
				}
				if tagged {
					add("vlan", "pass", fmt.Sprintf("VLAN %d is tagged on %s", node.VLANID, actualParent.Name))
				} else {
					add("vlan", "fail", fmt.Sprintf("VLAN %d is not tagged on %s", node.VLANID, actualParent.Name))
				}
				var found any = actualParent.TaggedVLANIDs
				if len(actualParent.TaggedVLANIDs) == 0 {
					found = "no tagged VLANs"
				}
				detail(node.NetBoxName, node.NetBoxVLANID, found)
			}
			if !exists {
				add("topology", "unknown", fmt.Sprintf("The parent of %s is not visible", node.NetBoxName))
				continue
			}
			parentKind := ""
			for _, candidate := range g.Nodes {
				if candidate.ID == node.Parent {
					parentKind = candidate.Kind
					break
				}
			}
			if parentKind != "physical" {
				add("topology", "unknown", fmt.Sprintf("Parent mapping for %s requires version qualification", node.NetBoxName))
			} else if !parent.ParentKnown {
				add("topology", "unknown", fmt.Sprintf("NetBox did not provide the parent of %s", node.NetBoxName))
			} else if parent.ParentID == nil || *parent.ParentID != actualParent.ID {
				add("topology", "fail", fmt.Sprintf("%s has a different NetBox parent", node.NetBoxName))
			} else {
				add("topology", "pass", fmt.Sprintf("%s has the expected NetBox parent", node.NetBoxName))
			}
		}
	}
	if interfaces.HasMore {
		add("interface_coverage", "unknown", "The interface page limit was reached; additional interfaces were not checked")
	}
	if addresses.HasMore {
		add("address_coverage", "unknown", "The IP address page limit was reached; additional addresses were not checked")
	}
	count := 0
	for _, expected := range imported.Addresses {
		if expected.DeviceID != deviceID {
			continue
		}
		count++
		interfaceID, ok := resolved[expected.InterfaceID]
		if !ok {
			add("address", "unknown", fmt.Sprintf("%s cannot be matched without its NetBox interface", expected.Address))
			continue
		}
		var vrf *int64
		if expected.VRFID != "" {
			if g.NetBoxInstanceID == "" {
				add("address", "unknown", fmt.Sprintf("%s has no NetBox connection for its VRF reference", expected.Address))
				continue
			}
			id, err := strconv.ParseInt(expected.VRFID, 10, 64)
			if err != nil || id <= 0 {
				add("address", "unknown", fmt.Sprintf("%s has an unverified VRF reference", expected.Address))
				continue
			}
			vrf = &id
		}
		address, err := netip.ParseAddr(expected.Address)
		if err != nil {
			add("address", "unknown", "Saved address is invalid")
			continue
		}
		prefix, err := netip.ParsePrefix(expected.Prefix)
		if err != nil {
			add("address", "unknown", "Saved prefix is invalid")
			continue
		}
		correct, conflict, unknownVRF := 0, false, false
		visible := []string{}
		for _, actual := range addresses.Results {
			p, err := netip.ParsePrefix(actual.Address)
			if err != nil || p.Addr() != address {
				continue
			}
			vrfLabel := "unknown VRF"
			if actual.VRFKnown {
				vrfLabel = "global"
			}
			if actual.VRFID != nil {
				vrfLabel = fmt.Sprintf("VRF #%d", *actual.VRFID)
			}
			visible = append(visible, fmt.Sprintf("%s on interface #%d (%s)", actual.Address, actual.InterfaceID, vrfLabel))
			if !actual.VRFKnown {
				unknownVRF = true
				continue
			}
			sameVRF := (vrf == nil && actual.VRFID == nil) || (vrf != nil && actual.VRFID != nil && *vrf == *actual.VRFID)
			if !sameVRF {
				continue
			}
			if actual.InterfaceID == interfaceID && p.Bits() == prefix.Bits() {
				correct++
			} else {
				conflict = true
			}
		}
		if unknownVRF {
			add("address", "unknown", fmt.Sprintf("%s has a visible assignment with an unknown VRF", expected.Address))
		} else if correct == 1 && !conflict {
			add("address", "pass", fmt.Sprintf("%s is assigned to the expected interface and VRF", expected.Address))
		} else if correct > 1 || (correct > 0 && conflict) {
			add("address", "unknown", fmt.Sprintf("%s has multiple visible assignments; review them", expected.Address))
		} else if conflict {
			add("address", "fail", fmt.Sprintf("%s is visible with a different interface, VRF or mask", expected.Address))
		} else {
			add("address", "unknown", fmt.Sprintf("%s is not present in the collected evidence", expected.Address))
		}
		vrfLabel := "global"
		if vrf != nil {
			vrfLabel = fmt.Sprintf("VRF #%d", *vrf)
		}
		var actual any
		if len(visible) > 0 {
			actual = strings.Join(visible, "; ")
		}
		detail(expected.Group, fmt.Sprintf("%s/%d on interface #%d (%s)", expected.Address, prefix.Bits(), interfaceID, vrfLabel), actual)
	}
	if count == 0 {
		add("addresses", "unknown", "No saved allocation is bound to this device")
	}
	add("global_conflicts", "unknown", "Competing allocations cannot be ruled out: NetBox visibility and address lookup coverage are limited")
	return result
}

// AddVisibleConflicts adds positive evidence only. The caller obtained these
// candidates through the current user's NetBox key. No result can establish
// that all competing allocations are visible or that pagination is complete.
func AddVisibleConflicts(result *AuditResult, g Graph, imported SavedImport, deviceID int64, interfaces netbox.InterfacePage, candidates []netbox.ConflictAddress) {
	byName := map[string][]int64{}
	for _, iface := range interfaces.Results {
		byName[iface.Name] = append(byName[iface.Name], iface.ID)
	}
	nodeNames := map[string]string{}
	for _, node := range g.Nodes {
		nodeNames[node.ID] = node.NetBoxName
	}
	for _, expected := range imported.Addresses {
		if expected.DeviceID != deviceID {
			continue
		}
		host, err := netip.ParseAddr(expected.Address)
		if err != nil {
			continue
		}
		matches := byName[nodeNames[expected.InterfaceID]]
		if len(matches) != 1 {
			continue
		}
		var vrf *int64
		if expected.VRFID != "" {
			id, err := strconv.ParseInt(expected.VRFID, 10, 64)
			if err != nil || id <= 0 {
				continue
			}
			vrf = &id
		}
		conflicts := 0
		for _, candidate := range candidates {
			if candidate.Address != host || !candidate.VRFKnown || candidate.AssignedID == nil || candidate.AssignedType == "" {
				continue
			}
			if !((vrf == nil && candidate.VRFID == nil) || (vrf != nil && candidate.VRFID != nil && *vrf == *candidate.VRFID)) {
				continue
			}
			if candidate.AssignedType != "dcim.interface" || *candidate.AssignedID != matches[0] {
				conflicts++
			}
		}
		if conflicts > 0 {
			result.Findings = append(result.Findings, AuditFinding{Rule: "visible_competing_allocation", Status: "fail", Severity: "error", Source: "netbox", Subject: expected.Group, Message: fmt.Sprintf("%s has %d visible competing allocation(s) in the same VRF; review shared or anycast use", host, conflicts), Expected: "No competing allocation", Actual: conflicts, BlocksInstall: true})
			result.Status = "fail"
		}
	}
}

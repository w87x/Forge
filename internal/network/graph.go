// Package network models desired network topology without generating changes.
package network

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

type Node struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"` // physical, bond, vlan, bridge
	OSName       string   `json:"os_name"`
	NetBoxName   string   `json:"netbox_name"`
	MTU          int      `json:"mtu"`
	Parent       string   `json:"parent"`
	Members      []string `json:"members"`
	VLANID       int      `json:"vlan_id"`
	NetBoxVLANID int64    `json:"netbox_vlan_id"`
}
type Network struct {
	Name        string `json:"name"`
	InterfaceID string `json:"interface_id"`
	Prefix      string `json:"prefix"`
	// VRFID identifies an IPAM VRF. It never creates a Linux VRF device.
	VRFID           string `json:"vrf_id"`
	AllocationGroup string `json:"allocation_group"`
}
type Graph struct {
	NetBoxInstanceID string    `json:"netbox_instance_id"`
	Nodes            []Node    `json:"nodes"`
	Networks         []Network `json:"networks"`
}
type Issue struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

var interfaceName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$`)

// Validate is deterministic and never reaches NetBox or creates resources.
// An empty VRFID means the NetBox global table, not a Linux VRF interface.
func Validate(g Graph) []Issue {
	issues := []Issue{}
	add := func(field, message string) { issues = append(issues, Issue{field, message}) }
	if len(g.Nodes) > 256 || len(g.Networks) > 256 {
		add("graph", "at most 256 nodes and networks are supported")
		return issues
	}
	if len(g.NetBoxInstanceID) > 128 || strings.ContainsAny(g.NetBoxInstanceID, "\x00\r\n") {
		add("netbox_instance_id", "invalid NetBox connection reference")
	}
	byID := map[string]Node{}
	vlanVIDs := map[int64]int{}
	osNames := map[string]bool{}
	nbNames := map[string]bool{}
	for i, n := range g.Nodes {
		field := fmt.Sprintf("nodes[%d]", i)
		if n.ID == "" || len(n.ID) > 128 {
			add(field+".id", "a stable ID is required")
		} else if _, ok := byID[n.ID]; ok {
			add(field+".id", "duplicate node ID")
		} else {
			byID[n.ID] = n
		}
		if !interfaceName.MatchString(n.OSName) {
			add(field+".os_name", "invalid Linux interface name")
		} else if osNames[n.OSName] {
			add(field+".os_name", "duplicate Linux interface name")
		} else {
			osNames[n.OSName] = true
		}
		if len(n.NetBoxName) > 128 || strings.ContainsAny(n.NetBoxName, "\x00\r\n") {
			add(field+".netbox_name", "invalid NetBox interface name")
		} else if n.NetBoxName != "" {
			if nbNames[n.NetBoxName] {
				add(field+".netbox_name", "duplicate NetBox interface name")
			}
			nbNames[n.NetBoxName] = true
		}
		if n.MTU != 0 && (n.MTU < 68 || n.MTU > 65535) {
			add(field+".mtu", "MTU must be 68–65535 or unspecified")
		}
		switch n.Kind {
		case "physical":
			if n.Parent != "" || len(n.Members) > 0 || n.VLANID != 0 || n.NetBoxVLANID != 0 {
				add(field, "physical interfaces cannot have parent, members or VLAN ID")
			}
		case "bond":
			if n.Parent != "" || n.VLANID != 0 || n.NetBoxVLANID != 0 || len(n.Members) == 0 {
				add(field, "a bond needs members and cannot have a parent or VLAN ID")
			}
		case "vlan":
			if n.Parent == "" || len(n.Members) > 0 || n.VLANID < 1 || n.VLANID > 4094 {
				add(field, "a VLAN needs a parent and VLAN ID 1–4094, without members")
			}
			if n.NetBoxVLANID < 0 || (n.NetBoxVLANID > 0 && g.NetBoxInstanceID == "") {
				add(field+".netbox_vlan_id", "a NetBox connection is required for a VLAN reference")
			}
			if n.NetBoxVLANID > 0 {
				if vid, exists := vlanVIDs[n.NetBoxVLANID]; exists && vid != n.VLANID {
					add(field+".netbox_vlan_id", "the same NetBox VLAN cannot have different VLAN IDs")
				} else {
					vlanVIDs[n.NetBoxVLANID] = n.VLANID
				}
			}
		case "bridge":
			if n.Parent != "" || n.VLANID != 0 || n.NetBoxVLANID != 0 || len(n.Members) == 0 {
				add(field, "a bridge needs members and cannot have a parent or VLAN ID")
			}
		default:
			add(field+".kind", "unsupported interface kind")
		}
	}
	memberOf := map[string]string{}
	edges := map[string][]string{}
	for i, n := range g.Nodes {
		field := fmt.Sprintf("nodes[%d]", i)
		if n.Parent != "" {
			p, ok := byID[n.Parent]
			if !ok {
				add(field+".parent", "parent does not exist")
			} else {
				edges[n.ID] = append(edges[n.ID], n.Parent)
				if n.Kind == "vlan" && p.Kind != "physical" && p.Kind != "bond" {
					add(field+".parent", "VLAN parent must be physical or bond")
				}
				if n.MTU > 0 && p.MTU > 0 && n.MTU > p.MTU {
					add(field+".mtu", "MTU exceeds parent MTU")
				}
			}
		}
		seen := map[string]bool{}
		for _, id := range n.Members {
			if seen[id] {
				add(field+".members", "duplicate member")
				continue
			}
			seen[id] = true
			m, ok := byID[id]
			if !ok {
				add(field+".members", "member does not exist")
				continue
			}
			edges[n.ID] = append(edges[n.ID], id)
			if owner, ok := memberOf[id]; ok && owner != n.ID {
				add(field+".members", "member already belongs to another bond or bridge")
			} else {
				memberOf[id] = n.ID
			}
			if n.Kind == "bond" && m.Kind != "physical" {
				add(field+".members", "bond members must be physical")
			}
			if n.Kind == "bridge" && m.Kind != "physical" && m.Kind != "bond" && m.Kind != "vlan" {
				add(field+".members", "bridge members must be physical, bond or VLAN")
			}
			if n.MTU > 0 && m.MTU > 0 && n.MTU > m.MTU {
				add(field+".mtu", "MTU exceeds member MTU")
			}
		}
	}
	state := map[string]int{}
	var visit func(string)
	visit = func(id string) {
		if state[id] == 1 {
			add("graph", "interface relationships contain a cycle")
			return
		}
		if state[id] == 2 {
			return
		}
		state[id] = 1
		for _, next := range edges[id] {
			visit(next)
		}
		state[id] = 2
	}
	for _, n := range g.Nodes {
		if n.ID != "" {
			visit(n.ID)
		}
	}
	groups := map[string]bool{}
	names := map[string]bool{}
	for i, n := range g.Networks {
		field := fmt.Sprintf("networks[%d]", i)
		if n.Name == "" || names[n.Name] {
			add(field+".name", "network name must be nonempty and unique")
		}
		names[n.Name] = true
		if _, ok := byID[n.InterfaceID]; !ok {
			add(field+".interface_id", "network interface does not exist")
		}
		prefix, err := netip.ParsePrefix(n.Prefix)
		if err != nil || prefix != prefix.Masked() {
			add(field+".prefix", "prefix must be a canonical IPv4 or IPv6 network")
		}
		if len(n.VRFID) > 128 || strings.ContainsAny(n.VRFID, "\x00\r\n") {
			add(field+".vrf_id", "invalid NetBox VRF reference")
		}
		if n.VRFID != "" {
			id, err := strconv.ParseInt(n.VRFID, 10, 64)
			if err != nil || id <= 0 || strconv.FormatInt(id, 10) != n.VRFID {
				add(field+".vrf_id", "VRF reference must be a numeric NetBox ID")
			}
		}
		if n.VRFID != "" && g.NetBoxInstanceID == "" {
			add(field+".vrf_id", "a NetBox connection is required for a VRF reference")
		}
		if n.AllocationGroup == "" || len(n.AllocationGroup) > 128 {
			add(field+".allocation_group", "allocation group is required")
		} else if groups[n.AllocationGroup] {
			add(field+".allocation_group", "allocation group is already used")
		} else {
			groups[n.AllocationGroup] = true
		}
	}
	return issues
}

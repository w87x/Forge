package network

import (
	"net/netip"
	"testing"

	"forge/internal/netbox"
)

func TestAuditDeviceRespectsVRFAndCoverage(t *testing.T) {
	g := Graph{NetBoxInstanceID: "nb", Nodes: []Node{{ID: "port", Kind: "physical", OSName: "eno1", NetBoxName: "Ethernet1"}}, Networks: []Network{{Name: "control", InterfaceID: "port", Prefix: "192.0.2.0/24", VRFID: "7", AllocationGroup: "ctl_ips"}}}
	imported := SavedImport{Addresses: []ResolvedAddress{{DeviceID: 1, HostKey: "host", Group: "ctl_ips", InterfaceID: "port", VRFID: "7", Address: "192.0.2.1", Prefix: "192.0.2.0/24"}}}
	seven := int64(7)
	other := int64(8)
	interfaces := netbox.InterfacePage{Results: []netbox.Interface{{ID: 10, Name: "Ethernet1"}}}
	addresses := netbox.IPAddressPage{Results: []netbox.IPAddress{{Address: "192.0.2.1/24", InterfaceID: 10, VRFKnown: true, VRFID: &seven}, {Address: "192.0.2.1/24", InterfaceID: 11, VRFKnown: true, VRFID: &other}}}
	result := AuditDevice(g, imported, 1, interfaces, addresses)
	if result.Status != "unknown" {
		t.Fatalf("global conflict scope must remain unknown: %+v", result)
	}
	for _, f := range result.Findings {
		if f.Rule == "address" && f.Status != "pass" {
			t.Fatalf("matching assignment with another VRF: %+v", result)
		}
	}
	addresses.Results = addresses.Results[1:]
	if result := AuditDevice(g, imported, 1, interfaces, addresses); result.Status != "unknown" {
		t.Fatalf("invisible assignment: %+v", result)
	}
	addresses.Results = []netbox.IPAddress{{Address: "192.0.2.1/24", InterfaceID: 11, VRFKnown: true, VRFID: &seven}}
	if result := AuditDevice(g, imported, 1, interfaces, addresses); result.Status != "fail" {
		t.Fatalf("wrong interface: %+v", result)
	} else {
		for _, finding := range result.Findings {
			if finding.Rule == "address" && (finding.Expected == nil || finding.Actual == nil || finding.Subject != "ctl_ips" || finding.Severity != "error") {
				t.Fatalf("address evidence: %+v", finding)
			}
		}
	}
	addresses.Results = []netbox.IPAddress{{Address: "192.0.2.1/25", InterfaceID: 10, VRFKnown: true, VRFID: &seven}}
	if result := AuditDevice(g, imported, 1, interfaces, addresses); result.Status != "fail" {
		t.Fatalf("wrong mask: %+v", result)
	}
	addresses.Results = []netbox.IPAddress{{Address: "192.0.2.1/24", InterfaceID: 10, VRFKnown: true, VRFID: &seven}}
	addresses.HasMore = true
	if result := AuditDevice(g, imported, 1, interfaces, addresses); result.Status != "unknown" {
		t.Fatalf("incomplete page passed: %+v", result)
	}
}

func TestAuditAddressWithOmittedVRFIsUnknown(t *testing.T) {
	g := Graph{Nodes: []Node{{ID: "p", Kind: "physical", OSName: "eno1", NetBoxName: "port1"}}, Networks: []Network{{Name: "ctl", InterfaceID: "p", Prefix: "192.0.2.0/24", AllocationGroup: "ctl"}}}
	imported := SavedImport{Addresses: []ResolvedAddress{{DeviceID: 1, InterfaceID: "p", Address: "192.0.2.1", Prefix: "192.0.2.0/24"}}}
	interfaces := netbox.InterfacePage{Results: []netbox.Interface{{ID: 1, Name: "port1"}}}
	addresses := netbox.IPAddressPage{Results: []netbox.IPAddress{{Address: "192.0.2.1/24", InterfaceID: 1}}}
	check := func(want string) {
		t.Helper()
		for _, f := range AuditDevice(g, imported, 1, interfaces, addresses).Findings {
			if f.Rule == "address" {
				if f.Status != want {
					t.Fatalf("address status %q, expected %q", f.Status, want)
				}
				return
			}
		}
		t.Fatal("missing address finding")
	}
	check("unknown")
	addresses.Results[0].VRFKnown = true
	check("pass")
	addresses.Results = append(addresses.Results, netbox.IPAddress{Address: "192.0.2.1/24", InterfaceID: 1})
	check("unknown")
}

func TestAuditBondAndBridgeRelationshipsUseKnownEvidence(t *testing.T) {
	g := Graph{Nodes: []Node{{ID: "p1", Kind: "physical", OSName: "eno1", NetBoxName: "port1"}, {ID: "p2", Kind: "physical", OSName: "eno2", NetBoxName: "port2"}, {ID: "bond", Kind: "bond", OSName: "bond0", NetBoxName: "bond0", Members: []string{"p1", "p2"}}, {ID: "bridge", Kind: "bridge", OSName: "br0", NetBoxName: "br0", Members: []string{"bond"}}}, Networks: []Network{{Name: "ctl", InterfaceID: "bridge", Prefix: "192.0.2.0/24", AllocationGroup: "ctl"}}}
	bond := int64(3)
	bridge := int64(4)
	pages := netbox.InterfacePage{Results: []netbox.Interface{{ID: 1, Name: "port1", LAGKnown: true, LAGID: &bond}, {ID: 2, Name: "port2"}, {ID: 3, Name: "bond0", BridgeKnown: true, BridgeID: &bridge}, {ID: 4, Name: "br0"}}}
	imported := SavedImport{Addresses: []ResolvedAddress{{DeviceID: 1, InterfaceID: "bridge", Address: "192.0.2.1", Prefix: "192.0.2.0/24"}}}
	ips := netbox.IPAddressPage{Results: []netbox.IPAddress{{Address: "192.0.2.1/24", InterfaceID: 4, VRFKnown: true}}}
	result := AuditDevice(g, imported, 1, pages, ips)
	unknown := false
	for _, f := range result.Findings {
		if f.Rule == "topology" && f.Status == "unknown" {
			unknown = true
		}
	}
	if !unknown {
		t.Fatalf("omitted relationship passed: %+v", result)
	}
	pages.Results[1].LAGKnown = true
	result = AuditDevice(g, imported, 1, pages, ips)
	if result.Status != "fail" {
		t.Fatalf("missing known bond membership: %+v", result)
	}
	pages.Results[1].LAGID = &bond
	result = AuditDevice(g, imported, 1, pages, ips)
	for _, f := range result.Findings {
		if f.Rule == "topology" && f.Status != "pass" {
			t.Fatalf("valid relationships: %+v", result)
		}
	}
}

func TestAuditVLANRequiresVerifiedObjectAndTagEvidence(t *testing.T) {
	g := Graph{NetBoxInstanceID: "nb", Nodes: []Node{{ID: "p", Kind: "physical", OSName: "eno1", NetBoxName: "port1"}, {ID: "v", Kind: "vlan", OSName: "eno1.100", NetBoxName: "eno1.100", Parent: "p", VLANID: 100, NetBoxVLANID: 12}}, Networks: []Network{{Name: "ctl", InterfaceID: "v", Prefix: "192.0.2.0/24", AllocationGroup: "ctl"}}}
	parent := int64(1)
	pages := netbox.InterfacePage{Results: []netbox.Interface{{ID: 1, Name: "port1", Mode: "tagged", UntaggedVLANKnown: true, TaggedVLANsKnown: true, TaggedVLANIDs: []int64{12}}, {ID: 2, Name: "eno1.100", ParentKnown: true, ParentID: &parent}}}
	imported := SavedImport{Addresses: []ResolvedAddress{{DeviceID: 1, InterfaceID: "v", Address: "192.0.2.1", Prefix: "192.0.2.0/24"}}}
	ips := netbox.IPAddressPage{Results: []netbox.IPAddress{{Address: "192.0.2.1/24", InterfaceID: 2, VRFKnown: true}}}
	result := AuditDevice(g, imported, 1, pages, ips, []netbox.VLAN{{ID: 12, VID: 100}})
	for _, f := range result.Findings {
		if f.Rule == "vlan" && f.Status != "pass" {
			t.Fatalf("valid VLAN: %+v", result)
		}
	}
	result = AuditDevice(g, imported, 1, pages, ips)
	for _, f := range result.Findings {
		if f.Rule == "vlan" && f.Status != "unknown" {
			t.Fatalf("unseen VLAN: %+v", result)
		}
	}
	result = AuditDevice(g, imported, 1, pages, ips, []netbox.VLAN{{ID: 12, VID: 200}})
	if result.Status != "fail" {
		t.Fatalf("VID mismatch: %+v", result)
	}
	pages.Results[0].Mode = "tagged-all"
	pages.Results[0].TaggedVLANsKnown = false
	result = AuditDevice(g, imported, 1, pages, ips, []netbox.VLAN{{ID: 12, VID: 100}})
	for _, f := range result.Findings {
		if f.Rule == "vlan" && f.Status != "pass" {
			t.Fatalf("tagged all: %+v", result)
		}
	}
	pages.Results[0].UntaggedVLANKnown = false
	result = AuditDevice(g, imported, 1, pages, ips, []netbox.VLAN{{ID: 12, VID: 100}})
	for _, f := range result.Findings {
		if f.Rule == "vlan" && f.Status != "unknown" {
			t.Fatalf("omitted native VLAN must remain unknown: %+v", result)
		}
	}
	pages.Results[0].UntaggedVLANKnown = true
	native := int64(12)
	pages.Results[0].UntaggedVLANID = &native
	result = AuditDevice(g, imported, 1, pages, ips, []netbox.VLAN{{ID: 12, VID: 100}})
	if result.Status != "fail" {
		t.Fatalf("untagged VLAN: %+v", result)
	}
}

func TestVisibleCompetingAllocations(t *testing.T) {
	g := Graph{NetBoxInstanceID: "nb", Nodes: []Node{{ID: "port", Kind: "physical", OSName: "eno1", NetBoxName: "port"}}, Networks: []Network{{Name: "ctl", InterfaceID: "port", Prefix: "192.0.2.0/24", VRFID: "7", AllocationGroup: "ctl"}}}
	imported := SavedImport{Addresses: []ResolvedAddress{{DeviceID: 1, InterfaceID: "port", VRFID: "7", Address: "192.0.2.1", Prefix: "192.0.2.0/24"}}}
	interfaces := netbox.InterfacePage{Results: []netbox.Interface{{ID: 10, Name: "port"}}}
	seven := int64(7)
	other := int64(8)
	assigned := int64(10)
	elsewhere := int64(11)
	candidates := []netbox.ConflictAddress{{ID: 1, Address: netip.MustParseAddr("192.0.2.1"), VRFKnown: true, VRFID: &seven, AssignedType: "dcim.interface", AssignedID: &assigned}, {ID: 2, Address: netip.MustParseAddr("192.0.2.1"), VRFKnown: true, VRFID: &other, AssignedType: "dcim.interface", AssignedID: &elsewhere}, {ID: 3, Address: netip.MustParseAddr("192.0.2.1"), VRFKnown: false, AssignedType: "dcim.interface", AssignedID: &elsewhere}}
	result := AuditResult{Status: "unknown"}
	AddVisibleConflicts(&result, g, imported, 1, interfaces, candidates)
	if result.Status != "unknown" || len(result.Findings) != 0 {
		t.Fatalf("unproven collision: %+v", result)
	}
	candidates = append(candidates, netbox.ConflictAddress{ID: 4, Address: netip.MustParseAddr("192.0.2.1"), VRFKnown: true, VRFID: &seven, AssignedType: "virtualization.vminterface", AssignedID: &elsewhere})
	AddVisibleConflicts(&result, g, imported, 1, interfaces, candidates)
	if result.Status != "fail" || len(result.Findings) != 1 || result.Findings[0].Rule != "visible_competing_allocation" {
		t.Fatalf("collision not reported: %+v", result)
	}
}

func TestAuditInterfaceTypes(t *testing.T) {
	g := Graph{Nodes: []Node{{ID: "port", Kind: "physical", OSName: "eno1", NetBoxName: "port1"}, {ID: "bond", Kind: "bond", OSName: "bond0", NetBoxName: "bond0", Members: []string{"port"}}}, Networks: []Network{{Name: "ctl", InterfaceID: "bond", Prefix: "192.0.2.0/24", AllocationGroup: "ctl"}}}
	bond := int64(2)
	interfaces := netbox.InterfacePage{Results: []netbox.Interface{{ID: 1, Name: "port1", Type: "virtual", LAGKnown: true, LAGID: &bond}, {ID: 2, Name: "bond0", Type: "virtual"}}}
	imported := SavedImport{Addresses: []ResolvedAddress{{DeviceID: 1, InterfaceID: "bond", Address: "192.0.2.1", Prefix: "192.0.2.0/24"}}}
	ips := netbox.IPAddressPage{Results: []netbox.IPAddress{{Address: "192.0.2.1/24", InterfaceID: 2, VRFKnown: true}}}
	count := 0
	for _, f := range AuditDevice(g, imported, 1, interfaces, ips).Findings {
		if f.Rule == "interface_type" && f.Status == "fail" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("expected physical and bond type mismatches, got %d", count)
	}
	interfaces.Results[0].Type = "1000base-t"
	interfaces.Results[1].Type = "lag"
	for _, f := range AuditDevice(g, imported, 1, interfaces, ips).Findings {
		if f.Rule == "interface_type" && f.Status != "pass" {
			t.Fatalf("valid types: %+v", f)
		}
	}
	interfaces.Results[1].Type = ""
	found := false
	for _, f := range AuditDevice(g, imported, 1, interfaces, ips).Findings {
		if f.Rule == "interface_type" && f.Status == "unknown" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing type treated as known")
	}
}

func TestAuditReportsUnexpectedBondMembersWithoutGuessing(t *testing.T) {
	g := Graph{Nodes: []Node{{ID: "p", Kind: "physical", OSName: "eno1", NetBoxName: "port1"}, {ID: "bond", Kind: "bond", OSName: "bond0", NetBoxName: "bond0", Members: []string{"p"}}}, Networks: []Network{{Name: "ctl", InterfaceID: "bond", Prefix: "192.0.2.0/24", AllocationGroup: "ctl"}}}
	bond := int64(2)
	ifaces := netbox.InterfacePage{HasMore: true, Results: []netbox.Interface{{ID: 1, Name: "port1", LAGKnown: true, LAGID: &bond}, {ID: 2, Name: "bond0", Type: "lag"}, {ID: 3, Name: "port2", LAGKnown: true, LAGID: &bond}}}
	imported := SavedImport{Addresses: []ResolvedAddress{{DeviceID: 1, InterfaceID: "bond", Address: "192.0.2.1", Prefix: "192.0.2.0/24"}}}
	check := func(want bool) {
		t.Helper()
		found := false
		for _, f := range AuditDevice(g, imported, 1, ifaces, netbox.IPAddressPage{}).Findings {
			if f.Rule == "unexpected_member" {
				found = true
				if f.Status != "fail" || f.Subject != "port2" {
					t.Fatalf("unexpected finding: %+v", f)
				}
			}
		}
		if found != want {
			t.Fatalf("unexpected member reported %v, want %v", found, want)
		}
	}
	check(true)
	ifaces.Results[2].LAGKnown = false
	check(false)
	ifaces.Results[2].LAGKnown = true
	ifaces.Results = ifaces.Results[1:]
	check(false) // Cannot prove whether the unresolved desired port is the observed member.
}

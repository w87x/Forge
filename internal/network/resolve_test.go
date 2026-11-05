package network

import (
	"strings"
	"testing"
)

func TestResolveAddressesAndVRFConflicts(t *testing.T) {
	g := Graph{NetBoxInstanceID: "nb", Nodes: []Node{{ID: "eth", Kind: "physical", OSName: "eth0"}}, Networks: []Network{{Name: "one", InterfaceID: "eth", Prefix: "192.0.2.0/24", VRFID: "1", AllocationGroup: "a"}, {Name: "two", InterfaceID: "eth", Prefix: "192.0.2.0/24", VRFID: "2", AllocationGroup: "b"}}}
	imported := AllocationImport{Assignments: []Assignment{{Group: "a", DeviceID: 1, HostKey: "one", Value: "192.0.2.1/24"}, {Group: "b", DeviceID: 1, HostKey: "one", Value: "192.0.2.1"}}}
	addresses, issues := Resolve(g, imported)
	if len(issues) != 0 || len(addresses) != 2 {
		t.Fatalf("different VRFs: %+v %+v", addresses, issues)
	}
	g.Networks[1].VRFID = "1"
	_, issues = Resolve(g, imported)
	if len(issues) != 1 || !strings.Contains(issues[0].Message, "same VRF") {
		t.Fatalf("duplicate: %+v", issues)
	}
	imported.Assignments[1].Value = "192.0.2.2/25"
	_, issues = Resolve(g, imported)
	if len(issues) != 1 || !strings.Contains(issues[0].Message, "mask") {
		t.Fatalf("mask: %+v", issues)
	}
	imported.Assignments[1].Value = "192.0.3.2"
	_, issues = Resolve(g, imported)
	if len(issues) != 1 || !strings.Contains(issues[0].Message, "outside") {
		t.Fatalf("prefix: %+v", issues)
	}
	g.Networks[1].InterfaceID = "missing"
	_, issues = Resolve(g, imported)
	if len(issues) == 0 || !strings.Contains(issues[0].Message, "interface") {
		t.Fatalf("interface: %+v", issues)
	}
}

package network

import (
	"strings"
	"testing"
)

func exampleGraph() Graph {
	return Graph{NetBoxInstanceID: "nb", Nodes: []Node{
		{ID: "p1", Kind: "physical", OSName: "eno1", NetBoxName: "port1", MTU: 9000},
		{ID: "p2", Kind: "physical", OSName: "eno2", NetBoxName: "port2", MTU: 9000},
		{ID: "bond", Kind: "bond", OSName: "bond0", Members: []string{"p1", "p2"}, MTU: 9000},
		{ID: "ctl", Kind: "vlan", OSName: "bond0.100", Parent: "bond", VLANID: 100, MTU: 1500},
		{ID: "tun", Kind: "vlan", OSName: "bond0.200", Parent: "bond", VLANID: 200, MTU: 1500},
	}, Networks: []Network{{Name: "control", InterfaceID: "ctl", Prefix: "192.0.2.0/24", VRFID: "7", AllocationGroup: "ctl_ips"}, {Name: "tunnel", InterfaceID: "tun", Prefix: "2001:db8::/64", AllocationGroup: "tun_ips"}}}
}
func TestValidBondAndVLANGraph(t *testing.T) {
	g := exampleGraph()
	if got := Validate(g); len(got) > 0 {
		t.Fatalf("valid graph: %+v", got)
	}
	if len(g.Nodes) != 5 {
		t.Fatal("IPAM VRF must not create a Linux interface")
	}
}
func TestRejectInvalidGraphs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Graph)
		want   string
	}{
		{"duplicate name", func(g *Graph) { g.Nodes[1].OSName = "eno1" }, "duplicate Linux"},
		{"missing member", func(g *Graph) { g.Nodes[2].Members = []string{"missing"} }, "member does not exist"},
		{"wrong member", func(g *Graph) { g.Nodes[2].Members = []string{"ctl"} }, "bond members must be physical"},
		{"cycle", func(g *Graph) { g.Nodes[2].Members = []string{"ctl"} }, "cycle"},
		{"bad vlan", func(g *Graph) { g.Nodes[3].VLANID = 4095 }, "VLAN ID"},
		{"mtu", func(g *Graph) { g.Nodes[3].MTU = 9001 }, "exceeds parent"},
		{"noncanonical prefix", func(g *Graph) { g.Networks[0].Prefix = "192.0.2.1/24" }, "canonical"},
		{"duplicate group", func(g *Graph) { g.Networks[1].AllocationGroup = "ctl_ips" }, "already used"},
		{"unknown kind", func(g *Graph) { g.Nodes[0].Kind = "linux_vrf" }, "unsupported interface kind"},
		{"unscoped VRF", func(g *Graph) { g.NetBoxInstanceID = "" }, "NetBox connection is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := exampleGraph()
			tt.mutate(&g)
			found := false
			for _, issue := range Validate(g) {
				if strings.Contains(issue.Message, tt.want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("missing %q: %+v", tt.want, Validate(g))
			}
		})
	}
}

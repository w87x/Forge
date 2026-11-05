package network

import (
	"errors"
	"strings"
	"testing"
)

func TestAllocationOnlySelectedHosts(t *testing.T) {
	data := []byte("ctl_ips:\n  host1: 192.0.2.1\n  host2: 192.0.2.2\n  host3: [unrelated, malformed]\ntun_ips:\n  host1: 2001:db8::1\n  host2: 2001:db8::2\n  host3: null\n")
	result, err := ParseAllocation(data, []HostBinding{{1, "host1"}, {2, "host2"}}, []string{"ctl_ips", "tun_ips"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assignments) != 4 || result.IgnoredHosts != 1 || result.Assignments[0].DeviceID != 1 || result.Assignments[3].Value != "2001:db8::2" || len(result.Hash) != 64 {
		t.Fatalf("result: %+v", result)
	}
}
func TestAllocationRejectsAmbiguityAndExpressions(t *testing.T) {
	hosts := []HostBinding{{1, "host1"}}
	tests := []struct {
		name, data string
		hosts      []HostBinding
	}{
		{"duplicate", "ctl:\n  host1: 192.0.2.1\n  host1: 192.0.2.2\n", hosts},
		{"missing", "ctl:\n  host2: 192.0.2.1\n", hosts},
		{"selected wrong type", "ctl:\n  host1: [one, two]\n", hosts},
		{"template", "ctl:\n  host1: '{{ inventory_hostname }}'\n", hosts},
		{"yaml alias", "ctl:\n  host1: &ip 192.0.2.1\n  host2: *ip\n", hosts},
		{"multiple documents", "ctl:\n  host1: 192.0.2.1\n---\nother: value\n", hosts},
		{"ambiguous host alias", "ctl:\n  host1: 192.0.2.1\n", []HostBinding{{1, "host1"}, {2, "host1"}}},
		{"oversized", strings.Repeat("x", allocationLimit+1), hosts},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseAllocation([]byte(tc.data), tc.hosts, []string{"ctl"}); !errors.Is(err, ErrAllocation) {
				t.Fatalf("expected invalid import, got %v", err)
			}
		})
	}
}

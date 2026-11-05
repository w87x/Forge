package network

import (
	"fmt"
	"net/netip"
)

type ResolvedAddress struct {
	DeviceID    int64  `json:"device_id"`
	HostKey     string `json:"host_key"`
	Group       string `json:"group"`
	InterfaceID string `json:"interface_id"`
	VRFID       string `json:"vrf_id"`
	Address     string `json:"address"`
	Prefix      string `json:"prefix"`
}

// Resolve validates selected assignments against the intended topology. It
// cannot establish whether addresses conflict with existing NetBox objects;
// that requires a later permission-scoped remote lookup before any mutation.
func Resolve(g Graph, imported AllocationImport) ([]ResolvedAddress, []Issue) {
	if issues := Validate(g); len(issues) > 0 {
		return nil, issues
	}
	byGroup := map[string]Network{}
	for _, n := range g.Networks {
		byGroup[n.AllocationGroup] = n
	}
	out := []ResolvedAddress{}
	issues := []Issue{}
	seen := map[string]int{}
	for i, a := range imported.Assignments {
		field := fmt.Sprintf("assignments[%d]", i)
		network, ok := byGroup[a.Group]
		if !ok {
			issues = append(issues, Issue{field + ".group", "allocation group has no network mapping"})
			continue
		}
		prefix, _ := netip.ParsePrefix(network.Prefix)
		value := a.Value
		var address netip.Addr
		if withMask, err := netip.ParsePrefix(value); err == nil {
			address = withMask.Addr()
			if withMask.Bits() != prefix.Bits() {
				issues = append(issues, Issue{field + ".value", "address mask differs from network prefix"})
				continue
			}
		} else {
			var err error
			address, err = netip.ParseAddr(value)
			if err != nil {
				issues = append(issues, Issue{field + ".value", "value is not an IPv4 or IPv6 address"})
				continue
			}
		}
		if !prefix.Contains(address) {
			issues = append(issues, Issue{field + ".value", "address is outside the network prefix"})
			continue
		}
		key := network.VRFID + "\x00" + address.String()
		if first, exists := seen[key]; exists {
			issues = append(issues, Issue{field + ".value", fmt.Sprintf("address duplicates assignment %d in the same VRF", first)})
			continue
		}
		seen[key] = i
		out = append(out, ResolvedAddress{DeviceID: a.DeviceID, HostKey: a.HostKey, Group: a.Group, InterfaceID: network.InterfaceID, VRFID: network.VRFID, Address: address.String(), Prefix: prefix.String()})
	}
	return out, issues
}

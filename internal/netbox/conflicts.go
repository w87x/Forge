package netbox

import (
	"context"
	"encoding/json"
	"net/netip"
	"net/url"
	"strconv"

	"forge/internal/auth"
)

// ConflictAddress contains only fields needed for collision checking. It does
// not expose unrelated device names or embedded NetBox objects.
type ConflictAddress struct {
	ID           int64
	Address      netip.Addr
	VRFID        *int64
	VRFKnown     bool
	AssignedType string
	AssignedID   *int64
}

// AddressCandidates reads one bounded page for up to 32 selected host IPs.
// Absence never proves uniqueness: visibility and pagination may be limited.
func (s *Service) AddressCandidates(ctx context.Context, actor auth.User, instanceID string, hosts []netip.Addr) ([]ConflictAddress, error) {
	if len(hosts) == 0 || len(hosts) > 32 {
		return nil, ErrInvalid
	}
	wanted := map[netip.Addr]bool{}
	q := url.Values{"limit": {strconv.Itoa(DevicePageSize)}, "offset": {"0"}}
	for _, host := range hosts {
		if !host.IsValid() || host.Zone() != "" || host.Is4In6() || wanted[host] {
			return nil, ErrInvalid
		}
		wanted[host] = true
		bits := 128
		if host.Is4() {
			bits = 32
		}
		q.Add("parent", netip.PrefixFrom(host, bits).String())
	}
	body, _, _, err := s.get(ctx, actor, instanceID, "/api/ipam/ip-addresses/", q)
	if err != nil {
		return nil, err
	}
	var page struct {
		Count   *int `json:"count"`
		Results *[]struct {
			ID           int64           `json:"id"`
			Address      string          `json:"address"`
			VRF          json.RawMessage `json:"vrf"`
			AssignedType string          `json:"assigned_object_type"`
			AssignedID   *int64          `json:"assigned_object_id"`
		} `json:"results"`
	}
	if json.Unmarshal(body, &page) != nil || page.Count == nil || *page.Count < 0 || page.Results == nil || len(*page.Results) > DevicePageSize || len(*page.Results) > *page.Count {
		return nil, ErrRemote
	}
	seen := map[int64]bool{}
	out := make([]ConflictAddress, 0, len(*page.Results))
	for _, v := range *page.Results {
		prefix, err := netip.ParsePrefix(v.Address)
		if err != nil || !wanted[prefix.Addr()] || v.ID <= 0 || seen[v.ID] || (v.AssignedID != nil && *v.AssignedID <= 0) {
			return nil, ErrRemote
		}
		seen[v.ID] = true
		vrf, known, err := rawRef(v.VRF)
		if err != nil {
			return nil, err
		}
		out = append(out, ConflictAddress{ID: v.ID, Address: prefix.Addr(), VRFID: vrf, VRFKnown: known, AssignedType: v.AssignedType, AssignedID: v.AssignedID})
	}
	return out, nil
}

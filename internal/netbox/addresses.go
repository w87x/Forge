package netbox

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"forge/internal/auth"
)

type IPAddress struct {
	ID            int64  `json:"id"`
	Address       string `json:"address"`
	Status        string `json:"status"`
	VRFID         *int64 `json:"vrf_id"`
	VRFKnown      bool   `json:"vrf_known"`
	VRFName       string `json:"vrf_name"`
	InterfaceID   int64  `json:"interface_id"`
	InterfaceName string `json:"interface_name"`
}
type IPAddressPage struct {
	Results []IPAddress `json:"results"`
	Count   int         `json:"count"`
	Offset  int         `json:"offset"`
	HasMore bool        `json:"has_more"`
}

// Addresses reads one page and rejects objects whose embedded assignment does
// not prove they belong to the selected device, even if a server ignores the filter.
func (s *Service) Addresses(ctx context.Context, actor auth.User, instanceID string, deviceID int64, offset int) (IPAddressPage, error) {
	if deviceID <= 0 || offset < 0 || offset > 1000000 {
		return IPAddressPage{}, ErrInvalid
	}
	q := url.Values{"device_id": {strconv.FormatInt(deviceID, 10)}, "limit": {strconv.Itoa(DevicePageSize)}, "offset": {strconv.Itoa(offset)}}
	body, _, instance, err := s.get(ctx, actor, instanceID, "/api/ipam/ip-addresses/", q)
	if err != nil {
		return IPAddressPage{}, err
	}
	var page struct {
		Count   *int    `json:"count"`
		Next    *string `json:"next"`
		Results *[]struct {
			ID      int64  `json:"id"`
			Address string `json:"address"`
			Status  *struct {
				Value string `json:"value"`
			} `json:"status"`
			VRF          json.RawMessage `json:"vrf"`
			AssignedType string          `json:"assigned_object_type"`
			AssignedID   *int64          `json:"assigned_object_id"`
			Assigned     *struct {
				ID     int64  `json:"id"`
				Name   string `json:"name"`
				Device *refID `json:"device"`
			} `json:"assigned_object"`
		} `json:"results"`
	}
	if json.Unmarshal(body, &page) != nil || page.Count == nil || page.Results == nil || *page.Count < 0 || len(*page.Results) > DevicePageSize {
		return IPAddressPage{}, ErrRemote
	}
	if page.Next != nil && *page.Next != "" {
		base, err := url.Parse(instance.BaseURL)
		if err != nil {
			return IPAddressPage{}, ErrRemote
		}
		next, err := url.Parse(*page.Next)
		if err != nil {
			return IPAddressPage{}, ErrRemote
		}
		next = base.ResolveReference(next)
		query := next.Query()
		if next.User != nil || next.Fragment != "" || !strings.EqualFold(next.Scheme, base.Scheme) || !strings.EqualFold(next.Host, base.Host) || next.Path != strings.TrimRight(base.Path, "/")+"/api/ipam/ip-addresses/" || len(query["device_id"]) != 1 || query.Get("device_id") != strconv.FormatInt(deviceID, 10) || len(*page.Results) == 0 || len(query["offset"]) != 1 || query.Get("offset") != strconv.Itoa(offset+len(*page.Results)) {
			return IPAddressPage{}, ErrRemote
		}
	}
	out := IPAddressPage{Results: []IPAddress{}, Count: *page.Count, Offset: offset, HasMore: page.Next != nil && *page.Next != ""}
	seen := map[int64]bool{}
	for _, v := range *page.Results {
		prefix, err := netip.ParsePrefix(v.Address)
		if err != nil || v.ID <= 0 || seen[v.ID] || v.AssignedType != "dcim.interface" || v.AssignedID == nil || *v.AssignedID <= 0 || v.Assigned == nil || v.Assigned.ID != *v.AssignedID || v.Assigned.Device == nil || v.Assigned.Device.ID != deviceID {
			return IPAddressPage{}, ErrRemote
		}
		seen[v.ID] = true
		item := IPAddress{ID: v.ID, Address: prefix.String(), InterfaceID: *v.AssignedID, InterfaceName: v.Assigned.Name}
		if v.Status != nil {
			item.Status = v.Status.Value
		}
		if len(v.VRF) > 0 {
			item.VRFKnown = true
		}
		if len(v.VRF) > 0 && !bytes.Equal(bytes.TrimSpace(v.VRF), []byte("null")) {
			var vrf struct {
				ID   int64  `json:"id"`
				Name string `json:"name"`
			}
			if json.Unmarshal(v.VRF, &vrf) != nil || vrf.ID <= 0 {
				return IPAddressPage{}, ErrRemote
			}
			id := vrf.ID
			item.VRFID = &id
			item.VRFName = vrf.Name
		}
		out.Results = append(out.Results, item)
	}
	return out, nil
}

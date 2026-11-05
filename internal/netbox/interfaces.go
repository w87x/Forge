package netbox

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"forge/internal/auth"
)

type Interface struct {
	ID                int64   `json:"id"`
	Name              string  `json:"name"`
	DeviceID          int64   `json:"device_id"`
	Type              string  `json:"type"`
	Enabled           *bool   `json:"enabled"`
	MTU               *int    `json:"mtu"`
	MTUKnown          bool    `json:"mtu_known"`
	MAC               string  `json:"mac"`
	Mode              string  `json:"mode"`
	ParentID          *int64  `json:"parent_id"`
	ParentKnown       bool    `json:"parent_known"`
	LAGID             *int64  `json:"lag_id"`
	LAGKnown          bool    `json:"lag_known"`
	BridgeID          *int64  `json:"bridge_id"`
	BridgeKnown       bool    `json:"bridge_known"`
	UntaggedVLANID    *int64  `json:"untagged_vlan_id"`
	UntaggedVLANKnown bool    `json:"untagged_vlan_known"`
	TaggedVLANIDs     []int64 `json:"tagged_vlan_ids"`
	TaggedVLANsKnown  bool    `json:"tagged_vlans_known"`
	CableID           *int64  `json:"cable_id"`
	CableKnown        bool    `json:"cable_known"`
	MarkConnected     *bool   `json:"mark_connected"`
	CableState        string  `json:"cable_state"`
}
type InterfacePage struct {
	Results []Interface `json:"results"`
	Count   int         `json:"count"`
	Offset  int         `json:"offset"`
	HasMore bool        `json:"has_more"`
}
type refID struct {
	ID int64 `json:"id"`
}

func rawRef(raw json.RawMessage) (*int64, bool, error) {
	if len(raw) == 0 {
		return nil, false, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, true, nil
	}
	var ref refID
	if json.Unmarshal(raw, &ref) != nil || ref.ID <= 0 {
		return nil, false, ErrRemote
	}
	return &ref.ID, true, nil
}

// Interfaces fetches one bounded page for a single explicitly selected device.
func (s *Service) Interfaces(ctx context.Context, actor auth.User, instanceID string, deviceID int64, offset int) (InterfacePage, error) {
	if deviceID <= 0 || offset < 0 || offset > 1000000 {
		return InterfacePage{}, ErrInvalid
	}
	q := url.Values{"device_id": {strconv.FormatInt(deviceID, 10)}, "limit": {strconv.Itoa(DevicePageSize)}, "offset": {strconv.Itoa(offset)}}
	body, _, instance, err := s.get(ctx, actor, instanceID, "/api/dcim/interfaces/", q)
	if err != nil {
		return InterfacePage{}, err
	}
	var page struct {
		Count   *int    `json:"count"`
		Next    *string `json:"next"`
		Results *[]struct {
			ID     int64  `json:"id"`
			Name   string `json:"name"`
			Device *refID `json:"device"`
			Type   struct {
				Value string `json:"value"`
			} `json:"type"`
			Enabled    *bool           `json:"enabled"`
			MTU        json.RawMessage `json:"mtu"`
			MAC        string          `json:"mac_address"`
			PrimaryMAC *struct {
				Address string `json:"mac_address"`
			} `json:"primary_mac_address"`
			Mode *struct {
				Value string `json:"value"`
			} `json:"mode"`
			Parent        json.RawMessage `json:"parent"`
			LAG           json.RawMessage `json:"lag"`
			Bridge        json.RawMessage `json:"bridge"`
			Untagged      json.RawMessage `json:"untagged_vlan"`
			Tagged        json.RawMessage `json:"tagged_vlans"`
			Cable         json.RawMessage `json:"cable"`
			MarkConnected *bool           `json:"mark_connected"`
		} `json:"results"`
	}
	if json.Unmarshal(body, &page) != nil || page.Count == nil || page.Results == nil || *page.Count < 0 || len(*page.Results) > DevicePageSize {
		return InterfacePage{}, ErrRemote
	}
	if page.Next != nil && *page.Next != "" {
		base, err := url.Parse(instance.BaseURL)
		if err != nil {
			return InterfacePage{}, ErrRemote
		}
		next, err := url.Parse(*page.Next)
		if err != nil {
			return InterfacePage{}, ErrRemote
		}
		next = base.ResolveReference(next)
		if next.User != nil || next.Fragment != "" || !strings.EqualFold(next.Scheme, base.Scheme) || !strings.EqualFold(next.Host, base.Host) || next.Path != strings.TrimRight(base.Path, "/")+"/api/dcim/interfaces/" || len(next.Query()["device_id"]) != 1 || next.Query().Get("device_id") != strconv.FormatInt(deviceID, 10) || len(*page.Results) == 0 || len(next.Query()["offset"]) != 1 || next.Query().Get("offset") != strconv.Itoa(offset+len(*page.Results)) {
			return InterfacePage{}, ErrRemote
		}
	}
	out := InterfacePage{Results: []Interface{}, Count: *page.Count, Offset: offset, HasMore: page.Next != nil && *page.Next != ""}
	seen := map[int64]bool{}
	for _, v := range *page.Results {
		if v.ID <= 0 || v.Device == nil || v.Device.ID != deviceID || seen[v.ID] {
			return InterfacePage{}, ErrRemote
		}
		seen[v.ID] = true
		parent, parentKnown, err := rawRef(v.Parent)
		if err != nil {
			return InterfacePage{}, err
		}
		lag, lagKnown, err := rawRef(v.LAG)
		if err != nil {
			return InterfacePage{}, err
		}
		bridge, bridgeKnown, err := rawRef(v.Bridge)
		if err != nil {
			return InterfacePage{}, err
		}
		untagged, untaggedKnown, err := rawRef(v.Untagged)
		if err != nil {
			return InterfacePage{}, err
		}
		cable, cableKnown, err := rawRef(v.Cable)
		if err != nil {
			return InterfacePage{}, err
		}
		var mtu *int
		if len(v.MTU) > 0 && !bytes.Equal(bytes.TrimSpace(v.MTU), []byte("null")) {
			var value int
			if json.Unmarshal(v.MTU, &value) != nil || value < 0 {
				return InterfacePage{}, ErrRemote
			}
			mtu = &value
		}
		item := Interface{ID: v.ID, Name: v.Name, DeviceID: deviceID, Type: v.Type.Value, Enabled: v.Enabled, MTU: mtu, MTUKnown: len(v.MTU) > 0, MAC: v.MAC, ParentID: parent, ParentKnown: parentKnown, LAGID: lag, LAGKnown: lagKnown, BridgeID: bridge, BridgeKnown: bridgeKnown, UntaggedVLANID: untagged, UntaggedVLANKnown: untaggedKnown, CableID: cable, CableKnown: cableKnown, MarkConnected: v.MarkConnected, CableState: cableState(cable, cableKnown, v.MarkConnected), TaggedVLANIDs: []int64{}}
		if item.MAC == "" && v.PrimaryMAC != nil {
			item.MAC = v.PrimaryMAC.Address
		}
		if v.Mode != nil {
			item.Mode = v.Mode.Value
		}
		var tags []refID
		if len(v.Tagged) > 0 && !bytes.Equal(bytes.TrimSpace(v.Tagged), []byte("null")) {
			if json.Unmarshal(v.Tagged, &tags) != nil {
				return InterfacePage{}, ErrRemote
			}
			item.TaggedVLANsKnown = true
		}
		seenTags := map[int64]bool{}
		for _, tag := range tags {
			if tag.ID <= 0 || seenTags[tag.ID] {
				return InterfacePage{}, ErrRemote
			}
			seenTags[tag.ID] = true
			item.TaggedVLANIDs = append(item.TaggedVLANIDs, tag.ID)
		}
		out.Results = append(out.Results, item)
	}
	return out, nil
}

// cableState describes direct NetBox cable indicators, not eligibility or link state.
func cableState(cable *int64, cableKnown bool, marked *bool) string {
	if cable != nil || (marked != nil && *marked) {
		return "occupied"
	}
	if cableKnown && marked != nil && !*marked {
		return "unconnected"
	}
	return "unknown"
}

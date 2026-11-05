package netbox

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"forge/internal/auth"
)

const DevicePageSize = 50

type DeviceFilter struct {
	Query  string `json:"query"`
	SiteID int64  `json:"site_id"`
	RoleID int64  `json:"role_id"`
	Status string `json:"status"`
	Offset int    `json:"offset"`
}
type Device struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Serial       string `json:"serial"`
	Site         string `json:"site"`
	SiteID       int64  `json:"site_id"`
	Rack         string `json:"rack"`
	RackID       int64  `json:"rack_id"`
	Role         string `json:"role"`
	Model        string `json:"model"`
	Manufacturer string `json:"manufacturer"`
	Status       string `json:"status"`
}
type DevicePage struct {
	Results []Device `json:"results"`
	Count   int      `json:"count"`
	Offset  int      `json:"offset"`
	HasMore bool     `json:"has_more"`
}
type nestedName struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}
type netboxDevice struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	Serial     string     `json:"serial"`
	Site       nestedName `json:"site"`
	Rack       nestedName `json:"rack"`
	Role       nestedName `json:"role"`
	DeviceRole nestedName `json:"device_role"`
	DeviceType struct {
		Model        string     `json:"model"`
		Manufacturer nestedName `json:"manufacturer"`
	} `json:"device_type"`
	Status struct {
		Value string `json:"value"`
	} `json:"status"`
}

// DeviceVisible checks the current user's NetBox permission without exposing
// a cached device merely because it was visible in an older snapshot.
func (s *Service) DeviceVisible(ctx context.Context, actor auth.User, instanceID string, deviceID int64) error {
	if deviceID <= 0 {
		return ErrInvalid
	}
	body, _, _, err := s.get(ctx, actor, instanceID, "/api/dcim/devices/"+strconv.FormatInt(deviceID, 10)+"/", nil)
	if err != nil {
		return err
	}
	var device struct {
		ID int64 `json:"id"`
	}
	if json.Unmarshal(body, &device) != nil || device.ID != deviceID {
		return ErrRemote
	}
	return nil
}

func (s *Service) Devices(ctx context.Context, actor auth.User, instanceID string, filter DeviceFilter) (DevicePage, error) {
	if len(filter.Query) > 128 || len(filter.Status) > 64 || filter.Offset < 0 || filter.Offset > 1000000 || filter.SiteID < 0 || filter.RoleID < 0 {
		return DevicePage{}, ErrInvalid
	}
	q := url.Values{"limit": {strconv.Itoa(DevicePageSize)}, "offset": {strconv.Itoa(filter.Offset)}}
	if filter.Query != "" {
		q.Set("q", filter.Query)
	}
	if filter.SiteID != 0 {
		q.Set("site_id", strconv.FormatInt(filter.SiteID, 10))
	}
	if filter.RoleID != 0 {
		q.Set("role_id", strconv.FormatInt(filter.RoleID, 10))
	}
	if filter.Status != "" {
		q.Set("status", filter.Status)
	}
	body, _, instance, err := s.get(ctx, actor, instanceID, "/api/dcim/devices/", q)
	if err != nil {
		return DevicePage{}, err
	}
	var page struct {
		Count   *int            `json:"count"`
		Next    *string         `json:"next"`
		Results *[]netboxDevice `json:"results"`
	}
	if json.Unmarshal(body, &page) != nil || page.Count == nil || page.Results == nil || *page.Count < 0 || len(*page.Results) > DevicePageSize {
		return DevicePage{}, ErrRemote
	}
	if page.Next != nil && *page.Next != "" {
		base, err := url.Parse(instance.BaseURL)
		if err != nil {
			return DevicePage{}, ErrRemote
		}
		next, err := url.Parse(*page.Next)
		if err != nil {
			return DevicePage{}, ErrRemote
		}
		next = base.ResolveReference(next)
		if next.User != nil || next.Fragment != "" || !strings.EqualFold(next.Scheme, base.Scheme) || !strings.EqualFold(next.Host, base.Host) || next.Path != strings.TrimRight(base.Path, "/")+"/api/dcim/devices/" {
			return DevicePage{}, ErrRemote
		}
	}
	result := DevicePage{Results: make([]Device, 0, len(*page.Results)), Count: *page.Count, Offset: filter.Offset, HasMore: page.Next != nil && *page.Next != ""}
	seen := make(map[int64]bool)
	for _, d := range *page.Results {
		if d.ID <= 0 || seen[d.ID] {
			return DevicePage{}, ErrRemote
		}
		seen[d.ID] = true
		role := d.Role.Name
		if role == "" {
			role = d.DeviceRole.Name
		}
		if d.Site.ID < 0 || d.Rack.ID < 0 {
			return DevicePage{}, ErrRemote
		}
		result.Results = append(result.Results, Device{ID: d.ID, Name: d.Name, Serial: d.Serial, Site: d.Site.Name, SiteID: d.Site.ID, Rack: d.Rack.Name, RackID: d.Rack.ID, Role: role, Model: d.DeviceType.Model, Manufacturer: d.DeviceType.Manufacturer.Name, Status: d.Status.Value})
	}
	return result, nil
}

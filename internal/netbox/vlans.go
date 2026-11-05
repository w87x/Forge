package netbox

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"forge/internal/auth"
)

type VLAN struct {
	ID    int64  `json:"id"`
	VID   int    `json:"vid"`
	Name  string `json:"name"`
	Scope string `json:"scope"`
}
type VLANPage struct {
	Results []VLAN `json:"results"`
	Count   int    `json:"count"`
	Offset  int    `json:"offset"`
	HasMore bool   `json:"has_more"`
}

func (s *Service) VLANs(ctx context.Context, actor auth.User, instanceID, search string, offset int) (VLANPage, error) {
	if len(search) > 128 || offset < 0 || offset > 1000000 {
		return VLANPage{}, ErrInvalid
	}
	q := url.Values{"limit": {strconv.Itoa(DevicePageSize)}, "offset": {strconv.Itoa(offset)}}
	if search != "" {
		q.Set("q", search)
	}
	return s.vlanPage(ctx, actor, instanceID, q, offset, nil)
}

// VLANsByID uses a bounded batch and accepts only the requested IDs. Missing
// objects remain unknown because NetBox may hide them from this user.
func (s *Service) VLANsByID(ctx context.Context, actor auth.User, instanceID string, ids []int64) (VLANPage, error) {
	if len(ids) == 0 || len(ids) > DevicePageSize {
		return VLANPage{}, ErrInvalid
	}
	wanted := map[int64]bool{}
	q := url.Values{"limit": {strconv.Itoa(DevicePageSize)}, "offset": {"0"}}
	for _, id := range ids {
		if id <= 0 || wanted[id] {
			return VLANPage{}, ErrInvalid
		}
		wanted[id] = true
		q.Add("id", strconv.FormatInt(id, 10))
	}
	return s.vlanPage(ctx, actor, instanceID, q, 0, wanted)
}

// AuditVLANs resolves a profile's distinct VLAN references in bounded batches.
// Missing or hidden IDs are not treated as absent: callers retain unknown
// coverage for IDs that did not appear in the returned evidence.
func (s *Service) AuditVLANs(ctx context.Context, actor auth.User, instanceID string, ids []int64) ([]VLAN, error) {
	if len(ids) == 0 || len(ids) > 256 {
		return nil, ErrInvalid
	}
	seen := make(map[int64]bool, len(ids))
	for _, id := range ids {
		if id <= 0 || seen[id] {
			return nil, ErrInvalid
		}
		seen[id] = true
	}
	results := make([]VLAN, 0, len(ids))
	for start := 0; start < len(ids); start += DevicePageSize {
		end := min(start+DevicePageSize, len(ids))
		batch := ids[start:end]
		page, err := WaitForLocalBudget(ctx, func() (VLANPage, error) {
			return s.VLANsByID(ctx, actor, instanceID, batch)
		})
		if err != nil {
			return nil, err
		}
		results = append(results, page.Results...)
	}
	return results, nil
}
func (s *Service) vlanPage(ctx context.Context, actor auth.User, instanceID string, q url.Values, offset int, wanted map[int64]bool) (VLANPage, error) {
	body, _, instance, err := s.get(ctx, actor, instanceID, "/api/ipam/vlans/", q)
	if err != nil {
		return VLANPage{}, err
	}
	var page struct {
		Count   *int    `json:"count"`
		Next    *string `json:"next"`
		Results *[]struct {
			ID   int64  `json:"id"`
			VID  int    `json:"vid"`
			Name string `json:"name"`
			Site *struct {
				Name string `json:"name"`
			} `json:"site"`
			Scope *struct {
				Name    string `json:"name"`
				Display string `json:"display"`
			} `json:"scope"`
		} `json:"results"`
	}
	if json.Unmarshal(body, &page) != nil || page.Count == nil || page.Results == nil || *page.Count < 0 || len(*page.Results) > DevicePageSize {
		return VLANPage{}, ErrRemote
	}
	if page.Next != nil && *page.Next != "" {
		base, err := url.Parse(instance.BaseURL)
		if err != nil {
			return VLANPage{}, ErrRemote
		}
		next, err := url.Parse(*page.Next)
		if err != nil {
			return VLANPage{}, ErrRemote
		}
		next = base.ResolveReference(next)
		nq := next.Query()
		if next.User != nil || next.Fragment != "" || !strings.EqualFold(next.Scheme, base.Scheme) || !strings.EqualFold(next.Host, base.Host) || next.Path != strings.TrimRight(base.Path, "/")+"/api/ipam/vlans/" || len(*page.Results) == 0 || len(nq["offset"]) != 1 || nq.Get("offset") != strconv.Itoa(offset+len(*page.Results)) || nq.Get("q") != q.Get("q") {
			return VLANPage{}, ErrRemote
		}
	}
	out := VLANPage{Results: []VLAN{}, Count: *page.Count, Offset: offset, HasMore: page.Next != nil && *page.Next != ""}
	seen := map[int64]bool{}
	for _, v := range *page.Results {
		if v.ID <= 0 || v.VID < 1 || v.VID > 4094 || seen[v.ID] || (wanted != nil && !wanted[v.ID]) {
			return VLANPage{}, ErrRemote
		}
		seen[v.ID] = true
		item := VLAN{ID: v.ID, VID: v.VID, Name: v.Name}
		if v.Site != nil {
			item.Scope = v.Site.Name
		}
		if v.Scope != nil {
			if v.Scope.Display != "" {
				item.Scope = v.Scope.Display
			} else if v.Scope.Name != "" {
				item.Scope = v.Scope.Name
			}
		}
		out.Results = append(out.Results, item)
	}
	return out, nil
}

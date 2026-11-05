package netbox

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"forge/internal/auth"
)

type VRF struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	RD   string `json:"rd"`
}
type VRFPage struct {
	Results []VRF `json:"results"`
	Count   int   `json:"count"`
	Offset  int   `json:"offset"`
	HasMore bool  `json:"has_more"`
}

// VRFs lists one page visible to the current user's NetBox key. A null VRF is
// represented separately by the caller as the global routing table.
func (s *Service) VRFs(ctx context.Context, actor auth.User, instanceID string, offset int) (VRFPage, error) {
	if offset < 0 || offset > 1000000 {
		return VRFPage{}, ErrInvalid
	}
	q := url.Values{"limit": {strconv.Itoa(DevicePageSize)}, "offset": {strconv.Itoa(offset)}}
	body, _, instance, err := s.get(ctx, actor, instanceID, "/api/ipam/vrfs/", q)
	if err != nil {
		return VRFPage{}, err
	}
	var page struct {
		Count   *int    `json:"count"`
		Next    *string `json:"next"`
		Results *[]struct {
			ID   int64   `json:"id"`
			Name string  `json:"name"`
			RD   *string `json:"rd"`
		} `json:"results"`
	}
	if json.Unmarshal(body, &page) != nil || page.Count == nil || page.Results == nil || *page.Count < 0 || len(*page.Results) > DevicePageSize {
		return VRFPage{}, ErrRemote
	}
	if page.Next != nil && *page.Next != "" {
		base, err := url.Parse(instance.BaseURL)
		if err != nil {
			return VRFPage{}, ErrRemote
		}
		next, err := url.Parse(*page.Next)
		if err != nil {
			return VRFPage{}, ErrRemote
		}
		next = base.ResolveReference(next)
		query := next.Query()
		if next.User != nil || next.Fragment != "" || !strings.EqualFold(next.Scheme, base.Scheme) || !strings.EqualFold(next.Host, base.Host) || next.Path != strings.TrimRight(base.Path, "/")+"/api/ipam/vrfs/" || len(*page.Results) == 0 || len(query["offset"]) != 1 || query.Get("offset") != strconv.Itoa(offset+len(*page.Results)) {
			return VRFPage{}, ErrRemote
		}
	}
	out := VRFPage{Results: []VRF{}, Count: *page.Count, Offset: offset, HasMore: page.Next != nil && *page.Next != ""}
	seen := map[int64]bool{}
	for _, v := range *page.Results {
		if v.ID <= 0 || seen[v.ID] {
			return VRFPage{}, ErrRemote
		}
		seen[v.ID] = true
		item := VRF{ID: v.ID, Name: v.Name}
		if v.RD != nil {
			item.RD = *v.RD
		}
		out.Results = append(out.Results, item)
	}
	return out, nil
}

package inventory

import (
	"context"
	"forge/internal/auth"
	"forge/internal/netbox"
)

// Audit evidence is bounded to four pages per object type. The result retains
// HasMore when the bound is reached; it does not claim a complete snapshot.
const auditPageLimit = 4

func (s *Service) AuditInterfaces(ctx context.Context, actor auth.User, selectionID string, deviceID int64) (netbox.InterfacePage, error) {
	result := netbox.InterfacePage{Results: []netbox.Interface{}}
	seen := map[int64]bool{}
	for pageNo := 0; pageNo < auditPageLimit; pageNo++ {
		page, err := netbox.WaitForLocalBudget(ctx, func() (netbox.InterfacePage, error) {
			return s.Interfaces(ctx, actor, selectionID, deviceID, len(result.Results))
		})
		if err != nil {
			return netbox.InterfacePage{}, err
		}
		if pageNo == 0 {
			result.Count = page.Count
		} else if page.Count != result.Count {
			return netbox.InterfacePage{}, netbox.ErrRemote
		}
		for _, item := range page.Results {
			if seen[item.ID] {
				return netbox.InterfacePage{}, netbox.ErrRemote
			}
			seen[item.ID] = true
			result.Results = append(result.Results, item)
		}
		if len(result.Results) > result.Count || (!page.HasMore && len(result.Results) != result.Count) || (page.HasMore && len(result.Results) >= result.Count) {
			return netbox.InterfacePage{}, netbox.ErrRemote
		}
		result.HasMore = page.HasMore
		if !page.HasMore {
			break
		}
	}
	return result, nil
}

func (s *Service) AuditAddresses(ctx context.Context, actor auth.User, selectionID string, deviceID int64) (netbox.IPAddressPage, error) {
	result := netbox.IPAddressPage{Results: []netbox.IPAddress{}}
	seen := map[int64]bool{}
	for pageNo := 0; pageNo < auditPageLimit; pageNo++ {
		page, err := netbox.WaitForLocalBudget(ctx, func() (netbox.IPAddressPage, error) {
			return s.Addresses(ctx, actor, selectionID, deviceID, len(result.Results))
		})
		if err != nil {
			return netbox.IPAddressPage{}, err
		}
		if pageNo == 0 {
			result.Count = page.Count
		} else if page.Count != result.Count {
			return netbox.IPAddressPage{}, netbox.ErrRemote
		}
		for _, item := range page.Results {
			if seen[item.ID] {
				return netbox.IPAddressPage{}, netbox.ErrRemote
			}
			seen[item.ID] = true
			result.Results = append(result.Results, item)
		}
		if len(result.Results) > result.Count || (!page.HasMore && len(result.Results) != result.Count) || (page.HasMore && len(result.Results) >= result.Count) {
			return netbox.IPAddressPage{}, netbox.ErrRemote
		}
		result.HasMore = page.HasMore
		if !page.HasMore {
			break
		}
	}
	return result, nil
}

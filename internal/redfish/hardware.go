package redfish

// Ethernet is an observed Redfish EthernetInterface, which may represent a
// logical interface or a controller; it is not assumed to be a physical port.
type Ethernet struct {
	Path         string `json:"path"`
	ID           string `json:"id"`
	Name         string `json:"name"`
	MAC          string `json:"mac"`
	PermanentMAC string `json:"permanent_mac"`
	SpeedMbps    *int   `json:"speed_mbps"`
	LinkStatus   string `json:"link_status"`
	Kind         string `json:"kind"`
	Health       string `json:"health"`
	State        string `json:"state"`
}
type Drive struct {
	Path          string `json:"path"`
	ID            string `json:"id"`
	Manufacturer  string `json:"manufacturer"`
	Model         string `json:"model"`
	Serial        string `json:"serial"`
	CapacityBytes *int64 `json:"capacity_bytes"`
	Protocol      string `json:"protocol"`
	MediaType     string `json:"media_type"`
	Revision      string `json:"revision"`
	Health        string `json:"health"`
	State         string `json:"state"`
}

// StorageVolume is reported logical-volume evidence, not a complete RAID
// configuration or proof that the listed drives are physically present.
type StorageVolume struct {
	Path          string   `json:"path"`
	StoragePath   string   `json:"storage_path"`
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	RAIDType      string   `json:"raid_type"`
	CapacityBytes *int64   `json:"capacity_bytes"`
	Health        string   `json:"health"`
	State         string   `json:"state"`
	DrivePaths    []string `json:"drive_paths"`
}
type collection struct {
	Members *[]link `json:"Members"`
	Next    string  `json:"Members@odata.nextLink"`
}

// Collection scope is not enough to establish complete physical hardware
// coverage. Even a successful collection is labeled partial until additional
// chassis, adapter, controller and vendor-specific paths are supported.
func collectionMembers(get func(string, any) error, getPage func(string, string, any) error, path string, limit int) ([]link, bool) {
	var c collection
	if path == "" || get(path, &c) != nil || c.Members == nil {
		return nil, false
	}
	items := append([]link(nil), (*c.Members)...)
	visited := map[string]bool{}
	for page := 1; c.Next != "" && page < 4 && len(items) < limit; page++ {
		if visited[c.Next] {
			break
		}
		visited[c.Next] = true
		var next collection
		if getPage(path, c.Next, &next) != nil || next.Members == nil {
			break
		}
		items = append(items, (*next.Members)...)
		c = next
	}
	if len(items) > limit {
		items = items[:limit]
	}
	return items, true
}

func collectInterfaces(get func(string, any) error, getPage func(string, string, any) error, path string) ([]Ethernet, string) {
	if path == "" {
		return nil, "unknown"
	}
	members, ok := collectionMembers(get, getPage, path, 64)
	if !ok {
		return nil, "unknown"
	}
	items := []Ethernet{}
	seen := map[string]bool{}
	for i, ref := range members {
		if i >= 64 {
			break
		}
		if ref.ID == "" || seen[ref.ID] {
			continue
		}
		seen[ref.ID] = true
		var v struct {
			ID           string `json:"Id"`
			Name         string `json:"Name"`
			MAC          string `json:"MACAddress"`
			PermanentMAC string `json:"PermanentMACAddress"`
			SpeedMbps    *int   `json:"SpeedMbps"`
			LinkStatus   string `json:"LinkStatus"`
			Status       struct {
				Health string `json:"Health"`
				State  string `json:"State"`
			} `json:"Status"`
		}
		if get(ref.ID, &v) != nil {
			continue
		}
		if v.SpeedMbps != nil && *v.SpeedMbps < 0 {
			v.SpeedMbps = nil
		}
		items = append(items, Ethernet{Path: ref.ID, ID: v.ID, Name: v.Name, MAC: v.MAC, PermanentMAC: v.PermanentMAC, SpeedMbps: v.SpeedMbps, LinkStatus: v.LinkStatus, Kind: "unknown", Health: v.Status.Health, State: v.Status.State})
	}
	return items, "partial"
}
func collectDrives(get func(string, any) error, getPage func(string, string, any) error, path string) ([]Drive, string, []StorageVolume, string) {
	if path == "" {
		return nil, "unknown", nil, "unknown"
	}
	members, ok := collectionMembers(get, getPage, path, 32)
	if !ok {
		return nil, "unknown", nil, "unknown"
	}
	items := []Drive{}
	seenStorage := map[string]bool{}
	seenDrive := map[string]bool{}
	volumes := []StorageVolume{}
	volumeCoverage := "unknown"
	seenVolumes := map[string]bool{}
	volumeCollections := 0
	for i, ref := range members {
		if i >= 32 {
			break
		}
		if ref.ID == "" || seenStorage[ref.ID] {
			continue
		}
		seenStorage[ref.ID] = true
		var storage struct {
			Drives  []link `json:"Drives"`
			Volumes link   `json:"Volumes"`
		}
		if get(ref.ID, &storage) != nil {
			continue
		}
		if storage.Volumes.ID != "" && volumeCollections < 8 && len(seenVolumes) < 64 {
			volumeCollections++
			refs, available := collectionMembers(get, getPage, storage.Volumes.ID, 64-len(seenVolumes))
			if available {
				volumeCoverage = "partial"
			}
			for _, item := range refs {
				if item.ID == "" || seenVolumes[item.ID] || len(seenVolumes) >= 64 {
					continue
				}
				seenVolumes[item.ID] = true
				var v struct {
					ID       string `json:"Id"`
					Name     string `json:"Name"`
					RAIDType string `json:"RAIDType"`
					Capacity *int64 `json:"CapacityBytes"`
					Status   struct {
						Health string `json:"Health"`
						State  string `json:"State"`
					} `json:"Status"`
					Links struct {
						Drives []link `json:"Drives"`
					} `json:"Links"`
				}
				if get(item.ID, &v) != nil {
					continue
				}
				if v.Capacity != nil && *v.Capacity < 0 {
					v.Capacity = nil
				}
				drives := []string{}
				seen := map[string]bool{}
				for _, drive := range v.Links.Drives {
					if len(drives) >= 128 {
						break
					}
					if drive.ID != "" && !seen[drive.ID] {
						seen[drive.ID] = true
						drives = append(drives, drive.ID)
					}
				}
				volumes = append(volumes, StorageVolume{Path: item.ID, StoragePath: ref.ID, ID: v.ID, Name: v.Name, RAIDType: v.RAIDType, CapacityBytes: v.Capacity, Health: v.Status.Health, State: v.Status.State, DrivePaths: drives})
			}
		}
		for _, d := range storage.Drives {
			if len(seenDrive) >= 128 {
				break
			}
			if d.ID == "" || seenDrive[d.ID] {
				continue
			}
			seenDrive[d.ID] = true
			var drive struct {
				ID           string `json:"Id"`
				Manufacturer string `json:"Manufacturer"`
				Model        string `json:"Model"`
				Serial       string `json:"SerialNumber"`
				Capacity     *int64 `json:"CapacityBytes"`
				Protocol     string `json:"Protocol"`
				Media        string `json:"MediaType"`
				Revision     string `json:"Revision"`
				Status       struct {
					Health string `json:"Health"`
					State  string `json:"State"`
				} `json:"Status"`
			}
			if get(d.ID, &drive) != nil {
				continue
			}
			if drive.Capacity != nil && *drive.Capacity < 0 {
				drive.Capacity = nil
			}
			items = append(items, Drive{Path: d.ID, ID: drive.ID, Manufacturer: drive.Manufacturer, Model: drive.Model, Serial: drive.Serial, CapacityBytes: drive.Capacity, Protocol: drive.Protocol, MediaType: drive.Media, Revision: drive.Revision, Health: drive.Status.Health, State: drive.Status.State})
		}
	}
	return items, "partial", volumes, volumeCoverage
}

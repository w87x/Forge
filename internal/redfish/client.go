// Package redfish implements a narrow, read-only Redfish inspection adapter.
package redfish

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrNotAllowed = errors.New("BMC address is not in an allowed network")
var ErrBusy = errors.New("BMC inspection is already in progress")
var ErrUnavailable = errors.New("Redfish resource unavailable")
var ErrAmbiguous = errors.New("Redfish exposes multiple systems; an explicit binding is required")

type Observation struct {
	SystemPath           string            `json:"system_path"`
	Manufacturer         string            `json:"manufacturer"`
	Model                string            `json:"model"`
	Serial               string            `json:"serial"`
	UUID                 string            `json:"uuid"`
	BIOSVersion          string            `json:"bios_version"`
	CPUSockets           *int              `json:"cpu_sockets"`
	MemoryGiB            *float64          `json:"memory_gib"`
	BIOSAttributes       map[string]any    `json:"bios_attributes"`
	BIOSRegistry         string            `json:"bios_registry"`
	BIOSRegistryHash     string            `json:"bios_registry_hash"`
	BIOSAttributeTypes   map[string]string `json:"bios_attribute_types"`
	BIOSRegistryCoverage string            `json:"bios_registry_coverage"`
	BIOSCoverage         string            `json:"bios_coverage"`
	PendingAttributes    map[string]any    `json:"pending_attributes"`
	PendingCoverage      string            `json:"pending_coverage"`
	NICCoverage          string            `json:"nic_coverage"`
	DiskCoverage         string            `json:"disk_coverage"`
	VolumeCoverage       string            `json:"volume_coverage"`
	Interfaces           []Ethernet        `json:"interfaces"`
	Drives               []Drive           `json:"drives"`
	Volumes              []StorageVolume   `json:"volumes"`
}
type Client struct {
	Allowed []netip.Prefix
	Roots   *x509.CertPool
	mu      sync.Mutex
	active  map[string]bool
}

func (c *Client) lock(address netip.Addr) (func(), error) {
	if !c.Permits(address) {
		return nil, ErrNotAllowed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active == nil {
		c.active = map[string]bool{}
	}
	key := address.String()
	if c.active[key] {
		return nil, ErrBusy
	}
	c.active[key] = true
	return func() { c.mu.Lock(); defer c.mu.Unlock(); delete(c.active, key) }, nil
}

func (c *Client) Permits(address netip.Addr) bool {
	for _, network := range c.Allowed {
		if network.Contains(address) {
			return true
		}
	}
	return false
}

type link struct {
	ID string `json:"@odata.id"`
}

func safeAttributes(in map[string]any) map[string]any {
	out := make(map[string]any)
	for k, v := range in {
		key := strings.ToLower(k)
		if strings.Contains(key, "password") || strings.Contains(key, "secret") || strings.Contains(key, "credential") || strings.Contains(key, "token") {
			continue
		}
		switch v.(type) {
		case string, bool, float64, nil:
			out[k] = v
		}
	}
	return out
}

// Inspect uses only GET requests and an explicit IP. It does not reset, mount
// media or modify BIOS; unknown/missing evidence stays explicitly unknown.
func (c *Client) Inspect(ctx context.Context, address netip.Addr, port int, username string, password []byte) (Observation, error) {
	if !address.IsValid() || port < 1 || port > 65535 || username == "" || len(password) == 0 {
		return Observation{}, ErrUnavailable
	}
	release, err := c.lock(address)
	if err != nil {
		return Observation{}, err
	}
	defer release()
	base := &url.URL{Scheme: "https", Host: net.JoinHostPort(address.String(), strconv.Itoa(port))}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 8 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.Roots}}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	getRequest := func(ref string, out any, allowQuery bool) error {
		u, err := url.Parse(ref)
		if err != nil || u.User != nil || (!allowQuery && u.RawQuery != "") || u.Fragment != "" {
			return ErrUnavailable
		}
		u = base.ResolveReference(u)
		if u.Scheme != "https" || !strings.EqualFold(u.Host, base.Host) || !strings.HasPrefix(u.Path, "/redfish/v1/") || path.Clean(u.Path) != strings.TrimSuffix(u.Path, "/") {
			return ErrUnavailable
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return ErrUnavailable
		}
		req.SetBasicAuth(username, string(password))
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return ErrUnavailable
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("%w (HTTP %d)", ErrUnavailable, resp.StatusCode)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
		if err != nil || len(body) > 1<<20 {
			return ErrUnavailable
		}
		if err = json.Unmarshal(body, out); err != nil {
			return ErrUnavailable
		}
		return nil
	}
	get := func(ref string, out any) error { return getRequest(ref, out, false) }
	// Collection next links may carry numeric paging parameters, but must
	// stay on the same collection and the same BMC. Never follow arbitrary
	// URLs or use pagination parameters on individual resource reads.
	getPage := func(collection, next string, out any) error {
		original, err := url.Parse(collection)
		if err != nil || original.User != nil || original.RawQuery != "" || original.Fragment != "" {
			return ErrUnavailable
		}
		original = base.ResolveReference(original)
		link, err := url.Parse(next)
		if err != nil || link.User != nil || link.Fragment != "" {
			return ErrUnavailable
		}
		link = original.ResolveReference(link)
		if link.Scheme != original.Scheme || !strings.EqualFold(link.Host, original.Host) || link.Path != original.Path {
			return ErrUnavailable
		}
		query, err := url.ParseQuery(link.RawQuery)
		if err != nil || len(query) == 0 || len(query) > 3 {
			return ErrUnavailable
		}
		for key, values := range query {
			if (key != "$skip" && key != "$top" && key != "page") || len(values) != 1 || len(values[0]) == 0 || len(values[0]) > 8 {
				return ErrUnavailable
			}
			if _, err := strconv.ParseUint(values[0], 10, 32); err != nil {
				return ErrUnavailable
			}
		}
		return getRequest(link.String(), out, true)
	}
	var root struct {
		Systems    link `json:"Systems"`
		Registries link `json:"Registries"`
	}
	if err = get("/redfish/v1/", &root); err != nil || root.Systems.ID == "" {
		return Observation{}, ErrUnavailable
	}
	var systems struct {
		Members []link `json:"Members"`
		Count   *int   `json:"Members@odata.count"`
		Next    string `json:"Members@odata.nextLink"`
	}
	if err = get(root.Systems.ID, &systems); err != nil {
		return Observation{}, err
	}
	// Never select the first system from a paginated or explicitly multi-system
	// collection. Its remaining members could refer to different hosts.
	if len(systems.Members) > 1 || systems.Next != "" || (systems.Count != nil && *systems.Count > 1) {
		return Observation{}, ErrAmbiguous
	}
	if len(systems.Members) != 1 || systems.Members[0].ID == "" || (systems.Count != nil && *systems.Count != 1) {
		return Observation{}, ErrUnavailable
	}
	var system struct {
		Manufacturer       string `json:"Manufacturer"`
		Model              string `json:"Model"`
		Serial             string `json:"SerialNumber"`
		UUID               string `json:"UUID"`
		BIOSVersion        string `json:"BiosVersion"`
		Bios               link   `json:"Bios"`
		EthernetInterfaces link   `json:"EthernetInterfaces"`
		Storage            link   `json:"Storage"`
		ProcessorSummary   struct {
			Count *int `json:"Count"`
		} `json:"ProcessorSummary"`
		MemorySummary struct {
			Total *float64 `json:"TotalSystemMemoryGiB"`
		} `json:"MemorySummary"`
	}
	if err = get(systems.Members[0].ID, &system); err != nil {
		return Observation{}, err
	}
	if system.ProcessorSummary.Count != nil && *system.ProcessorSummary.Count < 0 {
		system.ProcessorSummary.Count = nil
	}
	if system.MemorySummary.Total != nil && *system.MemorySummary.Total < 0 {
		system.MemorySummary.Total = nil
	}
	result := Observation{SystemPath: systems.Members[0].ID, Manufacturer: system.Manufacturer, Model: system.Model, Serial: system.Serial, UUID: system.UUID, BIOSVersion: system.BIOSVersion, CPUSockets: system.ProcessorSummary.Count, MemoryGiB: system.MemorySummary.Total, BIOSCoverage: "unknown", BIOSRegistryCoverage: "unknown", PendingCoverage: "unknown", NICCoverage: "unknown", DiskCoverage: "unknown"}
	if system.Bios.ID != "" {
		var bios struct {
			Attributes map[string]any `json:"Attributes"`
			Registry   string         `json:"AttributeRegistry"`
			Settings   struct {
				Object link `json:"SettingsObject"`
			} `json:"@Redfish.Settings"`
		}
		if err = get(system.Bios.ID, &bios); err == nil && bios.Attributes != nil {
			result.BIOSAttributes = safeAttributes(bios.Attributes)
			result.BIOSRegistry = bios.Registry
			result.BIOSCoverage = "available"
			if root.Registries.ID != "" && bios.Registry != "" {
				result.BIOSRegistryHash, result.BIOSAttributeTypes = readRegistry(get, getPage, root.Registries.ID, bios.Registry)
				if result.BIOSRegistryHash != "" {
					result.BIOSRegistryCoverage = "available"
				}
			}
			if bios.Settings.Object.ID != "" {
				var pending struct {
					Attributes map[string]any `json:"Attributes"`
				}
				if err = get(bios.Settings.Object.ID, &pending); err == nil && pending.Attributes != nil {
					result.PendingAttributes = safeAttributes(pending.Attributes)
					result.PendingCoverage = "available"
				}
			}
		}
	}
	result.Interfaces, result.NICCoverage = collectInterfaces(get, getPage, system.EthernetInterfaces.ID)
	result.Drives, result.DiskCoverage, result.Volumes, result.VolumeCoverage = collectDrives(get, getPage, system.Storage.ID)
	return result, nil
}

// readRegistry uses only locally hosted registry links and rejects ambiguous
// registry definitions. Free-form strings and passwords are not offered as
// baseline candidates because their sensitivity cannot be established here.
func readRegistry(get func(string, any) error, getPage func(string, string, any) error, collection, registryID string) (string, map[string]string) {
	// A baseline must not be derived from an incomplete registry list: another
	// page could contain a competing definition with the same identifier.
	type registryPage struct {
		Members *[]link `json:"Members"`
		Count   *int    `json:"Members@odata.count"`
		Next    string  `json:"Members@odata.nextLink"`
	}
	var page registryPage
	if get(collection, &page) != nil || page.Members == nil {
		return "", nil
	}
	members := append([]link(nil), (*page.Members)...)
	count := page.Count
	visited := map[string]bool{}
	for n := 1; page.Next != "" && n < 4 && len(members) <= 64; n++ {
		if visited[page.Next] {
			return "", nil
		}
		visited[page.Next] = true
		var next registryPage
		if getPage(collection, page.Next, &next) != nil || next.Members == nil {
			return "", nil
		}
		if count != nil && next.Count != nil && *count != *next.Count {
			return "", nil
		}
		if count == nil {
			count = next.Count
		}
		members = append(members, (*next.Members)...)
		page = next
	}
	if page.Next != "" || len(members) > 64 || (count != nil && (*count < 0 || *count != len(members))) {
		return "", nil
	}
	var registryPath string
	seenMembers := map[string]bool{}
	for _, member := range members {
		if member.ID == "" || seenMembers[member.ID] {
			return "", nil
		}
		seenMembers[member.ID] = true
		u, err := url.Parse(member.ID)
		if err != nil || path.Base(u.Path) != registryID {
			continue
		}
		if registryPath != "" {
			return "", nil
		}
		registryPath = member.ID
	}
	if registryPath == "" {
		return "", nil
	}
	var file struct {
		ID       string `json:"Id"`
		Location []struct {
			Language string `json:"Language"`
			URI      string `json:"Uri"`
		} `json:"Location"`
	}
	if get(registryPath, &file) != nil || file.ID != registryID {
		return "", nil
	}
	var location string
	for _, loc := range file.Location {
		if loc.URI != "" && strings.EqualFold(loc.Language, "en") {
			if location != "" {
				return "", nil
			}
			location = loc.URI
		}
	}
	if location == "" {
		return "", nil
	}
	var registry struct {
		ID      string `json:"Id"`
		Entries struct {
			Attributes []struct {
				Name      string `json:"AttributeName"`
				Type      string `json:"Type"`
				ReadOnly  bool   `json:"ReadOnly"`
				Hidden    bool   `json:"Hidden"`
				WriteOnly bool   `json:"WriteOnly"`
			} `json:"Attributes"`
		} `json:"RegistryEntries"`
	}
	// Hash the complete canonical registry rather than only selected fields.
	var raw map[string]any
	if get(location, &raw) != nil || raw == nil {
		return "", nil
	}
	canonical, err := json.Marshal(raw)
	if err != nil || json.Unmarshal(canonical, &registry) != nil || registry.ID != registryID || len(registry.Entries.Attributes) == 0 || len(registry.Entries.Attributes) > 10000 {
		return "", nil
	}
	types := map[string]string{}
	seen := map[string]bool{}
	for _, a := range registry.Entries.Attributes {
		if a.Name == "" || seen[a.Name] {
			return "", nil
		}
		seen[a.Name] = true
		key := strings.ToLower(a.Name)
		if a.ReadOnly || a.Hidden || a.WriteOnly || strings.Contains(key, "password") || strings.Contains(key, "secret") || strings.Contains(key, "credential") || strings.Contains(key, "token") || strings.Contains(key, "serial") || strings.Contains(key, "uuid") || strings.Contains(key, "macaddress") {
			continue
		}
		if baselineCandidate(a.Name) && (a.Type == "Enumeration" || a.Type == "Boolean" || a.Type == "Integer") {
			types[a.Name] = a.Type
		}
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), types
}

// Registry type alone does not establish that a setting is safe to copy
// between machines. Keep the initial set deliberately narrow until explicit
// operator classification is implemented.
func baselineCandidate(name string) bool {
	switch strings.ToLower(name) {
	case "virtualization", "procvirtualization", "intelvirtualizationtechnology", "prochyperthreading", "procturbomode", "powerprofile", "bootmode", "embeddedsata":
		return true
	default:
		return false
	}
}

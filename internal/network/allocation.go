package network

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

var ErrAllocation = errors.New("invalid allocation file or selected host binding")

const allocationLimit = 2 << 20

type HostBinding struct {
	DeviceID int64  `json:"device_id"`
	Key      string `json:"key"`
}
type Assignment struct {
	Group    string `json:"group"`
	HostKey  string `json:"host_key"`
	DeviceID int64  `json:"device_id"`
	Value    string `json:"value"`
}
type AllocationImport struct {
	Hash          string       `json:"hash"`
	ParserVersion int          `json:"parser_version"`
	Assignments   []Assignment `json:"assignments"`
	IgnoredHosts  int          `json:"ignored_hosts"`
}

// ParseAllocation parses data only: aliases, custom tags and template
// expressions are never evaluated. Keys bind selected devices explicitly.
func ParseAllocation(data []byte, hosts []HostBinding, groups []string) (AllocationImport, error) {
	if len(data) == 0 || len(data) > allocationLimit || len(hosts) == 0 || len(hosts) > 1000 || len(groups) == 0 || len(groups) > 256 {
		return AllocationImport{}, ErrAllocation
	}
	keys := map[string]bool{}
	ids := map[int64]bool{}
	for _, h := range hosts {
		if h.DeviceID <= 0 || h.Key == "" || len(h.Key) > 255 || keys[h.Key] || ids[h.DeviceID] {
			return AllocationImport{}, ErrAllocation
		}
		keys[h.Key] = true
		ids[h.DeviceID] = true
	}
	wanted := map[string]bool{}
	for _, g := range groups {
		if g == "" || len(g) > 128 || wanted[g] {
			return AllocationImport{}, ErrAllocation
		}
		wanted[g] = true
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if decoder.Decode(&doc) != nil {
		return AllocationImport{}, ErrAllocation
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return AllocationImport{}, ErrAllocation
	}
	count := 0
	var inspect func(*yaml.Node, int) bool
	inspect = func(n *yaml.Node, depth int) bool {
		count++
		if count > 100000 || depth > 8 || n.Kind == yaml.AliasNode || n.Anchor != "" {
			return false
		}
		if n.Kind == yaml.MappingNode {
			if len(n.Content)%2 != 0 {
				return false
			}
			seen := map[string]bool{}
			for i := 0; i < len(n.Content); i += 2 {
				k := n.Content[i]
				if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || seen[k.Value] {
					return false
				}
				seen[k.Value] = true
			}
		}
		for _, child := range n.Content {
			if !inspect(child, depth+1) {
				return false
			}
		}
		return true
	}
	if !inspect(&doc, 0) || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return AllocationImport{}, ErrAllocation
	}
	top := doc.Content[0]
	maps := map[string]*yaml.Node{}
	for i := 0; i < len(top.Content); i += 2 {
		if wanted[top.Content[i].Value] {
			maps[top.Content[i].Value] = top.Content[i+1]
		}
	}
	digest := sha256.Sum256(data)
	result := AllocationImport{Hash: hex.EncodeToString(digest[:]), ParserVersion: 1, Assignments: []Assignment{}}
	ignored := map[string]bool{}
	for _, group := range groups {
		m, ok := maps[group]
		if !ok || m.Kind != yaml.MappingNode {
			return AllocationImport{}, ErrAllocation
		}
		entries := map[string]*yaml.Node{}
		for i := 0; i < len(m.Content); i += 2 {
			key := m.Content[i].Value
			if keys[key] {
				entries[key] = m.Content[i+1]
			} else {
				ignored[key] = true
			}
		}
		for _, host := range hosts {
			v, ok := entries[host.Key]
			if !ok || v.Kind != yaml.ScalarNode || v.Tag != "!!str" || v.Value == "" || len(v.Value) > 255 || strings.Contains(v.Value, "{{") || strings.Contains(v.Value, "{%") {
				return AllocationImport{}, ErrAllocation
			}
			result.Assignments = append(result.Assignments, Assignment{Group: group, HostKey: host.Key, DeviceID: host.DeviceID, Value: v.Value})
		}
	}
	result.IgnoredHosts = len(ignored)
	return result, nil
}

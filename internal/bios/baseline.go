// Package bios implements read-only, model-specific BIOS comparisons.
package bios

import (
	"errors"
	"math"
	"sort"
	"strings"

	"forge/internal/inspection"
	"forge/internal/redfish"
)

var ErrInvalidReference = errors.New("reference inspection cannot form a BIOS baseline")

type Variant struct {
	ReferenceJobID string            `json:"reference_job_id"`
	Manufacturer   string            `json:"manufacturer"`
	Model          string            `json:"model"`
	Firmware       string            `json:"firmware"`
	Registry       string            `json:"registry"`
	RegistryHash   string            `json:"registry_hash"`
	Attributes     map[string]any    `json:"attributes"`
	Types          map[string]string `json:"types"`
}
type Finding struct {
	Attribute     string `json:"attribute"`
	Status        string `json:"status"`
	Expected      any    `json:"expected"`
	Active        any    `json:"active"`
	Pending       any    `json:"pending"`
	PendingStatus string `json:"pending_status"`
}
type Comparison struct {
	Status   string    `json:"status"`
	Reason   string    `json:"reason,omitempty"`
	Findings []Finding `json:"findings"`
}

func validValue(typ string, value any) bool {
	switch typ {
	case "Enumeration":
		_, ok := value.(string)
		return ok
	case "Boolean":
		_, ok := value.(bool)
		return ok
	case "Integer":
		v, ok := value.(float64)
		return ok && !math.IsNaN(v) && !math.IsInf(v, 0) && math.Trunc(v) == v
	}
	return false
}

// Capture copies only explicitly selected, classified attributes from a
// matched reference host. Later observations cannot alter the captured values.
func Capture(reference inspection.Record, selected []string) (Variant, error) {
	o := reference.Observed
	if reference.IdentityStatus != "match" || reference.JobID == "" || strings.TrimSpace(o.Manufacturer) == "" || strings.TrimSpace(o.Model) == "" || strings.TrimSpace(o.BIOSVersion) == "" || o.BIOSCoverage != "available" || o.BIOSRegistryCoverage != "available" || o.BIOSRegistry == "" || len(o.BIOSRegistryHash) != 64 || len(selected) == 0 || len(selected) > 1000 {
		return Variant{}, ErrInvalidReference
	}
	v := Variant{ReferenceJobID: reference.JobID, Manufacturer: o.Manufacturer, Model: o.Model, Firmware: o.BIOSVersion, Registry: o.BIOSRegistry, RegistryHash: o.BIOSRegistryHash, Attributes: map[string]any{}, Types: map[string]string{}}
	for _, name := range selected {
		typ, ok := o.BIOSAttributeTypes[name]
		if !ok {
			return Variant{}, ErrInvalidReference
		}
		value, ok := o.BIOSAttributes[name]
		if !ok || !validValue(typ, value) {
			return Variant{}, ErrInvalidReference
		}
		if _, duplicate := v.Attributes[name]; duplicate {
			return Variant{}, ErrInvalidReference
		}
		v.Attributes[name] = value
		v.Types[name] = typ
	}
	return v, nil
}

// Compare requires exact observed identity, firmware and registry content.
// Pending settings are reported separately and never count as active success.
func Compare(v Variant, o redfish.Observation) Comparison {
	result := Comparison{Status: "unknown", Findings: []Finding{}}
	if o.Manufacturer == "" || o.Model == "" || o.BIOSVersion == "" || o.BIOSRegistry == "" || o.BIOSRegistryCoverage != "available" || o.BIOSRegistryHash == "" {
		result.Reason = "missing compatibility evidence"
		return result
	}
	if o.Manufacturer != v.Manufacturer || o.Model != v.Model || o.BIOSVersion != v.Firmware || o.BIOSRegistry != v.Registry || o.BIOSRegistryHash != v.RegistryHash {
		result.Status = "not_applicable"
		result.Reason = "vendor, model, firmware, or registry differs"
		return result
	}
	if o.BIOSCoverage != "available" {
		result.Reason = "active BIOS settings unavailable"
		return result
	}
	names := make([]string, 0, len(v.Attributes))
	for name := range v.Attributes {
		names = append(names, name)
	}
	sort.Strings(names)
	result.Status = "pass"
	for _, name := range names {
		expected := v.Attributes[name]
		typ := v.Types[name]
		active, exists := o.BIOSAttributes[name]
		f := Finding{Attribute: name, Expected: expected, Active: active, Status: "unknown", PendingStatus: "unknown"}
		if exists && validValue(typ, active) && validValue(typ, expected) && o.BIOSAttributeTypes[name] == typ {
			if active == expected {
				f.Status = "pass"
			} else {
				f.Status = "fail"
			}
		}
		if o.PendingCoverage == "available" {
			if pending, ok := o.PendingAttributes[name]; ok && validValue(typ, pending) {
				f.Pending = pending
				if pending == expected {
					f.PendingStatus = "matches"
				} else {
					f.PendingStatus = "differs"
				}
			}
		}
		if f.Status == "fail" {
			result.Status = "fail"
		} else if f.Status == "unknown" && result.Status != "fail" {
			result.Status = "unknown"
		}
		result.Findings = append(result.Findings, f)
	}
	if len(result.Findings) == 0 {
		result.Status = "unknown"
		result.Reason = "empty baseline"
	}
	return result
}

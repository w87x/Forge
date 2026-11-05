// Package compliance evaluates stored evidence without changing infrastructure.
package compliance

import (
	"fmt"
	"math"
	"strings"
	"time"

	"forge/internal/inspection"
	"forge/internal/inventory"
)

type Hardware struct {
	RequireSerial               bool    `json:"require_serial"`
	RequireModel                bool    `json:"require_model"`
	Manufacturer                string  `json:"manufacturer"`
	Model                       string  `json:"model"`
	MinCPUSockets               int     `json:"min_cpu_sockets"`
	MinMemoryGiB                float64 `json:"min_memory_gib"`
	MinDrives                   int     `json:"min_drives"`
	MinPhysicalNICs             int     `json:"min_physical_nics"`
	RequireInterfacesDocumented bool    `json:"require_interfaces_documented"`
	RAIDExpectation             string  `json:"raid_expectation"`
}
type Finding struct {
	Rule          string     `json:"rule"`
	Status        string     `json:"status"`
	Message       string     `json:"message"`
	BlocksInstall bool       `json:"blocks_install"`
	Severity      string     `json:"severity"`
	Source        string     `json:"source"`
	Expected      any        `json:"expected,omitempty"`
	Actual        any        `json:"actual,omitempty"`
	EvidenceAt    *time.Time `json:"evidence_at,omitempty"`
}
type Result struct {
	Status      string    `json:"status"`
	Findings    []Finding `json:"findings"`
	EvaluatedAt time.Time `json:"evaluated_at"`
}

func (h Hardware) Validate() error {
	if h.MinCPUSockets < 0 || h.MinCPUSockets > 1024 || math.IsNaN(h.MinMemoryGiB) || math.IsInf(h.MinMemoryGiB, 0) || h.MinMemoryGiB < 0 || h.MinMemoryGiB > 1048576 || h.MinDrives < 0 || h.MinDrives > 10000 || h.MinPhysicalNICs < 0 || h.MinPhysicalNICs > 10000 || len(h.Manufacturer) > 128 || len(h.Model) > 128 || len(h.RAIDExpectation) > 128 || strings.ContainsAny(h.Manufacturer+h.Model+h.RAIDExpectation, "\x00\r\n") {
		return fmt.Errorf("invalid hardware profile")
	}
	return nil
}

// Evaluate never interprets an absent or partially collected domain as an
// empty healthy inventory. A serial mismatch always blocks installation.
func Evaluate(h Hardware, device *inventory.Device, record *inspection.Record, now time.Time) Result {
	r := Result{Status: "pass", Findings: []Finding{}, EvaluatedAt: now.UTC()}
	add := func(rule, status, message string) {
		f := Finding{Rule: rule, Status: status, Message: message, BlocksInstall: status != "pass", Severity: "info", Source: "inspection"}
		if status == "fail" {
			f.Severity = "error"
		} else if status == "unknown" {
			f.Severity = "warning"
		}
		if record != nil {
			at := record.CollectedAt
			f.EvidenceAt = &at
			switch rule {
			case "serial":
				f.Source = "netbox+redfish"
				f.Expected = record.DeclaredSerial
				f.Actual = record.Observed.Serial
			case "netbox_model":
				f.Source = "netbox+redfish"
				if device != nil {
					f.Expected = device.Model
				}
				f.Actual = record.Observed.Model
			case "manufacturer":
				f.Source = "redfish"
				f.Expected = h.Manufacturer
				f.Actual = record.Observed.Manufacturer
			case "model":
				f.Source = "redfish"
				f.Expected = h.Model
				f.Actual = record.Observed.Model
			case "cpu_sockets":
				f.Source = "redfish"
				f.Expected = h.MinCPUSockets
				if record.Observed.CPUSockets != nil {
					f.Actual = *record.Observed.CPUSockets
				}
			case "memory":
				f.Source = "redfish"
				f.Expected = h.MinMemoryGiB
				if record.Observed.MemoryGiB != nil {
					f.Actual = *record.Observed.MemoryGiB
				}
			case "drives":
				f.Source = "redfish"
				f.Expected = h.MinDrives
				serials := map[string]bool{}
				for _, drive := range record.Observed.Drives {
					if serial := strings.TrimSpace(drive.Serial); serial != "" {
						serials[serial] = true
					}
				}
				f.Actual = len(serials)
			case "physical_nics":
				f.Source = "not_collected"
				f.Expected = h.MinPhysicalNICs
			case "interfaces":
				f.Source = "not_collected"
				f.Expected = "All physical interfaces documented"
			case "raid":
				f.Source = "not_collected"
				f.Expected = h.RAIDExpectation
			}
		}
		if value, ok := f.Expected.(string); ok && strings.TrimSpace(value) == "" {
			f.Expected = nil
		}
		if value, ok := f.Actual.(string); ok && strings.TrimSpace(value) == "" {
			f.Actual = nil
		}
		r.Findings = append(r.Findings, f)
		if status == "fail" {
			r.Status = "fail"
		} else if status == "unknown" && r.Status != "fail" {
			r.Status = "unknown"
		}
	}
	if record == nil {
		add("inspection", "unknown", "No authorized hardware inspection is available")
		return r
	}
	if record.CollectedAt.IsZero() || record.CollectedAt.After(now.Add(time.Minute)) || now.Sub(record.CollectedAt) > 24*time.Hour {
		add("inspection", "unknown", "Hardware inspection is older than 24 hours or has an invalid timestamp")
		return r
	}
	if record.IdentityStatus == "mismatch" {
		add("serial", "fail", "Observed serial differs from NetBox")
	} else if h.RequireSerial && record.IdentityStatus != "match" {
		add("serial", "unknown", "NetBox and observed serials are required")
	} else if record.IdentityStatus == "match" {
		add("serial", "pass", "Observed serial matches NetBox")
	}
	if h.RequireModel {
		if device == nil || strings.TrimSpace(device.Model) == "" || strings.TrimSpace(record.Observed.Model) == "" {
			add("netbox_model", "unknown", "NetBox or observed model is unavailable")
		} else if device.Model != record.Observed.Model {
			add("netbox_model", "fail", "NetBox and observed models differ")
		} else {
			add("netbox_model", "pass", "NetBox and observed models match")
		}
	}
	if h.Manufacturer != "" {
		if record.Observed.Manufacturer == "" {
			add("manufacturer", "unknown", "Observed manufacturer is unavailable")
		} else if record.Observed.Manufacturer != h.Manufacturer {
			add("manufacturer", "fail", "Observed manufacturer differs from the profile")
		} else {
			add("manufacturer", "pass", "Observed manufacturer matches the profile")
		}
	}
	if h.Model != "" {
		if record.Observed.Model == "" {
			add("model", "unknown", "Observed model is unavailable")
		} else if record.Observed.Model != h.Model {
			add("model", "fail", "Observed model differs from the profile")
		} else {
			add("model", "pass", "Observed model matches the profile")
		}
	}
	if h.MinCPUSockets > 0 {
		if record.Observed.CPUSockets == nil {
			add("cpu_sockets", "unknown", "Reported processor count is unavailable")
		} else if *record.Observed.CPUSockets < h.MinCPUSockets {
			add("cpu_sockets", "fail", "Reported processor count is below the minimum")
		} else {
			add("cpu_sockets", "pass", "Reported processor count meets the minimum")
		}
	}
	if h.MinMemoryGiB > 0 {
		if record.Observed.MemoryGiB == nil {
			add("memory", "unknown", "Memory capacity is unavailable")
		} else if *record.Observed.MemoryGiB < h.MinMemoryGiB {
			add("memory", "fail", "Observed memory is below the minimum")
		} else {
			add("memory", "pass", "Memory capacity meets the minimum")
		}
	}
	if h.MinDrives > 0 {
		serials := map[string]bool{}
		for _, d := range record.Observed.Drives {
			serial := strings.TrimSpace(d.Serial)
			if serial != "" {
				serials[serial] = true
			}
		}
		if len(serials) >= h.MinDrives {
			add("drives", "pass", "Distinct observed drive serials meet the minimum")
		} else if record.Observed.DiskCoverage == "available" && len(serials) == len(record.Observed.Drives) {
			add("drives", "fail", "Drive count is below the minimum")
		} else {
			add("drives", "unknown", "Drive inventory or distinct identities are incomplete")
		}
	}
	if h.MinPhysicalNICs > 0 {
		add("physical_nics", "unknown", "Physical NIC identity is not established by the current inspection")
	}
	if h.RequireInterfacesDocumented {
		add("interfaces", "unknown", "Complete physical-to-NetBox interface binding is not yet available")
	}
	if h.RAIDExpectation != "" {
		add("raid", "unknown", "RAID configuration inspection is not yet available")
	}
	if len(r.Findings) == 0 {
		add("profile", "unknown", "The profile contains no enabled checks")
	}
	return r
}

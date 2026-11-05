package compliance

import (
	"testing"
	"time"

	"forge/internal/inspection"
	"forge/internal/inventory"
	"forge/internal/netbox"
	"forge/internal/redfish"
)

func TestHardwareEvidenceAndIncompleteCoverage(t *testing.T) {
	now := time.Now()
	cpu := 2
	memory := 128.0
	device := inventory.Device{Device: netbox.Device{Model: "M1"}}
	record := inspection.Record{IdentityStatus: "match", CollectedAt: now, Observed: redfish.Observation{Manufacturer: "Vendor", Model: "M1", CPUSockets: &cpu, MemoryGiB: &memory, DiskCoverage: "partial", Drives: []redfish.Drive{{Serial: "disk-a"}, {Serial: "disk-a"}}}}
	h := Hardware{RequireSerial: true, RequireModel: true, Manufacturer: "Vendor", Model: "M1", MinCPUSockets: 2, MinMemoryGiB: 64, MinDrives: 2, MinPhysicalNICs: 2, RequireInterfacesDocumented: true, RAIDExpectation: "raid1"}
	result := Evaluate(h, &device, &record, now)
	if result.Status != "unknown" {
		t.Fatalf("partial coverage passed: %+v", result)
	}
	for _, f := range result.Findings {
		if (f.Rule == "drives" || f.Rule == "physical_nics" || f.Rule == "interfaces" || f.Rule == "raid") && (f.Status != "unknown" || !f.BlocksInstall) {
			t.Fatalf("unexpected coverage: %+v", f)
		}
	}
	record.Observed.Drives = append(record.Observed.Drives, redfish.Drive{Serial: "disk-b"})
	result = Evaluate(h, &device, &record, now)
	for _, f := range result.Findings {
		if f.Rule == "drives" && f.Status != "pass" {
			t.Fatalf("distinct lower bound: %+v", f)
		}
	}
	record.IdentityStatus = "mismatch"
	result = Evaluate(Hardware{}, &device, &record, now)
	if result.Status != "fail" || !result.Findings[0].BlocksInstall {
		t.Fatalf("identity mismatch: %+v", result)
	}
	record.IdentityStatus = "match"
	record.CollectedAt = now.Add(-25 * time.Hour)
	if got := Evaluate(h, &device, &record, now); got.Status != "unknown" {
		t.Fatalf("stale evidence: %+v", got)
	}
	if got := Evaluate(h, &device, nil, now); got.Status != "unknown" {
		t.Fatalf("missing evidence: %+v", got)
	}
}

func TestHardwareModelAndThresholdMismatch(t *testing.T) {
	now := time.Now()
	cpu := 1
	ram := 32.0
	d := inventory.Device{Device: netbox.Device{Model: "Different"}}
	record := inspection.Record{IdentityStatus: "match", CollectedAt: now, Observed: redfish.Observation{Model: "M1", CPUSockets: &cpu, MemoryGiB: &ram}}
	r := Evaluate(Hardware{RequireModel: true, MinCPUSockets: 2, MinMemoryGiB: 64}, &d, &record, now)
	if r.Status != "fail" {
		t.Fatalf("expected failure: %+v", r)
	}
	for _, f := range r.Findings {
		if f.Rule == "netbox_model" || f.Rule == "cpu_sockets" || f.Rule == "memory" {
			if f.Status != "fail" || !f.BlocksInstall {
				t.Fatalf("threshold: %+v", f)
			}
		}
		if f.Rule == "memory" && (f.Expected != float64(64) || f.Actual != float64(32) || f.Source != "redfish" || f.Severity != "error") {
			t.Fatalf("memory evidence: %+v", f)
		}
	}
}

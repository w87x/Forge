package bios

import (
	"errors"
	"strings"
	"testing"

	"forge/internal/inspection"
	"forge/internal/redfish"
)

func TestCaptureAndCompare(t *testing.T) {
	o := redfish.Observation{Manufacturer: "Vendor", Model: "A", BIOSVersion: "1", BIOSRegistry: "reg", BIOSRegistryHash: strings.Repeat("a", 64), BIOSRegistryCoverage: "available", BIOSCoverage: "available", BIOSAttributes: map[string]any{"Virtualization": "Enabled", "Unclassified": "value"}, BIOSAttributeTypes: map[string]string{"Virtualization": "Enumeration"}}
	reference := inspection.Record{JobID: "job", IdentityStatus: "match", Observed: o}
	v, err := Capture(reference, []string{"Virtualization"})
	if err != nil {
		t.Fatal(err)
	}
	o.BIOSAttributes["Virtualization"] = "Disabled"
	o.PendingCoverage = "available"
	o.PendingAttributes = map[string]any{"Virtualization": "Enabled"}
	got := Compare(v, o)
	if got.Status != "fail" || got.Findings[0].PendingStatus != "matches" || v.Attributes["Virtualization"] != "Enabled" {
		t.Fatalf("active and pending: %+v", got)
	}
	o.Model = "B"
	if got = Compare(v, o); got.Status != "not_applicable" {
		t.Fatalf("model: %+v", got)
	}
	o.Model = "A"
	o.BIOSRegistryHash = strings.Repeat("b", 64)
	if got = Compare(v, o); got.Status != "not_applicable" {
		t.Fatalf("registry change: %+v", got)
	}
	o.BIOSRegistryHash = v.RegistryHash
	delete(o.BIOSAttributes, "Virtualization")
	if got = Compare(v, o); got.Status != "unknown" {
		t.Fatalf("missing: %+v", got)
	}
	if _, err = Capture(reference, []string{"Unclassified"}); !errors.Is(err, ErrInvalidReference) {
		t.Fatalf("unclassified: %v", err)
	}
	reference.IdentityStatus = "mismatch"
	if _, err = Capture(reference, []string{"Virtualization"}); !errors.Is(err, ErrInvalidReference) {
		t.Fatalf("identity: %v", err)
	}
}

package plans

import (
	"testing"
	"time"
)

func reviewedFixture() (ReviewedInputs, PreflightEvidence) {
	now := time.Now().UTC()
	return ReviewedInputs{Plan: validPlan(), Selection: []string{"interface", "address", "primary"}, NetBoxInstanceID: "netbox", CredentialGeneration: 2, Devices: []ReviewedDevice{{DeviceID: 1, Serial: "serial"}}, Expectations: []TargetExpectation{{ActionID: "interface", State: "absent"}, {ActionID: "address", State: "absent"}, {ActionID: "primary", State: "present", ObjectID: 5}}}, PreflightEvidence{CollectedAt: now, NetBoxInstanceID: "netbox", CredentialGeneration: 2, AuthorizationVerified: true, Capabilities: map[string]bool{"create_interface": true, "create_ip": true, "set_primary_ip": true}, Serials: map[int64]string{1: "serial"}, Targets: map[string]ObservedTarget{"interface": {State: "absent", VisibilityComplete: true, ReferencesVerified: true}, "address": {State: "absent", VisibilityComplete: true, ReferencesVerified: true}, "primary": {State: "present", ObjectID: 5, VisibilityComplete: true, ReferencesVerified: true}}}
}
func TestPreflightRequiresFreshCompleteEvidenceAndPinnedInputs(t *testing.T) {
	in, ev := reviewedFixture()
	hash, err := ReviewedDigest(in)
	if err != nil {
		t.Fatal(err)
	}
	result, err := EvaluatePreflight(in, hash, ev, ev.CollectedAt)
	if err != nil || result.Status != "pass" {
		t.Fatalf("complete: %+v %v", result, err)
	}
	missing := ev
	missing.Targets = map[string]ObservedTarget{}
	result, err = EvaluatePreflight(in, hash, missing, ev.CollectedAt)
	if err != nil || result.Status != "unknown" {
		t.Fatalf("missing: %+v %v", result, err)
	}
	missing = ev
	missing.AuthorizationVerified = false
	result, _ = EvaluatePreflight(in, hash, missing, ev.CollectedAt)
	if result.Status != "unknown" {
		t.Fatalf("authorization: %+v", result)
	}
	result, _ = EvaluatePreflight(in, hash, ev, ev.CollectedAt.Add(6*time.Minute))
	if result.Status != "unknown" {
		t.Fatalf("stale: %+v", result)
	}
	changed := ev
	changed.CredentialGeneration++
	result, _ = EvaluatePreflight(in, hash, changed, ev.CollectedAt)
	if result.Status != "fail" {
		t.Fatalf("credential: %+v", result)
	}
	result, _ = EvaluatePreflight(in, "wrong", ev, ev.CollectedAt)
	if result.Status != "fail" {
		t.Fatalf("digest: %+v", result)
	}
	changed = ev
	changed.Targets = map[string]ObservedTarget{"interface": {State: "present", ObjectID: 22, VisibilityComplete: true, ReferencesVerified: true}}
	result, _ = EvaluatePreflight(in, hash, changed, ev.CollectedAt)
	if result.Status != "fail" {
		t.Fatalf("target changed: %+v", result)
	}
}
func TestReviewedDigestRejectsMissingExpectationsAndTracksPreconditions(t *testing.T) {
	in, _ := reviewedFixture()
	hash, err := ReviewedDigest(in)
	if err != nil {
		t.Fatal(err)
	}
	in.Expectations[2].ObjectID++
	changed, err := ReviewedDigest(in)
	if err != nil || changed == hash {
		t.Fatalf("changed precondition not bound: %s %v", changed, err)
	}
	in.Expectations = in.Expectations[:2]
	if _, err = ReviewedDigest(in); err == nil {
		t.Fatal("missing expectation accepted")
	}
}

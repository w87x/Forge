package plans

import (
	"forge/internal/audit"
	"forge/internal/bios"
	"forge/internal/compliance"
	"forge/internal/network"
	"testing"
)

func TestInvestigationsAreDerivedOnlyFromNonPassingEvidence(t *testing.T) {
	source := audit.Result{Hardware: compliance.Result{Findings: []compliance.Finding{{Rule: "cpu", Status: "pass"}, {Rule: "serial", Status: "fail", Message: "mismatch"}}}, Network: network.AuditResult{Findings: []network.AuditFinding{{Rule: "address", Status: "unknown", Message: "not visible"}}}, BIOS: &bios.Comparison{Status: "not_applicable", Reason: "no compatible variant"}, Freshness: []string{"old evidence"}}
	got := CompileInvestigations(source)
	if len(got) != 4 || got[0].Rule != "serial" || got[1].Rule != "address" || got[2].Category != "bios" || got[3].Rule != "freshness" {
		t.Fatalf("tasks: %+v", got)
	}
	for _, v := range got {
		if v.Status == "pass" {
			t.Fatalf("passing result became task: %+v", v)
		}
	}
}

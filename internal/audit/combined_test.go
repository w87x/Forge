package audit

import (
	"testing"
	"time"
)

func TestFreshnessUsesCurrentTime(t *testing.T) {
	now := time.Now().UTC()
	network := now.Format(time.RFC3339Nano)
	if got := freshnessAt(now, network, now); len(got) != 0 {
		t.Fatalf("fresh evidence: %+v", got)
	}
	if got := freshnessAt(now, network, now.Add(6*time.Minute)); len(got) != 1 {
		t.Fatalf("stale network: %+v", got)
	}
	if got := freshnessAt(now, network, now.Add(25*time.Hour)); len(got) != 2 {
		t.Fatalf("stale evidence: %+v", got)
	}
	if got := freshnessAt(now, "invalid", now); len(got) != 1 {
		t.Fatalf("invalid timestamp: %+v", got)
	}
}

package plans

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// ReviewedInputs are server-produced inputs for a future approval. In
// particular, Expectations must come from trusted evidence, never from an API
// client's proposed diff. This model is not wired to execution.
type ReviewedInputs struct {
	Plan                 Plan                `json:"plan"`
	Selection            []string            `json:"selection"`
	NetBoxInstanceID     string              `json:"netbox_instance_id"`
	CredentialGeneration int64               `json:"credential_generation"`
	Devices              []ReviewedDevice    `json:"devices"`
	Expectations         []TargetExpectation `json:"expectations"`
}
type ReviewedDevice struct {
	DeviceID int64  `json:"device_id"`
	Serial   string `json:"serial"`
}

// For create actions State must be absent. For a primary-IP action it must be
// present and ObjectID is the previous primary ID (zero means none).
type TargetExpectation struct {
	ActionID string `json:"action_id"`
	State    string `json:"state"`
	ObjectID int64  `json:"object_id"`
}

// ObservedTarget must be refreshed after approval. VisibilityComplete is an
// explicit assurance by a qualified adapter, not merely the end of a page.
type ObservedTarget struct {
	State              string
	ObjectID           int64
	VisibilityComplete bool
	ReferencesVerified bool
}
type PreflightEvidence struct {
	CollectedAt           time.Time
	NetBoxInstanceID      string
	CredentialGeneration  int64
	AuthorizationVerified bool
	Capabilities          map[string]bool
	Serials               map[int64]string
	Targets               map[string]ObservedTarget
}
type PreflightFinding struct {
	ActionID string `json:"action_id,omitempty"`
	Status   string `json:"status"`
	Message  string `json:"message"`
}
type PreflightResult struct {
	Status   string             `json:"status"`
	Findings []PreflightFinding `json:"findings"`
}

// ReviewedDigest binds all selected actions, preconditions, device identities,
// connection and credential generation. All input slices are copied before
// canonicalization, so calculating a digest cannot mutate an approved plan.
func ReviewedDigest(in ReviewedInputs) (string, error) {
	ordered, err := OrderedSelection(in.Plan, in.Selection)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(in.NetBoxInstanceID) == "" || len(in.NetBoxInstanceID) > 128 || strings.ContainsAny(in.NetBoxInstanceID, "\x00\r\n") || in.CredentialGeneration <= 0 {
		return "", ErrInvalid
	}
	deviceIDs := map[int64]bool{}
	actionIDs := map[string]Action{}
	for _, a := range ordered {
		deviceIDs[a.DeviceID] = true
		actionIDs[a.ID] = a
	}
	seenDevices := map[int64]bool{}
	for _, d := range in.Devices {
		if !deviceIDs[d.DeviceID] || seenDevices[d.DeviceID] || strings.TrimSpace(d.Serial) == "" || len(d.Serial) > 256 || strings.ContainsAny(d.Serial, "\x00\r\n") {
			return "", ErrInvalid
		}
		seenDevices[d.DeviceID] = true
	}
	if len(seenDevices) != len(deviceIDs) {
		return "", ErrInvalid
	}
	seenExpect := map[string]bool{}
	for _, e := range in.Expectations {
		a, ok := actionIDs[e.ActionID]
		if !ok || seenExpect[e.ActionID] || e.ObjectID < 0 {
			return "", ErrInvalid
		}
		if a.Kind == "set_primary_ip" {
			if e.State != "present" {
				return "", ErrInvalid
			}
		} else if e.State != "absent" || e.ObjectID != 0 {
			return "", ErrInvalid
		}
		seenExpect[e.ActionID] = true
	}
	if len(seenExpect) != len(actionIDs) {
		return "", ErrInvalid
	}
	digest, err := SelectionDigest(in.Plan, in.Selection)
	if err != nil {
		return "", err
	}
	devices := append([]ReviewedDevice(nil), in.Devices...)
	sort.Slice(devices, func(i, j int) bool { return devices[i].DeviceID < devices[j].DeviceID })
	expectations := append([]TargetExpectation(nil), in.Expectations...)
	sort.Slice(expectations, func(i, j int) bool { return expectations[i].ActionID < expectations[j].ActionID })
	data, err := json.Marshal(struct {
		Plan         string              `json:"plan"`
		Instance     string              `json:"instance"`
		Generation   int64               `json:"generation"`
		Devices      []ReviewedDevice    `json:"devices"`
		Expectations []TargetExpectation `json:"expectations"`
	}{digest, in.NetBoxInstanceID, in.CredentialGeneration, devices, expectations})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// EvaluatePreflight never mutates a system and does not authorize execution.
// Missing or unqualified evidence remains unknown. Even a pass is only one
// future prerequisite: external write fencing and recovery are not implemented.
func EvaluatePreflight(in ReviewedInputs, approvedDigest string, observed PreflightEvidence, now time.Time) (PreflightResult, error) {
	hash, err := ReviewedDigest(in)
	if err != nil {
		return PreflightResult{}, err
	}
	result := PreflightResult{Status: "pass", Findings: []PreflightFinding{}}
	add := func(id, status, message string) {
		result.Findings = append(result.Findings, PreflightFinding{id, status, message})
		if status == "fail" {
			result.Status = "fail"
		} else if status == "unknown" && result.Status != "fail" {
			result.Status = "unknown"
		}
	}
	if approvedDigest == "" {
		add("", "unknown", "No reviewed digest is available")
	} else if approvedDigest != hash {
		add("", "fail", "Reviewed inputs changed after approval")
	}
	if observed.CollectedAt.IsZero() || observed.CollectedAt.After(now.Add(time.Minute)) || now.Sub(observed.CollectedAt) > 5*time.Minute {
		add("", "unknown", "Fresh preflight evidence is required")
	}
	if observed.NetBoxInstanceID == "" || observed.CredentialGeneration <= 0 {
		add("", "unknown", "Connection or credential generation is unavailable")
	} else if observed.NetBoxInstanceID != in.NetBoxInstanceID || observed.CredentialGeneration != in.CredentialGeneration {
		add("", "fail", "Connection or credential changed")
	}
	if !observed.AuthorizationVerified {
		add("", "unknown", "Current authorization has not been verified")
	}
	for _, device := range in.Devices {
		serial := observed.Serials[device.DeviceID]
		if strings.TrimSpace(serial) == "" {
			add("", "unknown", "Device identity is unavailable")
		} else if serial != device.Serial {
			add("", "fail", "Device identity changed")
		}
	}
	expectations := map[string]TargetExpectation{}
	for _, e := range in.Expectations {
		expectations[e.ActionID] = e
	}
	actions, _ := OrderedSelection(in.Plan, in.Selection)
	for _, a := range actions {
		if !observed.Capabilities[a.Kind] {
			add(a.ID, "unknown", "The required NetBox capability is not verified")
		}
		actual, ok := observed.Targets[a.ID]
		if !ok || !actual.VisibilityComplete {
			add(a.ID, "unknown", "Target state or visibility is incomplete")
			continue
		}
		if !actual.ReferencesVerified {
			add(a.ID, "unknown", "Target references have not been verified")
		}
		expected := expectations[a.ID]
		if actual.State != "present" && actual.State != "absent" {
			add(a.ID, "unknown", "Target state is unavailable")
		} else if actual.State != expected.State || actual.ObjectID != expected.ObjectID {
			add(a.ID, "fail", "Target changed since review")
		}
	}
	return result, nil
}

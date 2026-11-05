package netbox

import (
	"encoding/json"
	"testing"
)

func TestUntaggedVLANReferenceCoverage(t *testing.T) {
	cases := []struct {
		raw     json.RawMessage
		known   bool
		id      int64
		invalid bool
	}{
		{nil, false, 0, false},
		{json.RawMessage(`null`), true, 0, false},
		{json.RawMessage(`{"id":12}`), true, 12, false},
		{json.RawMessage(`{"id":0}`), false, 0, true},
	}
	for _, tc := range cases {
		id, known, err := rawRef(tc.raw)
		if (err != nil) != tc.invalid || known != tc.known || (tc.id == 0 && id != nil) || (tc.id != 0 && (id == nil || *id != tc.id)) {
			t.Fatalf("raw %s: %v %v %v", tc.raw, id, known, err)
		}
	}
}

func TestCableStateNeedsBothDirectIndicators(t *testing.T) {
	yes, no := true, false
	cable := int64(4)
	cases := []struct {
		cable  *int64
		known  bool
		marked *bool
		want   string
	}{
		{nil, false, nil, "unknown"}, {nil, true, nil, "unknown"}, {nil, false, &no, "unknown"},
		{nil, true, &no, "unconnected"}, {nil, false, &yes, "occupied"}, {&cable, true, nil, "occupied"},
	}
	for _, tc := range cases {
		if got := cableState(tc.cable, tc.known, tc.marked); got != tc.want {
			t.Fatalf("state %q, want %q", got, tc.want)
		}
	}
}

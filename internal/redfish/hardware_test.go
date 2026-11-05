package redfish

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestEthernetInvalidSpeedIsUnknown(t *testing.T) {
	get := func(path string, out any) error {
		var data string
		switch path {
		case "/interfaces":
			data = `{"Members":[{"@odata.id":"/interface"}]}`
		case "/interface":
			data = `{"SpeedMbps":-1,"Status":{"Health":"OK","State":"Enabled"}}`
		default:
			return errors.New("not found")
		}
		return json.Unmarshal([]byte(data), out)
	}
	interfaces, coverage := collectInterfaces(get, func(string, string, any) error { return errors.New("unexpected page") }, "/interfaces")
	if coverage != "partial" || len(interfaces) != 1 || interfaces[0].SpeedMbps != nil || interfaces[0].Health != "OK" {
		t.Fatalf("invalid speed or coverage: %+v %s", interfaces, coverage)
	}
}

func TestCollectionPaginationIsBoundedAndLoopsStop(t *testing.T) {
	get := func(_ string, out any) error {
		return json.Unmarshal([]byte(`{"Members":[{"@odata.id":"/one"}],"Members@odata.nextLink":"?page=2"}`), out)
	}
	calls := 0
	next := func(_, _ string, out any) error {
		calls++
		return json.Unmarshal([]byte(`{"Members":[{"@odata.id":"/two"}],"Members@odata.nextLink":"?page=2"}`), out)
	}
	members, ok := collectionMembers(get, next, "/collection", 64)
	if !ok || calls != 1 || len(members) != 2 {
		t.Fatalf("pagination loop: %d %+v %v", calls, members, ok)
	}
}

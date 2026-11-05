package redfish

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
)

func TestReadOnlyInspectionAndRedaction(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("unexpected mutation %s", r.Method)
		}
		u, p, ok := r.BasicAuth()
		if !ok || u != "admin" || p != "secret" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/redfish/v1/":
			fmt.Fprint(w, `{"Systems":{"@odata.id":"/redfish/v1/Systems"},"Registries":{"@odata.id":"/redfish/v1/Registries"}}`)
		case "/redfish/v1/Systems":
			fmt.Fprint(w, `{"Members":[{"@odata.id":"/redfish/v1/Systems/node"}]}`)
		case "/redfish/v1/Systems/node":
			fmt.Fprint(w, `{"Manufacturer":"Vendor","Model":"Model","SerialNumber":"SERIAL","BiosVersion":"1.2","ProcessorSummary":{"Count":2},"MemorySummary":{"TotalSystemMemoryGiB":256},"Bios":{"@odata.id":"/redfish/v1/Systems/node/Bios"},"EthernetInterfaces":{"@odata.id":"/redfish/v1/Systems/node/EthernetInterfaces"},"Storage":{"@odata.id":"/redfish/v1/Systems/node/Storage"}}`)
		case "/redfish/v1/Systems/node/Bios":
			fmt.Fprint(w, `{"AttributeRegistry":"BiosRegistry.1","Attributes":{"Virtualization":"Enabled","AdminPassword":"hidden"},"@Redfish.Settings":{"SettingsObject":{"@odata.id":"/redfish/v1/Systems/node/Bios/Settings"}}}`)
		case "/redfish/v1/Systems/node/Bios/Settings":
			fmt.Fprint(w, `{"Attributes":{"Virtualization":"Disabled","SecretKey":"hidden"}}`)
		case "/redfish/v1/Registries":
			fmt.Fprint(w, `{"Members":[{"@odata.id":"/redfish/v1/Registries/BiosRegistry.1"}]}`)
		case "/redfish/v1/Registries/BiosRegistry.1":
			fmt.Fprint(w, `{"Id":"BiosRegistry.1","Location":[{"Language":"en","Uri":"/redfish/v1/Registries/BiosRegistry.1/registry.json"}]}`)
		case "/redfish/v1/Registries/BiosRegistry.1/registry.json":
			fmt.Fprint(w, `{"Id":"BiosRegistry.1","RegistryEntries":{"Attributes":[{"AttributeName":"Virtualization","Type":"Enumeration"},{"AttributeName":"AdminPassword","Type":"Password"},{"AttributeName":"SystemSerial","Type":"String"},{"AttributeName":"ReadOnly","Type":"Integer","ReadOnly":true}]}}`)
		case "/redfish/v1/Systems/node/EthernetInterfaces":
			if r.URL.Query().Get("page") == "2" {
				fmt.Fprint(w, `{"Members":[{"@odata.id":"/redfish/v1/Systems/node/EthernetInterfaces/2"}]}`)
			} else {
				fmt.Fprint(w, `{"Members":[{"@odata.id":"/redfish/v1/Systems/node/EthernetInterfaces/1"},{"@odata.id":"/redfish/v1/Systems/node/EthernetInterfaces/missing"}],"Members@odata.nextLink":"/redfish/v1/Systems/node/EthernetInterfaces?page=2"}`)
			}
		case "/redfish/v1/Systems/node/EthernetInterfaces/2":
			fmt.Fprint(w, `{"Id":"2","MACAddress":"00:11:22:33:44:66"}`)
		case "/redfish/v1/Systems/node/EthernetInterfaces/1":
			fmt.Fprint(w, `{"Id":"1","MACAddress":"00:11:22:33:44:55","SpeedMbps":1000,"Status":{"Health":"Warning","State":"Enabled"}}`)
		case "/redfish/v1/Systems/node/Storage":
			fmt.Fprint(w, `{"Members":[{"@odata.id":"/redfish/v1/Systems/node/Storage/1"}]}`)
		case "/redfish/v1/Systems/node/Storage/1":
			fmt.Fprint(w, `{"Drives":[{"@odata.id":"/redfish/v1/Systems/node/Storage/1/Drives/1"},{"@odata.id":"/redfish/v1/Systems/node/Storage/1/Drives/1"}],"Volumes":{"@odata.id":"/redfish/v1/Systems/node/Storage/1/Volumes"}}`)
		case "/redfish/v1/Systems/node/Storage/1/Volumes":
			fmt.Fprint(w, `{"Members":[{"@odata.id":"/redfish/v1/Systems/node/Storage/1/Volumes/1"}]}`)
		case "/redfish/v1/Systems/node/Storage/1/Volumes/1":
			fmt.Fprint(w, `{"Id":"1","RAIDType":"RAID1","CapacityBytes":-1,"Links":{"Drives":[{"@odata.id":"/redfish/v1/Systems/node/Storage/1/Drives/1"}]}}`)
		case "/redfish/v1/Systems/node/Storage/1/Drives/1":
			fmt.Fprint(w, `{"Id":"drive1","Model":"SSD","SerialNumber":"disk-serial","CapacityBytes":-1,"Revision":"1.2","Status":{"Health":"Critical","State":"Enabled"}}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	host, portStr, _ := net.SplitHostPort(server.Listener.Addr().String())
	ip, err := netip.ParseAddr(host)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client := Client{Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Roots: pool}
	observation, err := client.Inspect(context.Background(), ip, port, "admin", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if observation.Serial != "SERIAL" || observation.BIOSAttributes["Virtualization"] != "Enabled" || observation.PendingAttributes["Virtualization"] != "Disabled" || observation.NICCoverage != "partial" {
		t.Fatalf("observation %+v", observation)
	}
	if _, ok := observation.BIOSAttributes["AdminPassword"]; ok {
		t.Fatal("password attribute stored")
	}
	if _, ok := observation.PendingAttributes["SecretKey"]; ok {
		t.Fatal("secret attribute stored")
	}
	if observation.BIOSRegistryCoverage != "available" || len(observation.BIOSRegistryHash) != 64 || len(observation.BIOSAttributeTypes) != 1 || observation.BIOSAttributeTypes["Virtualization"] != "Enumeration" {
		t.Fatalf("registry: %+v", observation)
	}
	if observation.VolumeCoverage != "partial" || len(observation.Volumes) != 1 || observation.Volumes[0].RAIDType != "RAID1" || observation.Volumes[0].CapacityBytes != nil || len(observation.Volumes[0].DrivePaths) != 1 {
		t.Fatalf("volume evidence: %+v", observation)
	}
	if observation.Drives[0].Revision != "1.2" || observation.Drives[0].Health != "Critical" || observation.Drives[0].State != "Enabled" || observation.Interfaces[0].Health != "Warning" || observation.Interfaces[0].State != "Enabled" {
		t.Fatalf("hardware health: %+v", observation)
	}
	if observation.DiskCoverage != "partial" || len(observation.Drives) != 1 || observation.Drives[0].CapacityBytes != nil || len(observation.Interfaces) != 2 || observation.Interfaces[0].Kind != "unknown" || observation.Interfaces[0].MAC != "00:11:22:33:44:55" {
		t.Fatalf("hardware evidence: %+v", observation)
	}
	blocked := Client{}
	if _, err := blocked.Inspect(context.Background(), ip, port, "admin", []byte("secret")); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("unauthorized network: %v", err)
	}
}

func TestAttributeRedaction(t *testing.T) {
	got := safeAttributes(map[string]any{"Password": "secret", "ApiToken": "secret", "Flag": true, "Object": map[string]any{"x": "y"}})
	if len(got) != 1 || got["Flag"] != true {
		t.Fatalf("unexpected attributes: %+v", got)
	}
}

func TestInspectionRejectsIncompleteSystemsCollection(t *testing.T) {
	cases := []struct {
		name, systems string
		want          error
	}{
		{"next page", `{"Members":[{"@odata.id":"/redfish/v1/Systems/1"}],"Members@odata.nextLink":"/redfish/v1/Systems?$skip=1"}`, ErrAmbiguous},
		{"count indicates more", `{"Members":[{"@odata.id":"/redfish/v1/Systems/1"}],"Members@odata.count":2}`, ErrAmbiguous},
		{"inconsistent count", `{"Members":[{"@odata.id":"/redfish/v1/Systems/1"}],"Members@odata.count":0}`, ErrUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var systemReads int
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/redfish/v1/":
					fmt.Fprint(w, `{"Systems":{"@odata.id":"/redfish/v1/Systems"}}`)
				case "/redfish/v1/Systems":
					fmt.Fprint(w, tc.systems)
				default:
					systemReads++
					fmt.Fprint(w, `{}`)
				}
			}))
			defer server.Close()
			host, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
			address, _ := netip.ParseAddr(host)
			port, _ := strconv.Atoi(portText)
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			client := Client{Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Roots: roots}
			_, err := client.Inspect(context.Background(), address, port, "admin", []byte("secret"))
			if !errors.Is(err, tc.want) || systemReads != 0 {
				t.Fatalf("got %v, made %d system reads", err, systemReads)
			}
		})
	}
}

func TestInspectionNegativeResourceSummariesAreUnknown(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redfish/v1/":
			fmt.Fprint(w, `{"Systems":{"@odata.id":"/redfish/v1/Systems"}}`)
		case "/redfish/v1/Systems":
			fmt.Fprint(w, `{"Members":[{"@odata.id":"/redfish/v1/Systems/1"}],"Members@odata.count":1}`)
		case "/redfish/v1/Systems/1":
			fmt.Fprint(w, `{"ProcessorSummary":{"Count":-1},"MemorySummary":{"TotalSystemMemoryGiB":-1}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	host, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	address, _ := netip.ParseAddr(host)
	port, _ := strconv.Atoi(portText)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client := Client{Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Roots: roots}
	observed, err := client.Inspect(context.Background(), address, port, "admin", []byte("secret"))
	if err != nil || observed.CPUSockets != nil || observed.MemoryGiB != nil {
		t.Fatalf("invalid summary: %+v %v", observed, err)
	}
}

func TestRegistryPaginationRequiresCompleteUnambiguousList(t *testing.T) {
	cases := []struct {
		name, first, second string
		want                bool
	}{
		{"match on second page", `{"Members":[{"@odata.id":"/redfish/v1/Registries/Other"}],"Members@odata.count":2,"Members@odata.nextLink":"?page=2"}`, `{"Members":[{"@odata.id":"/redfish/v1/Registries/Registry.1"}],"Members@odata.count":2}`, true},
		{"duplicate match", `{"Members":[{"@odata.id":"/redfish/v1/Registries/Registry.1"}],"Members@odata.nextLink":"?page=2"}`, `{"Members":[{"@odata.id":"/redfish/v1/Registries/Registry.1"}]}`, false},
		{"changing count", `{"Members":[{"@odata.id":"/redfish/v1/Registries/Other"}],"Members@odata.count":2,"Members@odata.nextLink":"?page=2"}`, `{"Members":[{"@odata.id":"/redfish/v1/Registries/Registry.1"}],"Members@odata.count":3}`, false},
		{"unfinished", `{"Members":[{"@odata.id":"/redfish/v1/Registries/Registry.1"}],"Members@odata.nextLink":"?page=2"}`, `{"Members":[],"Members@odata.nextLink":"?page=2"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			get := func(path string, out any) error {
				var text string
				switch path {
				case "/redfish/v1/Registries":
					text = tc.first
				case "/redfish/v1/Registries/Registry.1":
					text = `{"Id":"Registry.1","Location":[{"Language":"en","Uri":"/redfish/v1/registry"}]}`
				case "/redfish/v1/registry":
					text = `{"Id":"Registry.1","RegistryEntries":{"Attributes":[{"AttributeName":"Virtualization","Type":"Boolean"}]}}`
				default:
					return errors.New("unexpected request")
				}
				return json.Unmarshal([]byte(text), out)
			}
			next := func(_, _ string, out any) error { return json.Unmarshal([]byte(tc.second), out) }
			hash, types := readRegistry(get, next, "/redfish/v1/Registries", "Registry.1")
			if (hash != "") != tc.want || (tc.want && types["Virtualization"] != "Boolean") {
				t.Fatalf("registry hash %q types %+v", hash, types)
			}
		})
	}
}

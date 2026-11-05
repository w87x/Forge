package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"forge/internal/auth"
	"forge/internal/bios"
	"forge/internal/compliance"
	"forge/internal/inspection"
	"forge/internal/inventory"
	"forge/internal/netbox"
	"forge/internal/network"
	"forge/internal/profiles"
	"forge/internal/redfish"
	"forge/internal/secrets"
	"forge/internal/store/sqlite"
)

func TestNetworkAllocationPreviewUsesOnlySelectedDevices(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/dcim/devices/":
			fmt.Fprint(w, `{"count":2,"next":null,"results":[{"id":1,"name":"host1"},{"id":2,"name":"host2"}]}`)
		case "/api/dcim/interfaces/":
			if r.URL.Query().Get("offset") == "0" {
				fmt.Fprint(w, `{"count":2,"next":"/api/dcim/interfaces/?device_id=1&limit=50&offset=1","results":[{"id":11,"name":"eth0","device":{"id":1},"type":{"value":"1000base-t"},"mode":{"value":"tagged"},"untagged_vlan":null,"tagged_vlans":[{"id":50}]}]}`)
			} else {
				fmt.Fprint(w, `{"count":2,"next":null,"results":[{"id":12,"name":"eth0.100","device":{"id":1},"type":{"value":"virtual"},"parent":{"id":11}}]}`)
			}
		case "/api/ipam/ip-addresses/":
			fmt.Fprint(w, `{"count":1,"next":null,"results":[{"id":22,"address":"192.0.2.1/24","vrf":null,"assigned_object_type":"dcim.interface","assigned_object_id":12,"assigned_object":{"id":12,"name":"eth0.100","device":{"id":1}}}]}`)
		case "/api/ipam/vlans/":
			fmt.Fprint(w, `{"count":1,"next":null,"results":[{"id":50,"vid":100,"name":"control"}]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer remote.Close()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a := &auth.Service{DB: db.DB, BootstrapToken: strings.Repeat("x", 32)}
	owner, token, err := a.Bootstrap(ctx, strings.Repeat("x", 32), "owner")
	if err != nil {
		t.Fatal(err)
	}
	env, err := a.CreateEnvironment(ctx, owner, "lab")
	if err != nil {
		t.Fatal(err)
	}
	vault, err := secrets.New(db.DB, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32))))
	if err != nil {
		t.Fatal(err)
	}
	host, _, _ := net.SplitHostPort(remote.Listener.Addr().String())
	nb := &netbox.Service{DB: db.DB, Auth: a, Vault: vault, AllowHTTP: true, ConnectionsEnabled: true, AllowedHosts: []string{host}}
	instance, err := nb.CreateInstance(ctx, owner, env.ID, "nb", remote.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = nb.SaveCredential(ctx, owner, instance.ID, "key"); err != nil {
		t.Fatal(err)
	}
	inv := &inventory.Service{DB: db.DB, NetBox: nb}
	snapshot, err := inv.Refresh(ctx, owner, instance.ID, netbox.DeviceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	selection, err := inv.Select(ctx, owner, snapshot.ID, []int64{1})
	if err != nil {
		t.Fatal(err)
	}
	ns := &network.Service{DB: db.DB, Auth: a}
	p, err := ns.Create(ctx, owner, auth.SharedWorkspaceID, "network")
	if err != nil {
		t.Fatal(err)
	}
	p, err = ns.Update(ctx, owner, p.ID, p.RowVersion, network.Graph{NetBoxInstanceID: instance.ID, Nodes: []network.Node{{ID: "eth", Kind: "physical", OSName: "eth0", NetBoxName: "eth0"}, {ID: "vlan", Kind: "vlan", OSName: "eth0.100", NetBoxName: "eth0.100", Parent: "eth", VLANID: 100, NetBoxVLANID: 50}}, Networks: []network.Network{{Name: "ctl", InterfaceID: "vlan", Prefix: "192.0.2.0/24", AllocationGroup: "ctl_ips"}}})
	if err != nil {
		t.Fatal(err)
	}
	revision, _, err := ns.Publish(ctx, owner, p.ID, p.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	is := &inspection.Service{DB: db.DB, Auth: a, Inventory: inv, NetBox: nb}
	h := Handler(nil, nil, a, vault, nil, nb, inv, &profiles.Service{DB: db.DB, Auth: a, Vault: vault}, is, false, false)
	request := func(method, path string, body any, cookies []*http.Cookie, csrf string) *httptest.ResponseRecorder {
		data, _ := json.Marshal(body)
		r := httptest.NewRequest(method, "http://forge.test"+path, bytes.NewReader(data))
		r.Header.Set("Content-Type", "application/json")
		for _, c := range cookies {
			r.AddCookie(c)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	login := request("POST", "/api/v1/auth/login", map[string]string{"token": token}, nil, "")
	if login.Code != 200 {
		t.Fatal(login.Body.String())
	}
	cookies := login.Result().Cookies()
	csrf := ""
	for _, c := range cookies {
		if c.Name == "forge_csrf" {
			csrf = c.Value
		}
	}
	input := map[string]any{"selection_id": selection.ID, "revision": revision.Number, "content": "ctl_ips:\n  host1: 192.0.2.1\n  host2: 192.0.2.2\n  host3: 192.0.2.3\n", "aliases": map[string]string{}}
	if _, err = db.DB.Exec(`INSERT INTO netbox_instances(id,environment_id,name,base_url,created_at) VALUES('other-netbox',?,'other','https://other.test','now')`, auth.SharedWorkspaceID); err != nil {
		t.Fatal(err)
	}
	otherProfile, err := ns.Create(ctx, owner, auth.SharedWorkspaceID, "other profile")
	if err != nil {
		t.Fatal(err)
	}
	otherProfile, err = ns.Update(ctx, owner, otherProfile.ID, otherProfile.RowVersion, network.Graph{NetBoxInstanceID: "other-netbox", Nodes: []network.Node{{ID: "eth", Kind: "physical", OSName: "eth0"}}, Networks: []network.Network{{Name: "ctl", InterfaceID: "eth", Prefix: "192.0.2.0/24", AllocationGroup: "ctl_ips"}}})
	if err != nil {
		t.Fatal(err)
	}
	otherRevision, _, err := ns.Publish(ctx, owner, otherProfile.ID, otherProfile.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	wrongInput := map[string]any{"selection_id": selection.ID, "revision": otherRevision.Number, "content": input["content"], "aliases": map[string]string{}}
	wrong := request("POST", "/api/v1/network-profiles/"+otherProfile.ID+"/allocation-preview", wrongInput, cookies, csrf)
	if wrong.Code != 409 || !strings.Contains(wrong.Body.String(), "wrong_netbox") {
		t.Fatalf("cross-connection profile: %d %s", wrong.Code, wrong.Body.String())
	}
	result := request("POST", "/api/v1/network-profiles/"+p.ID+"/allocation-preview", input, cookies, csrf)
	if result.Code != 200 || !strings.Contains(result.Body.String(), `"address":"192.0.2.1"`) || strings.Contains(result.Body.String(), "192.0.2.2") || !strings.Contains(result.Body.String(), `"ignored_hosts":2`) || !strings.Contains(result.Body.String(), `"netbox_conflicts_checked":false`) {
		t.Fatalf("preview %d %s", result.Code, result.Body.String())
	}
	result = request("POST", "/api/v1/network-profiles/"+p.ID+"/allocation-imports", input, cookies, csrf)
	if result.Code != 200 || !strings.Contains(result.Body.String(), `"persisted":true`) {
		t.Fatalf("save: %d %s", result.Code, result.Body.String())
	}
	var saved struct {
		Import struct {
			ID string `json:"id"`
		} `json:"import"`
	}
	if err = json.Unmarshal(result.Body.Bytes(), &saved); err != nil || saved.Import.ID == "" {
		t.Fatalf("saved import: %v", err)
	}
	result = request("POST", "/api/v1/network-profiles/"+p.ID+"/audits", map[string]any{"selection_id": selection.ID, "import_id": saved.Import.ID, "device_id": 1}, cookies, csrf)
	if result.Code != 201 || !strings.Contains(result.Body.String(), `"rule":"address","status":"pass"`) || !strings.Contains(result.Body.String(), `"rule":"global_conflicts","status":"unknown"`) || !strings.Contains(result.Body.String(), `"rule":"vlan","status":"pass"`) {
		t.Fatalf("network audit: %d %s", result.Code, result.Body.String())
	}
	var audit struct {
		ID string `json:"id"`
	}
	if err = json.Unmarshal(result.Body.Bytes(), &audit); err != nil || audit.ID == "" {
		t.Fatalf("saved audit ID: %v", err)
	}
	// Persist a fixture inspection and hardware check for the same selected
	// device, then compose both saved results without any infrastructure write.
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.DB.ExecContext(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO profiles(id,environment_id,name,kind,draft_json,created_at) VALUES('connection',?,'connection','connection','{}','now')`, auth.SharedWorkspaceID)
	exec(`INSERT INTO profile_revisions(profile_id,revision,content_json,content_hash,actor_id,published_at) VALUES('connection',1,'{}','hash',?,'now')`, owner.ID)
	now := time.Now().UTC()
	exec(`INSERT INTO jobs(id,kind,actor_id,input_hash,status,next_attempt_ns,deadline_ns,created_ns) VALUES('inspection','redfish.inspect',?,'hash','succeeded',0,?,?)`, owner.ID, now.Add(time.Hour).UnixNano(), now.UnixNano())
	observation := inspection.Record{ID: "obs", JobID: "inspection", ServerID: snapshot.Devices[0].ForgeID, DeviceID: 1, IdentityStatus: "match", CollectedAt: now, Observed: redfish.Observation{Serial: "serial", Manufacturer: "Vendor", Model: "Model", BIOSVersion: "1", BIOSCoverage: "available", BIOSRegistryCoverage: "available", BIOSRegistry: "reg", BIOSRegistryHash: strings.Repeat("a", 64), BIOSAttributes: map[string]any{"Virtualization": "Enabled"}, BIOSAttributeTypes: map[string]string{"Virtualization": "Enumeration"}}}
	observationJSON, _ := json.Marshal(observation)
	exec(`INSERT INTO observations(id,actor_id,job_id,server_id,selection_id,profile_id,profile_revision,management_address,observed_json,collected_at_ns) VALUES('obs',?,'inspection',?,?,'connection',1,'127.0.0.1',?,?)`, owner.ID, observation.ServerID, selection.ID, string(observationJSON), now.UnixNano())
	hs := &compliance.Service{DB: db.DB, Inspections: is, Inventory: inv}
	hardware, err := hs.Create(ctx, owner, "hardware", compliance.Hardware{RequireSerial: true})
	if err != nil {
		t.Fatal(err)
	}
	hwRevision, err := hs.Publish(ctx, owner, hardware.ID, hardware.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	hwAudit, err := hs.RunAudit(ctx, owner, hardware.ID, hwRevision.Number, "inspection")
	if err != nil {
		t.Fatal(err)
	}
	bs := &bios.Service{DB: db.DB, Auth: a, Inspections: is}
	biosProfile, err := bs.Create(ctx, owner, "bios", "inspection", []string{"Virtualization"})
	if err != nil {
		t.Fatal(err)
	}
	biosRevision, err := bs.Publish(ctx, owner, biosProfile.ID, biosProfile.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	combined := request("POST", "/api/v1/audits", map[string]any{"hardware_audit_id": hwAudit.ID, "network_audit_id": audit.ID, "selection_id": selection.ID, "bios_profile_id": biosProfile.ID, "bios_revision": biosRevision.Number}, cookies, csrf)
	if combined.Code != 201 || !strings.Contains(combined.Body.String(), `"status":"unknown"`) || !strings.Contains(combined.Body.String(), `"global_conflicts"`) || !strings.Contains(combined.Body.String(), `"bios":{"status":"pass"`) {
		t.Fatalf("combined audit: %d %s", combined.Code, combined.Body.String())
	}
	var combinedID struct {
		ID string `json:"id"`
	}
	if err = json.Unmarshal(combined.Body.Bytes(), &combinedID); err != nil || combinedID.ID == "" {
		t.Fatalf("combined ID: %v", err)
	}
	investigation := request("POST", "/api/v1/audits/"+combinedID.ID+"/investigations", map[string]any{"selection_id": selection.ID}, cookies, csrf)
	if investigation.Code != 201 || !strings.Contains(investigation.Body.String(), `"rule":"global_conflicts"`) {
		t.Fatalf("investigation draft: %d %s", investigation.Code, investigation.Body.String())
	}
	var investigationID struct {
		ID         string `json:"id"`
		RowVersion int    `json:"row_version"`
		Tasks      []struct {
			ID string `json:"id"`
		} `json:"tasks"`
	}
	if err = json.Unmarshal(investigation.Body.Bytes(), &investigationID); err != nil || investigationID.ID == "" {
		t.Fatalf("investigation ID: %v", err)
	}
	if investigationID.RowVersion != 1 || len(investigationID.Tasks) == 0 {
		t.Fatalf("initial progress: %+v", investigationID)
	}
	progress := map[string]any{"selection_id": selection.ID, "row_version": 1, "completed": []string{investigationID.Tasks[0].ID}}
	investigation = request("PUT", "/api/v1/investigations/"+investigationID.ID+"/progress", progress, cookies, csrf)
	if investigation.Code != 200 || !strings.Contains(investigation.Body.String(), `"row_version":2`) {
		t.Fatalf("save investigation progress: %d %s", investigation.Code, investigation.Body.String())
	}
	investigation = request("PUT", "/api/v1/investigations/"+investigationID.ID+"/progress", progress, cookies, csrf)
	if investigation.Code != 409 {
		t.Fatalf("stale update accepted: %d %s", investigation.Code, investigation.Body.String())
	}
	progress["row_version"] = 2
	progress["completed"] = []string{"not-a-task"}
	investigation = request("PUT", "/api/v1/investigations/"+investigationID.ID+"/progress", progress, cookies, csrf)
	if investigation.Code != 400 {
		t.Fatalf("unknown task accepted: %d %s", investigation.Code, investigation.Body.String())
	}
	investigation = request("GET", "/api/v1/investigations/"+investigationID.ID+"?selection_id="+selection.ID, nil, cookies, "")
	if investigation.Code != 200 || !strings.Contains(investigation.Body.String(), `"category":"network"`) {
		t.Fatalf("read investigation: %d %s", investigation.Code, investigation.Body.String())
	}
	investigation = request("GET", "/api/v1/audits/"+combinedID.ID+"/investigations?selection_id="+selection.ID, nil, cookies, "")
	if investigation.Code != 200 || !strings.Contains(investigation.Body.String(), investigationID.ID) {
		t.Fatalf("list investigations: %d %s", investigation.Code, investigation.Body.String())
	}
	combined = request("GET", "/api/v1/audits/"+combinedID.ID+"?selection_id="+selection.ID, nil, cookies, "")
	if combined.Code != 200 || !strings.Contains(combined.Body.String(), `"hardware"`) {
		t.Fatalf("read combined: %d %s", combined.Code, combined.Body.String())
	}
	exec(`INSERT INTO network_audits(id,actor_id,import_id,device_id,result_json,created_at) VALUES('other-device',?,?,2,'{}',?)`, owner.ID, saved.Import.ID, time.Now().UTC().Format(time.RFC3339Nano))
	combined = request("POST", "/api/v1/audits", map[string]any{"hardware_audit_id": hwAudit.ID, "network_audit_id": "other-device", "selection_id": selection.ID, "bios_profile_id": "", "bios_revision": 0}, cookies, csrf)
	if combined.Code != 400 {
		t.Fatalf("different device combined: %d %s", combined.Code, combined.Body.String())
	}
	result = request("POST", "/api/v1/network-profiles/"+p.ID+"/audit-preview", map[string]any{"selection_id": selection.ID, "import_id": saved.Import.ID, "device_id": 2}, cookies, csrf)
	if result.Code != 403 {
		t.Fatalf("unselected network audit: %d %s", result.Code, result.Body.String())
	}
	result = request("GET", "/api/v1/allocation-imports?selection_id="+selection.ID, nil, cookies, "")
	if result.Code != 200 || !strings.Contains(result.Body.String(), "192.0.2.1") || strings.Contains(result.Body.String(), "192.0.2.2") {
		t.Fatalf("saved imports: %d %s", result.Code, result.Body.String())
	}
	other, err := inv.Select(ctx, owner, snapshot.ID, []int64{2})
	if err != nil {
		t.Fatal(err)
	}
	result = request("GET", "/api/v1/allocation-imports?selection_id="+other.ID, nil, cookies, "")
	if result.Code != 200 || strings.TrimSpace(result.Body.String()) != "[]" {
		t.Fatalf("narrow selection: %d %s", result.Code, result.Body.String())
	}
	input["aliases"] = map[string]string{"1": "custom-host"}
	input["content"] = "ctl_ips:\n  custom-host: 192.0.2.4\n  host2: 192.0.2.2\n"
	result = request("POST", "/api/v1/network-profiles/"+p.ID+"/allocation-preview", input, cookies, csrf)
	if result.Code != 200 || !strings.Contains(result.Body.String(), `"host_key":"custom-host"`) {
		t.Fatalf("selected alias: %d %s", result.Code, result.Body.String())
	}
	input["aliases"] = map[string]string{"2": "host2"}
	result = request("POST", "/api/v1/network-profiles/"+p.ID+"/allocation-preview", input, cookies, csrf)
	if result.Code != 400 {
		t.Fatalf("unselected alias accepted: %d %s", result.Code, result.Body.String())
	}
	if _, err = nb.SaveCredential(ctx, owner, instance.ID, "new-key"); err != nil {
		t.Fatal(err)
	}
	result = request("GET", "/api/v1/allocation-imports?selection_id="+selection.ID, nil, cookies, "")
	if result.Code == 200 {
		t.Fatal("old credential selection still visible")
	}
	time.Sleep(600 * time.Millisecond) // Allow the bounded NetBox request budget to refill.
	newSnapshot, err := inv.Refresh(ctx, owner, instance.ID, netbox.DeviceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	newSelection, err := inv.Select(ctx, owner, newSnapshot.ID, []int64{1})
	if err != nil {
		t.Fatal(err)
	}
	result = request("GET", "/api/v1/allocation-imports?selection_id="+newSelection.ID, nil, cookies, "")
	if result.Code != 200 || !strings.Contains(result.Body.String(), "192.0.2.1") {
		t.Fatalf("refreshed visibility: %d %s", result.Code, result.Body.String())
	}
	result = request("GET", "/api/v1/network-audits/"+audit.ID+"?selection_id="+newSelection.ID, nil, cookies, "")
	if result.Code != 200 || !strings.Contains(result.Body.String(), `"rule":"address","status":"pass"`) {
		t.Fatalf("saved audit after reselect: %d %s", result.Code, result.Body.String())
	}
	reader, readerToken, err := a.CreateUser(ctx, owner, "reader", auth.Readonly)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.AddEnvironmentMember(ctx, owner, env.ID, reader.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = nb.SaveCredential(ctx, reader, instance.ID, "reader-key"); err != nil {
		t.Fatal(err)
	}
	// Let the shared two-requests-per-second host budget refill before the
	// fifth read; the test must not bypass rate limiting.
	time.Sleep(600 * time.Millisecond)
	readerSnap, err := inv.Refresh(ctx, reader, instance.ID, netbox.DeviceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	readerSelection, err := inv.Select(ctx, reader, readerSnap.ID, []int64{1})
	if err != nil {
		t.Fatal(err)
	}
	readerLogin := request("POST", "/api/v1/auth/login", map[string]string{"token": readerToken}, nil, "")
	if readerLogin.Code != 200 {
		t.Fatal(readerLogin.Body.String())
	}
	result = request("GET", "/api/v1/allocation-imports?selection_id="+readerSelection.ID, nil, readerLogin.Result().Cookies(), "")
	if result.Code != 200 || strings.TrimSpace(result.Body.String()) != "[]" {
		t.Fatalf("other actor saw imports: %d %s", result.Code, result.Body.String())
	}
	result = request("GET", "/api/v1/network-audits/"+audit.ID+"?selection_id="+readerSelection.ID, nil, readerLogin.Result().Cookies(), "")
	if result.Code != 403 {
		t.Fatalf("other actor saw audit: %d %s", result.Code, result.Body.String())
	}
	result = request("GET", "/api/v1/investigations/"+investigationID.ID+"?selection_id="+readerSelection.ID, nil, readerLogin.Result().Cookies(), "")
	if result.Code == 200 {
		t.Fatalf("other actor saw investigation: %s", result.Body.String())
	}
	result = request("GET", "/api/v1/audits/"+combinedID.ID+"?selection_id="+readerSelection.ID, nil, readerLogin.Result().Cookies(), "")
	if result.Code != 403 {
		t.Fatalf("other actor saw combined audit: %d %s", result.Code, result.Body.String())
	}
	readerCSRF := ""
	for _, cookie := range readerLogin.Result().Cookies() {
		if cookie.Name == "forge_csrf" {
			readerCSRF = cookie.Value
		}
	}
	result = request("PUT", "/api/v1/investigations/"+investigationID.ID+"/progress", map[string]any{"selection_id": readerSelection.ID, "row_version": 2, "completed": []string{}}, readerLogin.Result().Cookies(), readerCSRF)
	if result.Code != 403 {
		t.Fatalf("readonly updated progress: %d %s", result.Code, result.Body.String())
	}
	result = request("POST", "/api/v1/audits/"+combinedID.ID+"/investigations", map[string]any{"selection_id": readerSelection.ID}, readerLogin.Result().Cookies(), readerCSRF)
	if result.Code != 403 {
		t.Fatalf("readonly created investigation: %d %s", result.Code, result.Body.String())
	}
	result = request("POST", "/api/v1/audits", map[string]any{"hardware_audit_id": hwAudit.ID, "network_audit_id": audit.ID, "selection_id": readerSelection.ID, "bios_profile_id": "", "bios_revision": 0}, readerLogin.Result().Cookies(), readerCSRF)
	if result.Code != 403 {
		t.Fatalf("readonly created combined audit: %d %s", result.Code, result.Body.String())
	}
}

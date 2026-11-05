package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"forge/internal/auth"
	"forge/internal/inventory"
	"forge/internal/netbox"
	"forge/internal/network"
)

func mountNetworkProfiles(mux *http.ServeMux, a *auth.Service, inventoryService *inventory.Service, netboxService *netbox.Service, current func(http.ResponseWriter, *http.Request, bool) (auth.User, bool), origin func(http.ResponseWriter, *http.Request) bool, logger *slog.Logger) {
	s := &network.Service{DB: a.DB, Auth: a}
	fail := func(w http.ResponseWriter, err error) {
		var rate *netbox.RateLimitError
		switch {
		case errors.Is(err, network.ErrForbidden), errors.Is(err, inventory.ErrNotVisible), errors.Is(err, netbox.ErrForbidden):
			authError(w, auth.ErrForbidden, logger)
		case errors.Is(err, network.ErrInvalid), errors.Is(err, netbox.ErrInvalid):
			authError(w, auth.ErrInvalidInput, logger)
		case errors.Is(err, network.ErrConflict), errors.Is(err, inventory.ErrStale):
			writeJSON(w, 409, errorResponse{"stale_profile", "The profile changed; reload and try again", correlationID()})
		case errors.As(err, &rate):
			seconds := int64(rate.RetryAfter / time.Second)
			if rate.RetryAfter%time.Second > 0 {
				seconds++
			}
			if seconds < 1 {
				seconds = 1
			}
			w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
			writeJSON(w, 429, errorResponse{"rate_limited", "NetBox requests are temporarily rate limited", correlationID()})
		case errors.Is(err, netbox.ErrRemote):
			writeJSON(w, 502, errorResponse{"netbox_unavailable", "NetBox connection failed", correlationID()})
		default:
			authError(w, err, logger)
		}
	}
	mux.HandleFunc("GET /api/v1/network-profiles", func(w http.ResponseWriter, r *http.Request) {
		u, ok := current(w, r, false)
		if !ok {
			return
		}
		items, err := s.List(r.Context(), u)
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, items)
	})
	mux.HandleFunc("POST /api/v1/network-profiles", func(w http.ResponseWriter, r *http.Request) {
		if !origin(w, r) {
			return
		}
		u, ok := current(w, r, true)
		if !ok {
			return
		}
		var in struct {
			EnvironmentID string `json:"environment_id"`
			Name          string `json:"name"`
		}
		if !decodeJSON(w, r, &in) {
			return
		}
		if in.EnvironmentID == "" {
			in.EnvironmentID = auth.SharedWorkspaceID
		}
		p, err := s.Create(r.Context(), u, in.EnvironmentID, in.Name)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 201, p)
	})
	mux.HandleFunc("PUT /api/v1/network-profiles/{id}/draft", func(w http.ResponseWriter, r *http.Request) {
		if !origin(w, r) {
			return
		}
		u, ok := current(w, r, true)
		if !ok {
			return
		}
		var in struct {
			RowVersion int           `json:"row_version"`
			Graph      network.Graph `json:"graph"`
		}
		if !decodeJSONLimit(w, r, &in, 1<<20) {
			return
		}
		p, err := s.Update(r.Context(), u, r.PathValue("id"), in.RowVersion, in.Graph)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, p)
	})
	mux.HandleFunc("POST /api/v1/network-profiles/{id}/publish", func(w http.ResponseWriter, r *http.Request) {
		if !origin(w, r) {
			return
		}
		u, ok := current(w, r, true)
		if !ok {
			return
		}
		var in struct {
			RowVersion int `json:"row_version"`
		}
		if !decodeJSON(w, r, &in) {
			return
		}
		rev, issues, err := s.Publish(r.Context(), u, r.PathValue("id"), in.RowVersion)
		if errors.Is(err, network.ErrInvalid) {
			writeJSON(w, 422, map[string]any{"code": "invalid_graph", "message": "Network profile has validation errors", "issues": issues, "correlation_id": correlationID()})
			return
		}
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 201, rev)
	})
	mux.HandleFunc("GET /api/v1/network-profiles/{id}/revisions/{revision}", func(w http.ResponseWriter, r *http.Request) {
		u, ok := current(w, r, false)
		if !ok {
			return
		}
		number, err := strconv.Atoi(r.PathValue("revision"))
		if err != nil || number < 1 {
			fail(w, network.ErrInvalid)
			return
		}
		rev, err := s.Revision(r.Context(), u, r.PathValue("id"), number)
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, rev)
	})
	mux.HandleFunc("GET /api/v1/network-profiles/{id}/validation", func(w http.ResponseWriter, r *http.Request) {
		u, ok := current(w, r, false)
		if !ok {
			return
		}
		p, err := s.Get(r.Context(), u, r.PathValue("id"))
		if err != nil {
			fail(w, err)
			return
		}
		if p.Draft == nil {
			fail(w, network.ErrForbidden)
			return
		}
		issues := network.Validate(*p.Draft)
		if len(p.Draft.Nodes) == 0 || len(p.Draft.Networks) == 0 {
			issues = append(issues, network.Issue{Field: "graph", Message: "at least one interface and network are required"})
		}
		writeJSON(w, 200, issues)
	})
	if inventoryService != nil && netboxService != nil {
		imports := &network.ImportService{DB: a.DB, Inventory: inventoryService, NetBox: netboxService}
		handleAllocation := func(save bool) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				if !origin(w, r) {
					return
				}
				u, ok := current(w, r, true)
				if !ok {
					return
				}
				if save && !auth.Allowed(u, auth.Operate) {
					fail(w, network.ErrForbidden)
					return
				}
				var in struct {
					SelectionID string            `json:"selection_id"`
					Revision    int               `json:"revision"`
					Content     string            `json:"content"`
					Aliases     map[string]string `json:"aliases"`
				}
				if !decodeJSONLimit(w, r, &in, 3<<20) {
					return
				}
				if in.Revision < 1 {
					fail(w, network.ErrInvalid)
					return
				}
				p, err := s.Get(r.Context(), u, r.PathValue("id"))
				if err != nil {
					fail(w, err)
					return
				}
				rev, err := s.Revision(r.Context(), u, p.ID, in.Revision)
				if err != nil {
					fail(w, err)
					return
				}
				selection, err := inventoryService.Selection(r.Context(), u, in.SelectionID)
				if err != nil {
					fail(w, network.ErrForbidden)
					return
				}
				snap, err := inventoryService.Snapshot(r.Context(), u, selection.SnapshotID)
				if errors.Is(err, inventory.ErrStale) {
					writeJSON(w, 409, errorResponse{"stale_snapshot", "Inventory snapshot expired; refresh and select devices again", correlationID()})
					return
				}
				if err != nil {
					fail(w, network.ErrForbidden)
					return
				}
				instance, err := netboxService.Instance(r.Context(), u, snap.InstanceID)
				if err != nil {
					fail(w, network.ErrForbidden)
					return
				}
				if rev.Graph.NetBoxInstanceID != "" && rev.Graph.NetBoxInstanceID != instance.ID {
					writeJSON(w, 409, errorResponse{"wrong_netbox", "This network profile is bound to a different NetBox connection", correlationID()})
					return
				}
				devices := map[int64]string{}
				for _, d := range snap.Devices {
					devices[d.ID] = d.Name
				}
				selected := map[int64]bool{}
				hosts := []network.HostBinding{}
				for _, id := range selection.DeviceIDs {
					key, found := devices[id]
					if !found {
						fail(w, network.ErrInvalid)
						return
					}
					if alias, exists := in.Aliases[strconv.FormatInt(id, 10)]; exists {
						key = alias
					}
					hosts = append(hosts, network.HostBinding{DeviceID: id, Key: key})
					selected[id] = true
				}
				for key := range in.Aliases {
					id, err := strconv.ParseInt(key, 10, 64)
					if err != nil || strconv.FormatInt(id, 10) != key || !selected[id] {
						fail(w, network.ErrInvalid)
						return
					}
				}
				groups := []string{}
				for _, n := range rev.Graph.Networks {
					groups = append(groups, n.AllocationGroup)
				}
				parsed, err := network.ParseAllocation([]byte(in.Content), hosts, groups)
				if err != nil {
					writeJSON(w, 400, errorResponse{"invalid_allocation", "Allocation data is invalid, ambiguous, or missing selected entries", correlationID()})
					return
				}
				resolved, issues := network.Resolve(rev.Graph, parsed)
				// Recheck selection and membership after processing before disclosing preview.
				if _, err = inventoryService.Snapshot(r.Context(), u, selection.SnapshotID); err != nil {
					fail(w, network.ErrForbidden)
					return
				}
				var saved any
				if save {
					if len(issues) > 0 {
						writeJSON(w, 422, map[string]any{"code": "invalid_allocation", "message": "Fix allocation errors before saving", "issues": issues, "correlation_id": correlationID()})
						return
					}
					item, err := imports.Save(r.Context(), u, selection, instance, p.ID, in.Revision, hosts, resolved, parsed.Hash, parsed.ParserVersion)
					if err != nil {
						fail(w, err)
						return
					}
					saved = item
				}
				writeJSON(w, 200, map[string]any{"assignments": resolved, "issues": issues, "ignored_hosts": parsed.IgnoredHosts, "hash": parsed.Hash, "parser_version": parsed.ParserVersion, "netbox_conflicts_checked": false, "persisted": save, "import": saved})
			}
		}
		mux.HandleFunc("POST /api/v1/network-profiles/{id}/allocation-preview", handleAllocation(false))
		mux.HandleFunc("POST /api/v1/network-profiles/{id}/allocation-imports", handleAllocation(true))
		mux.HandleFunc("GET /api/v1/allocation-imports", func(w http.ResponseWriter, r *http.Request) {
			u, ok := current(w, r, false)
			if !ok {
				return
			}
			items, err := imports.List(r.Context(), u, r.URL.Query().Get("selection_id"))
			if errors.Is(err, inventory.ErrStale) {
				writeJSON(w, 409, errorResponse{"stale_snapshot", "Inventory snapshot expired; refresh and select devices again", correlationID()})
				return
			}
			if err != nil {
				fail(w, network.ErrForbidden)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, 200, items)
		})
		handleNetworkAudit := func(save bool) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				if !origin(w, r) {
					return
				}
				u, ok := current(w, r, true)
				if !ok {
					return
				}
				if save && !auth.Allowed(u, auth.Operate) {
					fail(w, network.ErrForbidden)
					return
				}
				var in struct {
					SelectionID string `json:"selection_id"`
					ImportID    string `json:"import_id"`
					DeviceID    int64  `json:"device_id"`
				}
				if !decodeJSON(w, r, &in) {
					return
				}
				items, err := imports.List(r.Context(), u, in.SelectionID)
				if err != nil {
					fail(w, err)
					return
				}
				var selected *network.SavedImport
				for i := range items {
					if items[i].ID == in.ImportID && items[i].ProfileID == r.PathValue("id") {
						selected = &items[i]
						break
					}
				}
				if selected == nil {
					fail(w, network.ErrForbidden)
					return
				}
				rev, err := s.Revision(r.Context(), u, selected.ProfileID, selected.Revision)
				if err != nil {
					fail(w, err)
					return
				}
				selection, err := inventoryService.Selection(r.Context(), u, in.SelectionID)
				if err != nil {
					fail(w, err)
					return
				}
				snap, err := inventoryService.Snapshot(r.Context(), u, selection.SnapshotID)
				if err != nil {
					fail(w, err)
					return
				}
				if rev.Graph.NetBoxInstanceID != "" && rev.Graph.NetBoxInstanceID != snap.InstanceID {
					writeJSON(w, 409, errorResponse{"wrong_netbox", "This network profile is bound to a different NetBox connection", correlationID()})
					return
				}
				interfaces, err := inventoryService.AuditInterfaces(r.Context(), u, in.SelectionID, in.DeviceID)
				if err != nil {
					fail(w, err)
					return
				}
				addresses, err := inventoryService.AuditAddresses(r.Context(), u, in.SelectionID, in.DeviceID)
				if err != nil {
					fail(w, err)
					return
				}
				vlanIDs := []int64{}
				seenVLANs := map[int64]bool{}
				for _, node := range rev.Graph.Nodes {
					if node.NetBoxVLANID > 0 && !seenVLANs[node.NetBoxVLANID] {
						vlanIDs = append(vlanIDs, node.NetBoxVLANID)
						seenVLANs[node.NetBoxVLANID] = true
					}
				}
				var vlanEvidence []netbox.VLAN
				if len(vlanIDs) > 0 && rev.Graph.NetBoxInstanceID != "" {
					vlanEvidence, err = netboxService.AuditVLANs(r.Context(), u, snap.InstanceID, vlanIDs)
					if err != nil {
						fail(w, err)
						return
					}
					if _, err = inventoryService.Selection(r.Context(), u, in.SelectionID); err != nil {
						fail(w, err)
						return
					}
					if _, err = inventoryService.Snapshot(r.Context(), u, selection.SnapshotID); err != nil {
						fail(w, err)
						return
					}
				}
				result := network.AuditDevice(rev.Graph, *selected, in.DeviceID, interfaces, addresses, vlanEvidence)
				// Look for positive collision evidence on a bounded subset of the
				// selected device's addresses. Missing results never prove safety.
				hosts := []netip.Addr{}
				seenHosts := map[netip.Addr]bool{}
				for _, address := range selected.Addresses {
					if address.DeviceID != in.DeviceID || len(hosts) >= 32 {
						continue
					}
					host, parseErr := netip.ParseAddr(address.Address)
					if parseErr == nil && !host.Is4In6() && host.Zone() == "" && !seenHosts[host] {
						seenHosts[host] = true
						hosts = append(hosts, host)
					}
				}
				if len(hosts) > 0 {
					candidates, lookupErr := netbox.WaitForLocalBudget(r.Context(), func() ([]netbox.ConflictAddress, error) {
						return netboxService.AddressCandidates(r.Context(), u, snap.InstanceID, hosts)
					})
					if lookupErr != nil {
						fail(w, lookupErr)
						return
					}
					if _, err = inventoryService.Selection(r.Context(), u, in.SelectionID); err != nil {
						fail(w, err)
						return
					}
					if _, err = inventoryService.Snapshot(r.Context(), u, selection.SnapshotID); err != nil {
						fail(w, err)
						return
					}
					network.AddVisibleConflicts(&result, rev.Graph, *selected, in.DeviceID, interfaces, candidates)
				}
				w.Header().Set("Cache-Control", "no-store")
				if !save {
					writeJSON(w, 200, result)
					return
				}
				selection, err = inventoryService.Selection(r.Context(), u, in.SelectionID)
				if err != nil {
					fail(w, err)
					return
				}
				item, err := imports.SaveAudit(r.Context(), u, selection, in.ImportID, in.DeviceID, result)
				if err != nil {
					fail(w, err)
					return
				}
				writeJSON(w, 201, item)
			}
		}
		mux.HandleFunc("POST /api/v1/network-profiles/{id}/audit-preview", handleNetworkAudit(false))
		mux.HandleFunc("POST /api/v1/network-profiles/{id}/audits", handleNetworkAudit(true))
		mux.HandleFunc("GET /api/v1/network-audits", func(w http.ResponseWriter, r *http.Request) {
			u, ok := current(w, r, false)
			if !ok {
				return
			}
			items, err := imports.ListAudits(r.Context(), u, r.URL.Query().Get("selection_id"))
			if err != nil {
				fail(w, err)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, 200, items)
		})
		mux.HandleFunc("GET /api/v1/network-audits/{id}", func(w http.ResponseWriter, r *http.Request) {
			u, ok := current(w, r, false)
			if !ok {
				return
			}
			item, err := imports.GetAudit(r.Context(), u, r.URL.Query().Get("selection_id"), r.PathValue("id"))
			if err != nil {
				fail(w, err)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, 200, item)
		})
	}
}

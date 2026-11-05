package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"forge/internal/audit"
	"forge/internal/auth"
	"forge/internal/bios"
	"forge/internal/compliance"
	"forge/internal/inspection"
	"forge/internal/inventory"
	"forge/internal/netbox"
	"forge/internal/network"
	"forge/internal/plans"
)

func mountCombinedAudits(mux *http.ServeMux, is *inspection.Service, current func(http.ResponseWriter, *http.Request, bool) (auth.User, bool), origin func(http.ResponseWriter, *http.Request) bool, logger *slog.Logger) {
	hw := &compliance.Service{DB: is.DB, Inspections: is, Inventory: is.Inventory}
	ns := &network.ImportService{DB: is.DB, Inventory: is.Inventory, NetBox: is.NetBox}
	bs := &bios.Service{DB: is.DB, Auth: is.Auth, Inspections: is}
	svc := &audit.Service{DB: is.DB, Hardware: hw, Network: ns, BIOS: bs, Inspections: is}
	investigations := &plans.InvestigationService{DB: is.DB, Audits: svc}
	fail := func(w http.ResponseWriter, err error) {
		var rate *netbox.RateLimitError
		switch {
		case errors.Is(err, audit.ErrForbidden), errors.Is(err, plans.ErrForbidden), errors.Is(err, compliance.ErrForbidden), errors.Is(err, network.ErrForbidden), errors.Is(err, bios.ErrForbidden), errors.Is(err, inventory.ErrNotVisible), errors.Is(err, inspection.ErrForbidden), errors.Is(err, netbox.ErrForbidden):
			authError(w, auth.ErrForbidden, logger)
		case errors.Is(err, audit.ErrInvalid):
			writeJSON(w, 400, errorResponse{"invalid_audit_inputs", "Choose valid saved checks for the same device and NetBox connection", correlationID()})
		case errors.Is(err, plans.ErrInvalid):
			writeJSON(w, 400, errorResponse{"invalid_investigation", "Choose valid investigation task IDs", correlationID()})
		case errors.Is(err, plans.ErrConflict):
			writeJSON(w, 409, errorResponse{"investigation_conflict", "The investigation changed or is no longer visible; reload it", correlationID()})
		case errors.Is(err, inspection.ErrInvalid):
			authError(w, auth.ErrInvalidInput, logger)
		case errors.Is(err, inventory.ErrStale):
			writeJSON(w, 409, errorResponse{"stale_input", "Refresh and reselect the devices before opening the audit", correlationID()})
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
	mux.HandleFunc("POST /api/v1/audits/{id}/investigations", func(w http.ResponseWriter, r *http.Request) {
		if !origin(w, r) {
			return
		}
		actor, ok := current(w, r, true)
		if !ok {
			return
		}
		var in struct {
			SelectionID string `json:"selection_id"`
		}
		if !decodeJSON(w, r, &in) {
			return
		}
		item, err := investigations.Create(r.Context(), actor, r.PathValue("id"), in.SelectionID)
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 201, item)
	})
	mux.HandleFunc("GET /api/v1/audits/{id}/investigations", func(w http.ResponseWriter, r *http.Request) {
		actor, ok := current(w, r, false)
		if !ok {
			return
		}
		items, err := investigations.List(r.Context(), actor, r.PathValue("id"), r.URL.Query().Get("selection_id"))
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, items)
	})
	mux.HandleFunc("GET /api/v1/investigations/{id}", func(w http.ResponseWriter, r *http.Request) {
		actor, ok := current(w, r, false)
		if !ok {
			return
		}
		item, err := investigations.Get(r.Context(), actor, r.PathValue("id"), r.URL.Query().Get("selection_id"))
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, item)
	})
	mux.HandleFunc("PUT /api/v1/investigations/{id}/progress", func(w http.ResponseWriter, r *http.Request) {
		if !origin(w, r) {
			return
		}
		actor, ok := current(w, r, true)
		if !ok {
			return
		}
		var in struct {
			SelectionID string   `json:"selection_id"`
			RowVersion  int64    `json:"row_version"`
			Completed   []string `json:"completed"`
		}
		if !decodeJSON(w, r, &in) {
			return
		}
		item, err := investigations.UpdateProgress(r.Context(), actor, r.PathValue("id"), in.SelectionID, in.RowVersion, in.Completed)
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, item)
	})
	mux.HandleFunc("POST /api/v1/audits", func(w http.ResponseWriter, r *http.Request) {
		if !origin(w, r) {
			return
		}
		actor, ok := current(w, r, true)
		if !ok {
			return
		}
		var in audit.Request
		if !decodeJSON(w, r, &in) {
			return
		}
		result, err := svc.Run(r.Context(), actor, in)
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 201, result)
	})
	mux.HandleFunc("GET /api/v1/audits", func(w http.ResponseWriter, r *http.Request) {
		actor, ok := current(w, r, false)
		if !ok {
			return
		}
		items, err := svc.List(r.Context(), actor)
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, items)
	})
	mux.HandleFunc("GET /api/v1/audits/{id}", func(w http.ResponseWriter, r *http.Request) {
		actor, ok := current(w, r, false)
		if !ok {
			return
		}
		result, err := svc.Get(r.Context(), actor, r.PathValue("id"), r.URL.Query().Get("selection_id"))
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, result)
	})
}

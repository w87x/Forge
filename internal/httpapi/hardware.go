package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"forge/internal/auth"
	"forge/internal/compliance"
	"forge/internal/inspection"
	"forge/internal/inventory"
	"forge/internal/netbox"
)

func mountHardwareProfiles(mux *http.ServeMux, inspections *inspection.Service, current func(http.ResponseWriter, *http.Request, bool) (auth.User, bool), origin func(http.ResponseWriter, *http.Request) bool, logger *slog.Logger) {
	s := &compliance.Service{DB: inspections.DB, Inspections: inspections, Inventory: inspections.Inventory}
	fail := func(w http.ResponseWriter, err error) {
		var rate *netbox.RateLimitError
		switch {
		case errors.Is(err, compliance.ErrForbidden), errors.Is(err, inspection.ErrForbidden), errors.Is(err, inventory.ErrNotVisible), errors.Is(err, netbox.ErrForbidden):
			authError(w, auth.ErrForbidden, logger)
		case errors.Is(err, compliance.ErrInvalid), errors.Is(err, inspection.ErrInvalid):
			authError(w, auth.ErrInvalidInput, logger)
		case errors.Is(err, compliance.ErrConflict), errors.Is(err, inventory.ErrStale):
			writeJSON(w, 409, errorResponse{"stale_input", "The profile or inventory changed; refresh and try again", correlationID()})
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
	mux.HandleFunc("GET /api/v1/hardware-profiles", func(w http.ResponseWriter, r *http.Request) {
		a, ok := current(w, r, false)
		if !ok {
			return
		}
		items, err := s.List(r.Context(), a)
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, items)
	})
	mux.HandleFunc("POST /api/v1/hardware-profiles", func(w http.ResponseWriter, r *http.Request) {
		if !origin(w, r) {
			return
		}
		a, ok := current(w, r, true)
		if !ok {
			return
		}
		var in struct {
			Name  string              `json:"name"`
			Draft compliance.Hardware `json:"draft"`
		}
		if !decodeJSON(w, r, &in) {
			return
		}
		p, err := s.Create(r.Context(), a, in.Name, in.Draft)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 201, p)
	})
	mux.HandleFunc("PUT /api/v1/hardware-profiles/{id}/draft", func(w http.ResponseWriter, r *http.Request) {
		if !origin(w, r) {
			return
		}
		a, ok := current(w, r, true)
		if !ok {
			return
		}
		var in struct {
			RowVersion int                 `json:"row_version"`
			Draft      compliance.Hardware `json:"draft"`
		}
		if !decodeJSON(w, r, &in) {
			return
		}
		p, err := s.Update(r.Context(), a, r.PathValue("id"), in.RowVersion, in.Draft)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, p)
	})
	mux.HandleFunc("POST /api/v1/hardware-profiles/{id}/publish", func(w http.ResponseWriter, r *http.Request) {
		if !origin(w, r) {
			return
		}
		a, ok := current(w, r, true)
		if !ok {
			return
		}
		var in struct {
			RowVersion int `json:"row_version"`
		}
		if !decodeJSON(w, r, &in) {
			return
		}
		rev, err := s.Publish(r.Context(), a, r.PathValue("id"), in.RowVersion)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 201, rev)
	})
	mux.HandleFunc("GET /api/v1/hardware-profiles/{id}/revisions/{revision}", func(w http.ResponseWriter, r *http.Request) {
		a, ok := current(w, r, false)
		if !ok {
			return
		}
		n, err := strconv.Atoi(r.PathValue("revision"))
		if err != nil || n < 1 {
			fail(w, compliance.ErrInvalid)
			return
		}
		rev, err := s.Revision(r.Context(), a, r.PathValue("id"), n)
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, rev)
	})
	mux.HandleFunc("POST /api/v1/hardware-profiles/{id}/preview", func(w http.ResponseWriter, r *http.Request) {
		if !origin(w, r) {
			return
		}
		a, ok := current(w, r, true)
		if !ok {
			return
		}
		var in struct {
			Revision int    `json:"revision"`
			JobID    string `json:"job_id"`
		}
		if !decodeJSON(w, r, &in) {
			return
		}
		if in.Revision < 1 {
			fail(w, compliance.ErrInvalid)
			return
		}
		result, err := s.Preview(r.Context(), a, r.PathValue("id"), in.Revision, in.JobID)
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, result)
	})
	mux.HandleFunc("POST /api/v1/hardware-profiles/{id}/audits", func(w http.ResponseWriter, r *http.Request) {
		if !origin(w, r) {
			return
		}
		a, ok := current(w, r, true)
		if !ok {
			return
		}
		var in struct {
			Revision int    `json:"revision"`
			JobID    string `json:"job_id"`
		}
		if !decodeJSON(w, r, &in) {
			return
		}
		if in.Revision < 1 {
			fail(w, compliance.ErrInvalid)
			return
		}
		item, err := s.RunAudit(r.Context(), a, r.PathValue("id"), in.Revision, in.JobID)
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 201, item)
	})
	mux.HandleFunc("GET /api/v1/hardware-audits", func(w http.ResponseWriter, r *http.Request) {
		a, ok := current(w, r, false)
		if !ok {
			return
		}
		items, err := s.ListAudits(r.Context(), a)
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, items)
	})
	mux.HandleFunc("GET /api/v1/hardware-audits/{id}", func(w http.ResponseWriter, r *http.Request) {
		a, ok := current(w, r, false)
		if !ok {
			return
		}
		item, err := s.GetAudit(r.Context(), a, r.PathValue("id"))
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, item)
	})
}

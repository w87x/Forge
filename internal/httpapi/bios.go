package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"forge/internal/auth"
	"forge/internal/bios"
	"forge/internal/inspection"
	"forge/internal/inventory"
	"forge/internal/netbox"
)

func mountBIOSProfiles(mux *http.ServeMux, inspections *inspection.Service, current func(http.ResponseWriter, *http.Request, bool) (auth.User, bool), origin func(http.ResponseWriter, *http.Request) bool, logger *slog.Logger) {
	s := &bios.Service{DB: inspections.DB, Auth: inspections.Auth, Inspections: inspections}
	fail := func(w http.ResponseWriter, err error) {
		var rate *netbox.RateLimitError
		switch {
		case errors.Is(err, bios.ErrForbidden), errors.Is(err, inspection.ErrForbidden), errors.Is(err, inventory.ErrNotVisible), errors.Is(err, netbox.ErrForbidden):
			authError(w, auth.ErrForbidden, logger)
		case errors.Is(err, bios.ErrInvalid), errors.Is(err, bios.ErrInvalidReference), errors.Is(err, inspection.ErrInvalid):
			writeJSON(w, 400, errorResponse{"invalid_reference", "The profile or reference inspection is invalid, incomplete, or too old", correlationID()})
		case errors.Is(err, bios.ErrConflict), errors.Is(err, inventory.ErrStale):
			writeJSON(w, 409, errorResponse{"stale_input", "The profile or inventory changed; reload and try again", correlationID()})
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
	mux.HandleFunc("GET /api/v1/bios-profiles", func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("POST /api/v1/bios-profiles", func(w http.ResponseWriter, r *http.Request) {
		if !origin(w, r) {
			return
		}
		a, ok := current(w, r, true)
		if !ok {
			return
		}
		var in struct {
			Name       string   `json:"name"`
			JobID      string   `json:"job_id"`
			Attributes []string `json:"attributes"`
		}
		if !decodeJSON(w, r, &in) {
			return
		}
		p, err := s.Create(r.Context(), a, in.Name, in.JobID, in.Attributes)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 201, p)
	})
	mux.HandleFunc("POST /api/v1/bios-profiles/{id}/variants", func(w http.ResponseWriter, r *http.Request) {
		if !origin(w, r) {
			return
		}
		a, ok := current(w, r, true)
		if !ok {
			return
		}
		var in struct {
			RowVersion int      `json:"row_version"`
			JobID      string   `json:"job_id"`
			Attributes []string `json:"attributes"`
		}
		if !decodeJSON(w, r, &in) {
			return
		}
		p, err := s.AddVariant(r.Context(), a, r.PathValue("id"), in.RowVersion, in.JobID, in.Attributes)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, p)
	})
	mux.HandleFunc("POST /api/v1/bios-profiles/{id}/publish", func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("DELETE /api/v1/bios-profiles/{id}/variants", func(w http.ResponseWriter, r *http.Request) {
		if !origin(w, r) {
			return
		}
		a, ok := current(w, r, true)
		if !ok {
			return
		}
		var in struct {
			RowVersion int  `json:"row_version"`
			Index      *int `json:"index"`
		}
		if !decodeJSON(w, r, &in) {
			return
		}
		if in.Index == nil {
			fail(w, bios.ErrInvalid)
			return
		}
		p, err := s.RemoveVariant(r.Context(), a, r.PathValue("id"), in.RowVersion, *in.Index)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, p)
	})
	mux.HandleFunc("GET /api/v1/bios-profiles/{id}/revisions/{revision}", func(w http.ResponseWriter, r *http.Request) {
		a, ok := current(w, r, false)
		if !ok {
			return
		}
		n, err := strconv.Atoi(r.PathValue("revision"))
		if err != nil || n < 1 {
			fail(w, bios.ErrInvalid)
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
	mux.HandleFunc("POST /api/v1/bios-profiles/{id}/compare", func(w http.ResponseWriter, r *http.Request) {
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
			fail(w, bios.ErrInvalid)
			return
		}
		result, err := s.CompareJob(r.Context(), a, r.PathValue("id"), in.Revision, in.JobID)
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, result)
	})
}

package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"forge/internal/auth"
	"forge/internal/inspection"
	"forge/internal/inventory"
	"forge/internal/jobs"
	"forge/internal/netbox"
	"forge/internal/profiles"
	"forge/internal/redfish"
)

func mountInspections(mux *http.ServeMux, service *inspection.Service, current func(http.ResponseWriter, *http.Request, bool) (auth.User, bool), origin func(http.ResponseWriter, *http.Request) bool, logger *slog.Logger) {
	writeError := func(w http.ResponseWriter, err error) {
		var rate *netbox.RateLimitError
		switch {
		case errors.Is(err, inspection.ErrForbidden), errors.Is(err, inventory.ErrNotVisible), errors.Is(err, netbox.ErrForbidden), errors.Is(err, profiles.ErrForbidden):
			authError(w, auth.ErrForbidden, logger)
		case errors.Is(err, inspection.ErrInvalid), errors.Is(err, profiles.ErrInvalid):
			authError(w, auth.ErrInvalidInput, logger)
		case errors.Is(err, redfish.ErrNotAllowed):
			writeJSON(w, 403, errorResponse{"bmc_not_allowed", "BMC address is not in a configured allowed network", correlationID()})
		case errors.Is(err, inspection.ErrUnsupported):
			writeJSON(w, 422, errorResponse{"unsupported", "Only explicit BMC addresses are supported for inspection", correlationID()})
		case errors.Is(err, inventory.ErrStale), errors.Is(err, jobs.ErrConflict):
			writeJSON(w, 409, errorResponse{"stale_input", "Inventory or inspection inputs changed; refresh and try again", correlationID()})
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
	mux.HandleFunc("POST /api/v1/inspections", func(w http.ResponseWriter, r *http.Request) {
		if !origin(w, r) {
			return
		}
		actor, ok := current(w, r, true)
		if !ok {
			return
		}
		var input inspection.Request
		if !decodeJSON(w, r, &input) {
			return
		}
		job, created, err := service.Submit(r.Context(), actor, r.Header.Get("Idempotency-Key"), input)
		if err != nil {
			writeError(w, err)
			return
		}
		status := http.StatusOK
		if created {
			status = http.StatusAccepted
		}
		writeJSON(w, status, job)
	})
	mux.HandleFunc("GET /api/v1/inspections/{jobID}", func(w http.ResponseWriter, r *http.Request) {
		actor, ok := current(w, r, false)
		if !ok {
			return
		}
		record, err := service.Get(r.Context(), actor, r.PathValue("jobID"))
		if err != nil {
			writeError(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, record)
	})
}

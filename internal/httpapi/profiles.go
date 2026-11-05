package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"forge/internal/auth"
	"forge/internal/profiles"
)

func mountProfiles(mux *http.ServeMux, service *profiles.Service, current func(http.ResponseWriter, *http.Request, bool) (auth.User, bool), origin func(http.ResponseWriter, *http.Request) bool, logger *slog.Logger) {
	profileError := func(w http.ResponseWriter, err error) {
		switch {
		case errors.Is(err, profiles.ErrForbidden):
			authError(w, auth.ErrForbidden, logger)
		case errors.Is(err, profiles.ErrInvalid):
			authError(w, auth.ErrInvalidInput, logger)
		case errors.Is(err, profiles.ErrConflict):
			writeJSON(w, 409, errorResponse{"stale_profile", "The profile changed; reload it before saving", correlationID()})
		default:
			authError(w, err, logger)
		}
	}
	mux.HandleFunc("GET /api/v1/profiles", func(w http.ResponseWriter, r *http.Request) {
		actor, ok := current(w, r, false)
		if !ok {
			return
		}
		items, err := service.List(r.Context(), actor)
		if err != nil {
			profileError(w, err)
			return
		}
		writeJSON(w, 200, items)
	})
	mux.HandleFunc("POST /api/v1/profiles", func(w http.ResponseWriter, r *http.Request) {
		if !origin(w, r) {
			return
		}
		actor, ok := current(w, r, true)
		if !ok {
			return
		}
		var input struct {
			EnvironmentID string              `json:"environment_id"`
			Name          string              `json:"name"`
			Draft         profiles.Connection `json:"draft"`
		}
		if !decodeJSON(w, r, &input) {
			return
		}
		if input.EnvironmentID == "" {
			input.EnvironmentID = auth.SharedWorkspaceID
		}
		item, err := service.Create(r.Context(), actor, input.EnvironmentID, input.Name, input.Draft)
		if err != nil {
			profileError(w, err)
			return
		}
		writeJSON(w, 201, item)
	})
	mux.HandleFunc("GET /api/v1/profiles/{id}", func(w http.ResponseWriter, r *http.Request) {
		actor, ok := current(w, r, false)
		if !ok {
			return
		}
		item, err := service.Get(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			profileError(w, err)
			return
		}
		writeJSON(w, 200, item)
	})
	mux.HandleFunc("PUT /api/v1/profiles/{id}/draft", func(w http.ResponseWriter, r *http.Request) {
		if !origin(w, r) {
			return
		}
		actor, ok := current(w, r, true)
		if !ok {
			return
		}
		var input struct {
			RowVersion int                 `json:"row_version"`
			Draft      profiles.Connection `json:"draft"`
		}
		if !decodeJSON(w, r, &input) {
			return
		}
		item, err := service.Update(r.Context(), actor, r.PathValue("id"), input.RowVersion, input.Draft)
		if err != nil {
			profileError(w, err)
			return
		}
		writeJSON(w, 200, item)
	})
	mux.HandleFunc("POST /api/v1/profiles/{id}/publish", func(w http.ResponseWriter, r *http.Request) {
		if !origin(w, r) {
			return
		}
		actor, ok := current(w, r, true)
		if !ok {
			return
		}
		var input struct {
			RowVersion int `json:"row_version"`
		}
		if !decodeJSON(w, r, &input) {
			return
		}
		revision, err := service.Publish(r.Context(), actor, r.PathValue("id"), input.RowVersion)
		if err != nil {
			profileError(w, err)
			return
		}
		writeJSON(w, 201, revision)
	})
	mux.HandleFunc("GET /api/v1/profiles/{id}/revisions/{revision}", func(w http.ResponseWriter, r *http.Request) {
		actor, ok := current(w, r, false)
		if !ok {
			return
		}
		number, err := strconv.Atoi(r.PathValue("revision"))
		if err != nil || number < 1 {
			authError(w, auth.ErrInvalidInput, logger)
			return
		}
		revision, err := service.Revision(r.Context(), actor, r.PathValue("id"), number)
		if err != nil {
			profileError(w, err)
			return
		}
		writeJSON(w, 200, revision)
	})
	mux.HandleFunc("POST /api/v1/profiles/{id}/preview", func(w http.ResponseWriter, r *http.Request) {
		if !origin(w, r) {
			return
		}
		actor, ok := current(w, r, true)
		if !ok {
			return
		}
		var input struct {
			BMCIP          string `json:"bmc_ip"`
			DeclaredSerial string `json:"declared_serial"`
		}
		if !decodeJSON(w, r, &input) {
			return
		}
		p, err := service.Get(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			profileError(w, err)
			return
		}
		settings := p.Published
		if p.Draft != nil {
			settings = p.Draft
		}
		if settings == nil || settings.Validate() != nil {
			profileError(w, profiles.ErrInvalid)
			return
		}
		value, err := settings.DeviceValue(input.BMCIP, input.DeclaredSerial)
		if err != nil {
			profileError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"mode": settings.PasswordMode, "device_value": value, "prefix_present": settings.PrefixSecretID != "", "suffix_present": settings.SuffixSecretID != ""})
	})
}

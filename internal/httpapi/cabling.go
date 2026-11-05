package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"forge/internal/auth"
	"forge/internal/cabling"
)

func mountCablingProfiles(mux *http.ServeMux, a *auth.Service, current func(http.ResponseWriter, *http.Request, bool) (auth.User, bool), origin func(http.ResponseWriter, *http.Request) bool, logger *slog.Logger) {
	s := &cabling.Service{DB: a.DB}
	fail := func(w http.ResponseWriter, err error) {
		switch {
		case errors.Is(err, cabling.ErrForbidden):
			authError(w, auth.ErrForbidden, logger)
		case errors.Is(err, cabling.ErrInvalid):
			writeJSON(w, 400, errorResponse{"invalid_cabling_profile", err.Error(), correlationID()})
		case errors.Is(err, cabling.ErrConflict):
			writeJSON(w, 409, errorResponse{"stale_profile", "The profile changed or its NetBox connection is unavailable", correlationID()})
		default:
			authError(w, err, logger)
		}
	}
	mux.HandleFunc("GET /api/v1/cabling-profiles", func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("POST /api/v1/cabling-profiles", func(w http.ResponseWriter, r *http.Request) {
		if !origin(w, r) {
			return
		}
		u, ok := current(w, r, true)
		if !ok {
			return
		}
		var in struct {
			Name string `json:"name"`
		}
		if !decodeJSON(w, r, &in) {
			return
		}
		p, err := s.Create(r.Context(), u, in.Name)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 201, p)
	})
	mux.HandleFunc("PUT /api/v1/cabling-profiles/{id}/draft", func(w http.ResponseWriter, r *http.Request) {
		if !origin(w, r) {
			return
		}
		u, ok := current(w, r, true)
		if !ok {
			return
		}
		var in struct {
			RowVersion int             `json:"row_version"`
			Profile    cabling.Profile `json:"profile"`
		}
		if !decodeJSON(w, r, &in) {
			return
		}
		p, err := s.Update(r.Context(), u, r.PathValue("id"), in.RowVersion, in.Profile)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, p)
	})
	mux.HandleFunc("POST /api/v1/cabling-profiles/{id}/publish", func(w http.ResponseWriter, r *http.Request) {
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
		p, err := s.Publish(r.Context(), u, r.PathValue("id"), in.RowVersion)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 201, p)
	})
	mux.HandleFunc("GET /api/v1/cabling-profiles/{id}/revisions/{revision}", func(w http.ResponseWriter, r *http.Request) {
		u, ok := current(w, r, false)
		if !ok {
			return
		}
		n, err := strconv.Atoi(r.PathValue("revision"))
		if err != nil || n <= 0 {
			fail(w, cabling.ErrInvalid)
			return
		}
		p, err := s.Revision(r.Context(), u, r.PathValue("id"), n)
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, p)
	})
}

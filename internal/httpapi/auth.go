package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"forge/internal/auth"
	"forge/internal/inspection"
	"forge/internal/inventory"
	"forge/internal/jobs"
	"forge/internal/netbox"
	"forge/internal/profiles"
	"forge/internal/secrets"
	"forge/internal/simulation"
)

type attempt struct {
	count int
	until time.Time
}
type limiter struct {
	mu      sync.Mutex
	entries map[string]attempt
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.entries) > 10000 {
		for k, v := range l.entries {
			if now.After(v.until) {
				delete(l.entries, k)
			}
		}
	}
	if len(l.entries) > 20000 {
		return false
	}
	a := l.entries[key]
	if now.After(a.until) {
		a = attempt{until: now.Add(time.Minute)}
	}
	a.count++
	l.entries[key] = a
	return a.count <= 10
}
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && strings.EqualFold(u.Host, r.Host)
}
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	return decodeJSONLimit(w, r, v, 16<<10)
}
func decodeJSONLimit(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		http.Error(w, "expected application/json", http.StatusUnsupportedMediaType)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return false
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return false
	}
	return true
}
func authError(w http.ResponseWriter, err error, logger *slog.Logger) {
	id := correlationID()
	w.Header().Set("X-Correlation-ID", id)
	status, code, message := http.StatusInternalServerError, "internal_error", "Request could not be completed"
	switch {
	case errors.Is(err, auth.ErrUnauthorized):
		status, code, message = 401, "unauthorized", "Invalid credentials or expired session"
	case errors.Is(err, auth.ErrForbidden):
		status, code, message = 403, "forbidden", "Operation not permitted"
	case errors.Is(err, auth.ErrAlreadySetup):
		status, code, message = 409, "already_setup", "Initial setup is complete"
	case errors.Is(err, auth.ErrInvalidInput):
		status, code, message = 400, "invalid_input", "Invalid input"
	default:
		logger.Error("authentication request failed", "correlation_id", id, "error", err)
	}
	writeJSON(w, status, errorResponse{code, message, id})
}

func mountAuth(mux *http.ServeMux, service *auth.Service, vault *secrets.Vault, jobStore *jobs.Store, netboxService *netbox.Service, inventoryService *inventory.Service, profileService *profiles.Service, inspectionService *inspection.Service, simulated bool, secure bool, logger *slog.Logger) {
	limits := &limiter{entries: make(map[string]attempt)}
	requireOrigin := func(w http.ResponseWriter, r *http.Request) bool {
		if !sameOrigin(r) {
			http.Error(w, "invalid origin", http.StatusForbidden)
			return false
		}
		return true
	}
	requireLimit := func(w http.ResponseWriter, r *http.Request) bool {
		if !limits.allow(clientIP(r)) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many attempts", http.StatusTooManyRequests)
			return false
		}
		return true
	}
	current := func(w http.ResponseWriter, r *http.Request, csrf bool) (auth.User, bool) {
		cookie, err := r.Cookie("forge_session")
		if err != nil {
			authError(w, auth.ErrUnauthorized, logger)
			return auth.User{}, false
		}
		u, err := service.SessionUser(r.Context(), cookie.Value, r.Header.Get("X-CSRF-Token"), csrf)
		if err != nil {
			authError(w, err, logger)
			return auth.User{}, false
		}
		return u, true
	}
	if profileService != nil {
		mountProfiles(mux, profileService, current, requireOrigin, logger)
		mountNetworkProfiles(mux, service, inventoryService, netboxService, current, requireOrigin, logger)
		mountCablingProfiles(mux, service, current, requireOrigin, logger)
	}
	if inspectionService != nil {
		mountInspections(mux, inspectionService, current, requireOrigin, logger)
		mountBIOSProfiles(mux, inspectionService, current, requireOrigin, logger)
		mountHardwareProfiles(mux, inspectionService, current, requireOrigin, logger)
		mountCombinedAudits(mux, inspectionService, current, requireOrigin, logger)
	}
	mux.HandleFunc("GET /api/v1/auth/bootstrap-status", func(w http.ResponseWriter, r *http.Request) {
		needed, err := service.SetupNeeded(r.Context())
		if err != nil {
			authError(w, err, logger)
			return
		}
		writeJSON(w, 200, map[string]bool{"setup_needed": needed})
	})
	mux.HandleFunc("POST /api/v1/auth/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		if !requireOrigin(w, r) || !requireLimit(w, r) {
			return
		}
		var input struct {
			Token    string `json:"token"`
			Username string `json:"username"`
		}
		if !decodeJSON(w, r, &input) {
			return
		}
		u, token, err := service.Bootstrap(r.Context(), input.Token, input.Username)
		if err != nil {
			authError(w, err, logger)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 201, map[string]any{"user": u, "token": token})
	})
	mux.HandleFunc("POST /api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if !requireOrigin(w, r) || !requireLimit(w, r) {
			return
		}
		var input struct {
			Token string `json:"token"`
		}
		if !decodeJSON(w, r, &input) {
			return
		}
		session, err := service.Login(r.Context(), input.Token)
		if err != nil {
			authError(w, err, logger)
			return
		}
		if old, err := r.Cookie("forge_session"); err == nil {
			_ = service.Logout(r.Context(), old.Value)
		}
		for _, c := range []*http.Cookie{{Name: "forge_session", Value: session.Token, HttpOnly: true}, {Name: "forge_csrf", Value: session.CSRF}} {
			c.Path = "/"
			c.Secure = secure
			c.SameSite = http.SameSiteStrictMode
			c.Expires = session.Expires
			http.SetCookie(w, c)
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, map[string]any{"user": session.User})
	})
	mux.HandleFunc("GET /api/v1/me", func(w http.ResponseWriter, r *http.Request) {
		u, ok := current(w, r, false)
		if !ok {
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, u)
	})
	mux.HandleFunc("POST /api/v1/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		if !requireOrigin(w, r) {
			return
		}
		if _, ok := current(w, r, true); !ok {
			return
		}
		cookie, _ := r.Cookie("forge_session")
		if err := service.Logout(r.Context(), cookie.Value); err != nil {
			authError(w, err, logger)
			return
		}
		for _, name := range []string{"forge_session", "forge_csrf"} {
			http.SetCookie(w, &http.Cookie{Name: name, Path: "/", MaxAge: -1, Secure: secure, HttpOnly: name == "forge_session", SameSite: http.SameSiteStrictMode})
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		if !requireOrigin(w, r) {
			return
		}
		actor, ok := current(w, r, true)
		if !ok {
			return
		}
		var input struct {
			Username string    `json:"username"`
			Role     auth.Role `json:"role"`
		}
		if !decodeJSON(w, r, &input) {
			return
		}
		u, token, err := service.CreateUser(r.Context(), actor, input.Username, input.Role)
		if err != nil {
			authError(w, err, logger)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 201, map[string]any{"user": u, "token": token})
	})
	mux.HandleFunc("GET /api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		actor, ok := current(w, r, false)
		if !ok {
			return
		}
		users, err := service.Users(r.Context(), actor)
		if err != nil {
			authError(w, err, logger)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, users)
	})
	mux.HandleFunc("POST /api/v1/users/{id}/revoke-tokens", func(w http.ResponseWriter, r *http.Request) {
		if !requireOrigin(w, r) {
			return
		}
		actor, ok := current(w, r, true)
		if !ok {
			return
		}
		if err := service.RevokeUserTokens(r.Context(), actor, r.PathValue("id")); err != nil {
			authError(w, err, logger)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /api/v1/users/{id}/tokens", func(w http.ResponseWriter, r *http.Request) {
		if !requireOrigin(w, r) {
			return
		}
		actor, ok := current(w, r, true)
		if !ok {
			return
		}
		token, err := service.IssueToken(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			authError(w, err, logger)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 201, map[string]string{"token": token})
	})
	mux.HandleFunc("GET /api/v1/environments", func(w http.ResponseWriter, r *http.Request) {
		actor, ok := current(w, r, false)
		if !ok {
			return
		}
		items, err := service.Environments(r.Context(), actor)
		if err != nil {
			authError(w, err, logger)
			return
		}
		writeJSON(w, 200, items)
	})
	mux.HandleFunc("POST /api/v1/environments", func(w http.ResponseWriter, r *http.Request) {
		if !requireOrigin(w, r) {
			return
		}
		actor, ok := current(w, r, true)
		if !ok {
			return
		}
		var input struct {
			Name string `json:"name"`
		}
		if !decodeJSON(w, r, &input) {
			return
		}
		item, err := service.CreateEnvironment(r.Context(), actor, input.Name)
		if err != nil {
			authError(w, err, logger)
			return
		}
		writeJSON(w, 201, item)
	})
	mux.HandleFunc("POST /api/v1/environments/{id}/members", func(w http.ResponseWriter, r *http.Request) {
		if !requireOrigin(w, r) {
			return
		}
		actor, ok := current(w, r, true)
		if !ok {
			return
		}
		var input struct {
			UserID string `json:"user_id"`
		}
		if !decodeJSON(w, r, &input) {
			return
		}
		if err := service.AddEnvironmentMember(r.Context(), actor, r.PathValue("id"), input.UserID); err != nil {
			authError(w, err, logger)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	if netboxService != nil {
		netboxError := func(w http.ResponseWriter, err error) {
			var rate *netbox.RateLimitError
			switch {
			case errors.Is(err, netbox.ErrForbidden):
				authError(w, auth.ErrForbidden, logger)
			case errors.Is(err, netbox.ErrInvalid):
				authError(w, auth.ErrInvalidInput, logger)
			case errors.Is(err, netbox.ErrDuplicateCredential):
				writeJSON(w, 409, errorResponse{"duplicate_credential", "This NetBox key is already assigned to another user", correlationID()})
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
			case errors.Is(err, netbox.ErrConnectionsDisabled):
				writeJSON(w, 403, errorResponse{"connection_disabled", "NetBox connections are disabled in simulation", correlationID()})
			case errors.Is(err, netbox.ErrHostNotAllowed):
				writeJSON(w, 403, errorResponse{"host_not_allowed", "NetBox host is not in the configured allowed host list", correlationID()})
			case errors.Is(err, netbox.ErrRemote):
				writeJSON(w, 502, errorResponse{"netbox_unavailable", "NetBox connection failed", correlationID()})
			case errors.Is(err, inventory.ErrNotVisible):
				authError(w, auth.ErrForbidden, logger)
			case errors.Is(err, inventory.ErrInvalid):
				authError(w, auth.ErrInvalidInput, logger)
			case errors.Is(err, inventory.ErrStale):
				writeJSON(w, 409, errorResponse{"stale_snapshot", "Inventory snapshot expired or its credential changed; refresh it", correlationID()})
			default:
				authError(w, err, logger)
			}
		}
		mux.HandleFunc("GET /api/v1/netbox/instances", func(w http.ResponseWriter, r *http.Request) {
			actor, ok := current(w, r, false)
			if !ok {
				return
			}
			items, err := netboxService.Instances(r.Context(), actor)
			if err != nil {
				netboxError(w, err)
				return
			}
			writeJSON(w, 200, items)
		})
		mux.HandleFunc("POST /api/v1/netbox/instances", func(w http.ResponseWriter, r *http.Request) {
			if !requireOrigin(w, r) {
				return
			}
			actor, ok := current(w, r, true)
			if !ok {
				return
			}
			var input struct {
				EnvironmentID string `json:"environment_id"`
				Name          string `json:"name"`
				BaseURL       string `json:"base_url"`
			}
			if !decodeJSON(w, r, &input) {
				return
			}
			if input.EnvironmentID == "" {
				input.EnvironmentID = auth.SharedWorkspaceID
			}
			item, err := netboxService.CreateInstance(r.Context(), actor, input.EnvironmentID, input.Name, input.BaseURL)
			if err != nil {
				netboxError(w, err)
				return
			}
			writeJSON(w, 201, item)
		})
		mux.HandleFunc("GET /api/v1/netbox/credentials", func(w http.ResponseWriter, r *http.Request) {
			actor, ok := current(w, r, false)
			if !ok {
				return
			}
			items, err := netboxService.Credentials(r.Context(), actor)
			if err != nil {
				netboxError(w, err)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, 200, items)
		})
		mux.HandleFunc("GET /api/v1/netbox/instances/{id}/vrfs", func(w http.ResponseWriter, r *http.Request) {
			actor, ok := current(w, r, false)
			if !ok {
				return
			}
			offset := 0
			if value := r.URL.Query().Get("offset"); value != "" {
				parsed, err := strconv.Atoi(value)
				if err != nil {
					netboxError(w, netbox.ErrInvalid)
					return
				}
				offset = parsed
			}
			if offset < 0 || offset > 1000000 {
				netboxError(w, netbox.ErrInvalid)
				return
			}
			page, err := netboxService.VRFs(r.Context(), actor, r.PathValue("id"), offset)
			if err != nil {
				if errors.Is(err, netbox.ErrInvalid) {
					writeJSON(w, 400, errorResponse{"netbox_key_missing", "Register your own NetBox key for this connection", correlationID()})
					return
				}
				netboxError(w, err)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, 200, page)
		})
		mux.HandleFunc("GET /api/v1/netbox/instances/{id}/vlans", func(w http.ResponseWriter, r *http.Request) {
			actor, ok := current(w, r, false)
			if !ok {
				return
			}
			offset := 0
			if value := r.URL.Query().Get("offset"); value != "" {
				parsed, err := strconv.Atoi(value)
				if err != nil {
					netboxError(w, netbox.ErrInvalid)
					return
				}
				offset = parsed
			}
			search := r.URL.Query().Get("q")
			if offset < 0 || offset > 1000000 || len(search) > 128 {
				netboxError(w, netbox.ErrInvalid)
				return
			}
			page, err := netboxService.VLANs(r.Context(), actor, r.PathValue("id"), search, offset)
			if err != nil {
				if errors.Is(err, netbox.ErrInvalid) {
					writeJSON(w, 400, errorResponse{"netbox_key_missing", "Register your own NetBox key for this connection", correlationID()})
					return
				}
				netboxError(w, err)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, 200, page)
		})
		mux.HandleFunc("PUT /api/v1/netbox/instances/{id}/credential", func(w http.ResponseWriter, r *http.Request) {
			if !requireOrigin(w, r) {
				return
			}
			actor, ok := current(w, r, true)
			if !ok {
				return
			}
			var input struct {
				Token string `json:"token"`
			}
			if !decodeJSON(w, r, &input) {
				return
			}
			item, err := netboxService.SaveCredential(r.Context(), actor, r.PathValue("id"), input.Token)
			if err != nil {
				netboxError(w, err)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, 200, item)
		})
		mux.HandleFunc("DELETE /api/v1/netbox/instances/{id}/credential", func(w http.ResponseWriter, r *http.Request) {
			if !requireOrigin(w, r) {
				return
			}
			actor, ok := current(w, r, true)
			if !ok {
				return
			}
			if err := netboxService.DeleteCredential(r.Context(), actor, r.PathValue("id")); err != nil {
				netboxError(w, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("POST /api/v1/netbox/instances/{id}/test", func(w http.ResponseWriter, r *http.Request) {
			if !requireOrigin(w, r) {
				return
			}
			actor, ok := current(w, r, true)
			if !ok {
				return
			}
			report, err := netboxService.CheckConnection(r.Context(), actor, r.PathValue("id"))
			if err != nil {
				netboxError(w, err)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, 200, report)
		})
		if inventoryService != nil {
			mux.HandleFunc("POST /api/v1/netbox/instances/{id}/inventory", func(w http.ResponseWriter, r *http.Request) {
				if !requireOrigin(w, r) {
					return
				}
				actor, ok := current(w, r, true)
				if !ok {
					return
				}
				var filter netbox.DeviceFilter
				if !decodeJSON(w, r, &filter) {
					return
				}
				snapshot, err := inventoryService.Refresh(r.Context(), actor, r.PathValue("id"), filter)
				if err != nil {
					netboxError(w, err)
					return
				}
				w.Header().Set("Cache-Control", "no-store")
				writeJSON(w, 200, snapshot)
			})
			mux.HandleFunc("GET /api/v1/inventory/snapshots/{id}", func(w http.ResponseWriter, r *http.Request) {
				actor, ok := current(w, r, false)
				if !ok {
					return
				}
				snapshot, err := inventoryService.Snapshot(r.Context(), actor, r.PathValue("id"))
				if err != nil {
					netboxError(w, err)
					return
				}
				w.Header().Set("Cache-Control", "no-store")
				writeJSON(w, 200, snapshot)
			})
			mux.HandleFunc("POST /api/v1/inventory/selections", func(w http.ResponseWriter, r *http.Request) {
				if !requireOrigin(w, r) {
					return
				}
				actor, ok := current(w, r, true)
				if !ok {
					return
				}
				var input struct {
					SnapshotID string  `json:"snapshot_id"`
					DeviceIDs  []int64 `json:"device_ids"`
				}
				if !decodeJSON(w, r, &input) {
					return
				}
				selection, err := inventoryService.Select(r.Context(), actor, input.SnapshotID, input.DeviceIDs)
				if err != nil {
					netboxError(w, err)
					return
				}
				writeJSON(w, 201, selection)
			})
			mux.HandleFunc("GET /api/v1/inventory/selections/{id}", func(w http.ResponseWriter, r *http.Request) {
				actor, ok := current(w, r, false)
				if !ok {
					return
				}
				selection, err := inventoryService.Selection(r.Context(), actor, r.PathValue("id"))
				if err != nil {
					netboxError(w, err)
					return
				}
				writeJSON(w, 200, selection)
			})
			mux.HandleFunc("POST /api/v1/inventory/selections/{id}/interfaces", func(w http.ResponseWriter, r *http.Request) {
				if !requireOrigin(w, r) {
					return
				}
				actor, ok := current(w, r, true)
				if !ok {
					return
				}
				var input struct {
					DeviceID int64 `json:"device_id"`
					Offset   int   `json:"offset"`
				}
				if !decodeJSON(w, r, &input) {
					return
				}
				page, err := inventoryService.Interfaces(r.Context(), actor, r.PathValue("id"), input.DeviceID, input.Offset)
				if err != nil {
					netboxError(w, err)
					return
				}
				w.Header().Set("Cache-Control", "no-store")
				writeJSON(w, 200, page)
			})
			mux.HandleFunc("POST /api/v1/inventory/selections/{id}/addresses", func(w http.ResponseWriter, r *http.Request) {
				if !requireOrigin(w, r) {
					return
				}
				actor, ok := current(w, r, true)
				if !ok {
					return
				}
				var input struct {
					DeviceID int64 `json:"device_id"`
					Offset   int   `json:"offset"`
				}
				if !decodeJSON(w, r, &input) {
					return
				}
				page, err := inventoryService.Addresses(r.Context(), actor, r.PathValue("id"), input.DeviceID, input.Offset)
				if err != nil {
					netboxError(w, err)
					return
				}
				w.Header().Set("Cache-Control", "no-store")
				writeJSON(w, 200, page)
			})
		}
	}
	if vault != nil {
		mux.HandleFunc("GET /api/v1/shared-secrets", func(w http.ResponseWriter, r *http.Request) {
			actor, ok := current(w, r, false)
			if !ok {
				return
			}
			items, err := vault.ListShared(r.Context(), actor)
			if err != nil {
				authError(w, auth.ErrForbidden, logger)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, 200, items)
		})
		mux.HandleFunc("POST /api/v1/shared-secrets", func(w http.ResponseWriter, r *http.Request) {
			if !requireOrigin(w, r) {
				return
			}
			actor, ok := current(w, r, true)
			if !ok {
				return
			}
			var input struct {
				Label string `json:"label"`
				Kind  string `json:"kind"`
				Value string `json:"value"`
			}
			if !decodeJSON(w, r, &input) {
				return
			}
			if len(input.Label) == 0 || len(input.Label) > 128 || len(input.Kind) == 0 || len(input.Kind) > 64 || len(input.Value) == 0 {
				authError(w, auth.ErrInvalidInput, logger)
				return
			}
			item, err := vault.Put(r.Context(), actor, secrets.Scope{EnvironmentID: auth.SharedWorkspaceID}, input.Kind, input.Label, []byte(input.Value))
			if err != nil {
				authError(w, err, logger)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, 201, item)
		})
		mux.HandleFunc("PUT /api/v1/shared-secrets/{secretID}", func(w http.ResponseWriter, r *http.Request) {
			if !requireOrigin(w, r) {
				return
			}
			actor, ok := current(w, r, true)
			if !ok {
				return
			}
			var input struct {
				Value string `json:"value"`
			}
			if !decodeJSON(w, r, &input) {
				return
			}
			if input.Value == "" {
				authError(w, auth.ErrInvalidInput, logger)
				return
			}
			if _, err := vault.SharedSecret(r.Context(), actor, r.PathValue("secretID")); err != nil {
				authError(w, auth.ErrForbidden, logger)
				return
			}
			generation, err := vault.Replace(r.Context(), actor, r.PathValue("secretID"), []byte(input.Value))
			if err != nil {
				authError(w, err, logger)
				return
			}
			writeJSON(w, 200, map[string]int{"generation": generation})
		})
		mux.HandleFunc("GET /api/v1/environments/{id}/secrets", func(w http.ResponseWriter, r *http.Request) {
			actor, ok := current(w, r, false)
			if !ok {
				return
			}
			items, err := vault.ListEnvironment(r.Context(), actor, r.PathValue("id"))
			if err != nil {
				if errors.Is(err, secrets.ErrForbidden) {
					authError(w, auth.ErrForbidden, logger)
				} else {
					authError(w, err, logger)
				}
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, 200, items)
		})
		mux.HandleFunc("POST /api/v1/environments/{id}/secrets", func(w http.ResponseWriter, r *http.Request) {
			if !requireOrigin(w, r) {
				return
			}
			actor, ok := current(w, r, true)
			if !ok {
				return
			}
			var input struct {
				Label string `json:"label"`
				Kind  string `json:"kind"`
				Value string `json:"value"`
			}
			if !decodeJSON(w, r, &input) {
				return
			}
			if len(input.Label) == 0 || len(input.Label) > 128 || len(input.Kind) == 0 || len(input.Kind) > 64 || len(input.Value) == 0 {
				authError(w, auth.ErrInvalidInput, logger)
				return
			}
			item, err := vault.Put(r.Context(), actor, secrets.Scope{EnvironmentID: r.PathValue("id")}, input.Kind, input.Label, []byte(input.Value))
			if err != nil {
				if errors.Is(err, secrets.ErrForbidden) {
					authError(w, auth.ErrForbidden, logger)
				} else {
					authError(w, err, logger)
				}
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, 201, item)
		})
		mux.HandleFunc("PUT /api/v1/environments/{id}/secrets/{secretID}", func(w http.ResponseWriter, r *http.Request) {
			if !requireOrigin(w, r) {
				return
			}
			actor, ok := current(w, r, true)
			if !ok {
				return
			}
			var input struct {
				Value string `json:"value"`
			}
			if !decodeJSON(w, r, &input) {
				return
			}
			if input.Value == "" {
				authError(w, auth.ErrInvalidInput, logger)
				return
			}
			if _, err := vault.EnvironmentSecret(r.Context(), actor, r.PathValue("id"), r.PathValue("secretID")); err != nil {
				authError(w, auth.ErrForbidden, logger)
				return
			}
			generation, err := vault.Replace(r.Context(), actor, r.PathValue("secretID"), []byte(input.Value))
			if err != nil {
				authError(w, err, logger)
				return
			}
			writeJSON(w, 200, map[string]int{"generation": generation})
		})
		mux.HandleFunc("GET /api/v1/me/secrets", func(w http.ResponseWriter, r *http.Request) {
			actor, ok := current(w, r, false)
			if !ok {
				return
			}
			items, err := vault.ListOwned(r.Context(), actor)
			if err != nil {
				authError(w, err, logger)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, 200, items)
		})
		mux.HandleFunc("POST /api/v1/me/secrets", func(w http.ResponseWriter, r *http.Request) {
			if !requireOrigin(w, r) {
				return
			}
			actor, ok := current(w, r, true)
			if !ok {
				return
			}
			var input struct {
				Label string `json:"label"`
				Kind  string `json:"kind"`
				Value string `json:"value"`
			}
			if !decodeJSON(w, r, &input) {
				return
			}
			if len(input.Label) == 0 || len(input.Label) > 128 || len(input.Kind) == 0 || len(input.Kind) > 64 || len(input.Value) == 0 {
				authError(w, auth.ErrInvalidInput, logger)
				return
			}
			item, err := vault.Put(r.Context(), actor, secrets.Scope{OwnerID: actor.ID}, input.Kind, input.Label, []byte(input.Value))
			if err != nil {
				authError(w, err, logger)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, 201, item)
		})
		mux.HandleFunc("PUT /api/v1/me/secrets/{id}", func(w http.ResponseWriter, r *http.Request) {
			if !requireOrigin(w, r) {
				return
			}
			actor, ok := current(w, r, true)
			if !ok {
				return
			}
			var input struct {
				Value string `json:"value"`
			}
			if !decodeJSON(w, r, &input) {
				return
			}
			if input.Value == "" {
				authError(w, auth.ErrInvalidInput, logger)
				return
			}
			generation, err := vault.ReplaceOwned(r.Context(), actor, r.PathValue("id"), []byte(input.Value))
			if err != nil {
				if errors.Is(err, secrets.ErrForbidden) {
					authError(w, auth.ErrForbidden, logger)
				} else {
					authError(w, err, logger)
				}
				return
			}
			writeJSON(w, 200, map[string]int{"generation": generation})
		})
		mux.HandleFunc("DELETE /api/v1/me/secrets/{id}", func(w http.ResponseWriter, r *http.Request) {
			if !requireOrigin(w, r) {
				return
			}
			actor, ok := current(w, r, true)
			if !ok {
				return
			}
			if err := vault.DeleteOwned(r.Context(), actor, r.PathValue("id")); err != nil {
				if errors.Is(err, secrets.ErrForbidden) {
					authError(w, auth.ErrForbidden, logger)
				} else {
					authError(w, err, logger)
				}
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
	}
	if simulated {
		mux.HandleFunc("GET /api/v1/simulation/devices", func(w http.ResponseWriter, r *http.Request) {
			if _, ok := current(w, r, false); !ok {
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, 200, simulation.Devices())
		})
	}
	if jobStore != nil {
		if simulated {
			mux.HandleFunc("POST /api/v1/simulation/jobs", func(w http.ResponseWriter, r *http.Request) {
				if !requireOrigin(w, r) {
					return
				}
				actor, ok := current(w, r, true)
				if !ok {
					return
				}
				if !auth.Allowed(actor, auth.Operate) {
					authError(w, auth.ErrForbidden, logger)
					return
				}
				if r.ContentLength != 0 {
					authError(w, auth.ErrInvalidInput, logger)
					return
				}
				key := r.Header.Get("Idempotency-Key")
				if key == "" || len(key) > 128 {
					authError(w, auth.ErrInvalidInput, logger)
					return
				}
				j, created, err := jobStore.CreateIdempotent(r.Context(), actor.ID, "simulation.inspect", key, "simulation.inspect.v1", "simulation.inspect", time.Now().Add(5*time.Minute), []string{"Read simulation fixture", "Record simulation result"})
				if err != nil {
					if errors.Is(err, jobs.ErrConflict) {
						writeJSON(w, 409, errorResponse{"conflict", "Idempotency key has different input", correlationID()})
					} else {
						authError(w, err, logger)
					}
					return
				}
				status := http.StatusOK
				if created {
					status = http.StatusAccepted
				}
				writeJSON(w, status, j)
			})
		}
		owned := func(w http.ResponseWriter, r *http.Request) (jobs.Job, auth.User, bool) {
			actor, ok := current(w, r, false)
			if !ok {
				return jobs.Job{}, auth.User{}, false
			}
			j, err := jobStore.Get(r.Context(), r.PathValue("id"))
			if errors.Is(err, sql.ErrNoRows) || (err == nil && j.ActorID != actor.ID) {
				authError(w, auth.ErrForbidden, logger)
				return jobs.Job{}, auth.User{}, false
			}
			if err != nil {
				authError(w, err, logger)
				return jobs.Job{}, auth.User{}, false
			}
			return j, actor, true
		}
		mux.HandleFunc("GET /api/v1/jobs", func(w http.ResponseWriter, r *http.Request) {
			actor, ok := current(w, r, false)
			if !ok {
				return
			}
			items, err := jobStore.ListByActor(r.Context(), actor.ID)
			if err != nil {
				authError(w, err, logger)
				return
			}
			writeJSON(w, 200, items)
		})
		mux.HandleFunc("GET /api/v1/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
			j, _, ok := owned(w, r)
			if ok {
				writeJSON(w, 200, j)
			}
		})
		mux.HandleFunc("POST /api/v1/jobs/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
			if !requireOrigin(w, r) {
				return
			}
			actor, ok := current(w, r, true)
			if !ok {
				return
			}
			if !auth.Allowed(actor, auth.Operate) {
				authError(w, auth.ErrForbidden, logger)
				return
			}
			if err := jobStore.RequestCancel(r.Context(), r.PathValue("id"), actor.ID); err != nil {
				if errors.Is(err, jobs.ErrConflict) {
					writeJSON(w, 409, errorResponse{"conflict", "Job cannot be cancelled", correlationID()})
				} else {
					authError(w, err, logger)
				}
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("GET /api/v1/jobs/{id}/events", func(w http.ResponseWriter, r *http.Request) {
			j, _, ok := owned(w, r)
			if !ok {
				return
			}
			last := int64(0)
			if value := r.Header.Get("Last-Event-ID"); value != "" {
				var err error
				last, err = strconv.ParseInt(value, 10, 64)
				if err != nil || last < 0 {
					authError(w, auth.ErrInvalidInput, logger)
					return
				}
			}
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "streaming unavailable", 500)
				return
			}
			cookie, err := r.Cookie("forge_session")
			if err != nil {
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache, no-store")
			w.Header().Set("X-Accel-Buffering", "no")
			flusher.Flush()
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				actor, err := service.SessionUser(r.Context(), cookie.Value, "", false)
				if err != nil || actor.ID != j.ActorID {
					return
				}
				items, err := jobStore.Events(r.Context(), j.ID, last)
				if err != nil {
					return
				}
				for _, event := range items {
					data, err := json.Marshal(event)
					if err != nil {
						return
					}
					if _, err = fmt.Fprintf(w, "id: %d\nevent: job\ndata: %s\n\n", event.Sequence, data); err != nil {
						return
					}
					last = event.Sequence
				}
				flusher.Flush()
				if len(items) == 1000 {
					continue
				}
				latest, err := jobStore.Get(r.Context(), j.ID)
				if err != nil {
					return
				}
				if latest.Status == jobs.Succeeded || latest.Status == jobs.Failed || latest.Status == jobs.Cancelled || latest.Status == jobs.NeedsAttention {
					return
				}
				select {
				case <-r.Context().Done():
					return
				case <-ticker.C:
				}
			}
		})
	}
}

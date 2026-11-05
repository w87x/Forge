package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"forge/internal/auth"
	"forge/internal/inspection"
	"forge/internal/inventory"
	"forge/internal/jobs"
	"forge/internal/netbox"
	"forge/internal/profiles"
	"forge/internal/secrets"
)

type errorResponse struct {
	Code          string `json:"code"`
	Message       string `json:"message"`
	CorrelationID string `json:"correlation_id"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Handler creates the API handler. It never exposes internal errors to clients.
func Handler(logger *slog.Logger, frontend http.Handler, authentication *auth.Service, vault *secrets.Vault, jobStore *jobs.Store, netboxService *netbox.Service, inventoryService *inventory.Service, profileService *profiles.Service, inspectionService *inspection.Service, simulation bool, secureCookies bool) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	mux := http.NewServeMux()
	if authentication != nil {
		mountAuth(mux, authentication, vault, jobStore, netboxService, inventoryService, profileService, inspectionService, simulation, secureCookies, logger)
	}
	mux.HandleFunc("GET /api/v1/info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]bool{"simulation": simulation})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		id := correlationID()
		w.Header().Set("X-Correlation-ID", id)
		writeJSON(w, http.StatusNotFound, errorResponse{"not_found", "API endpoint not found", id})
	})
	if frontend != nil {
		mux.Handle("/", frontend)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Path, "\x00\r\n") {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func correlationID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unavailable"
	}
	return hex.EncodeToString(b[:])
}

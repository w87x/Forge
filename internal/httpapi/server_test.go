package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthAndUnknownAPI(t *testing.T) {
	h := Handler(nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("frontend")) }), nil, nil, nil, nil, nil, nil, nil, false, true)
	for _, tc := range []struct {
		path   string
		status int
	}{{"/healthz", 200}, {"/api/missing", 404}, {"/inventory", 200}} {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest("GET", tc.path, nil))
		if r.Code != tc.status {
			t.Fatalf("%s: got %d", tc.path, r.Code)
		}
		if tc.path == "/api/missing" {
			var body errorResponse
			if err := json.Unmarshal(r.Body.Bytes(), &body); err != nil || body.CorrelationID == "" || body.Code != "not_found" {
				t.Fatalf("unexpected response: %s", r.Body.String())
			}
		}
	}
}

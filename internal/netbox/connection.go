package netbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"forge/internal/auth"
)

var ErrConnectionsDisabled = errors.New("NetBox connections are disabled")
var ErrHostNotAllowed = errors.New("NetBox host is not configured in the allowed host list")
var ErrRemote = errors.New("NetBox connection failed")

type RateLimitError struct {
	RetryAfter time.Duration
	// Local reports that Forge's own request budget, rather than NetBox, is
	// responsible. Callers may wait briefly for a local token.
	Local bool
}

func (e *RateLimitError) Error() string { return "NetBox requests are temporarily rate limited" }

type hostLimit struct {
	tokens   float64
	updated  time.Time
	cooldown time.Time
	inFlight int
}
type Compatibility struct {
	Reachable      bool      `json:"reachable"`
	APIVersion     string    `json:"api_version"`
	Authentication string    `json:"authentication"`
	WritesEnabled  bool      `json:"writes_enabled"`
	CheckedAt      time.Time `json:"checked_at"`
}

func (s *Service) hostAllowed(u *url.URL) bool {
	for _, allowed := range s.AllowedHosts {
		allowed = strings.TrimSpace(allowed)
		if allowed != "" && (strings.EqualFold(allowed, u.Host) || strings.EqualFold(allowed, u.Hostname())) {
			return true
		}
	}
	return false
}
func (s *Service) acquire(host string) (func(), error) {
	s.limitsMu.Lock()
	defer s.limitsMu.Unlock()
	if s.limits == nil {
		s.limits = map[string]*hostLimit{}
	}
	now := time.Now()
	l := s.limits[host]
	if l == nil {
		l = &hostLimit{tokens: 4, updated: now}
		s.limits[host] = l
	}
	if now.Before(l.cooldown) {
		return nil, &RateLimitError{RetryAfter: l.cooldown.Sub(now)}
	}
	l.tokens += now.Sub(l.updated).Seconds() * 2
	if l.tokens > 4 {
		l.tokens = 4
	}
	l.updated = now
	if l.inFlight >= 2 {
		return nil, &RateLimitError{RetryAfter: time.Second, Local: true}
	}
	if l.tokens < 1 {
		return nil, &RateLimitError{RetryAfter: time.Duration((1 - l.tokens) / 2 * float64(time.Second)), Local: true}
	}
	l.tokens--
	l.inFlight++
	return func() { s.limitsMu.Lock(); defer s.limitsMu.Unlock(); l.inFlight-- }, nil
}
func (s *Service) cooldown(host string, d time.Duration) {
	if d <= 0 {
		d = 5 * time.Second
	}
	s.limitsMu.Lock()
	defer s.limitsMu.Unlock()
	l := s.limits[host]
	if l != nil && time.Now().Add(d).After(l.cooldown) {
		l.cooldown = time.Now().Add(d)
	}
}
func retryAfter(value string, now time.Time) time.Duration {
	trimmed := strings.TrimSpace(value)
	if trimmed != "" && strings.Trim(trimmed, "0123456789") == "" {
		seconds, err := strconv.ParseUint(trimmed, 10, 64)
		if err != nil || seconds > uint64(math.MaxInt64/int64(time.Second)) {
			return time.Duration(math.MaxInt64)
		}
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil && at.After(now) {
		return at.Sub(now)
	}
	return 5 * time.Second
}

// CheckConnection makes one bounded read-only request. A successful API-root
// response does not prove identity because NetBox may exempt reads from auth.
func (s *Service) CheckConnection(ctx context.Context, actor auth.User, instanceID string) (Compatibility, error) {
	body, header, _, err := s.get(ctx, actor, instanceID, "/api/", nil)
	if err != nil {
		return Compatibility{}, err
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(body, &root) != nil || root == nil {
		return Compatibility{}, ErrRemote
	}
	version := header.Get("API-Version")
	if len(version) > 64 {
		version = ""
	}
	if version == "" {
		version = "unknown"
	}
	return Compatibility{Reachable: true, APIVersion: version, Authentication: "unverified", WritesEnabled: false, CheckedAt: time.Now().UTC()}, nil
}

// get performs a bounded authenticated GET against a fixed API path. It
// never follows a server-provided redirect or retries ambiguous operations.
func (s *Service) get(ctx context.Context, actor auth.User, instanceID, path string, query url.Values) ([]byte, http.Header, Instance, error) {
	if !s.ConnectionsEnabled {
		return nil, nil, Instance{}, ErrConnectionsDisabled
	}
	instance, _, token, err := s.CredentialValue(ctx, actor, instanceID)
	if err != nil {
		return nil, nil, Instance{}, err
	}
	defer func() {
		for i := range token {
			token[i] = 0
		}
	}()
	base, err := url.Parse(instance.BaseURL)
	if err != nil || !s.hostAllowed(base) {
		return nil, nil, Instance{}, ErrHostNotAllowed
	}
	release, err := s.acquire(strings.ToLower(base.Host))
	if err != nil {
		return nil, nil, Instance{}, err
	}
	defer release()
	base.Path = strings.TrimRight(base.Path, "/") + path
	base.RawPath = ""
	base.RawQuery = query.Encode()
	base.Fragment = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return nil, nil, Instance{}, ErrInvalid
	}
	scheme := "Token "
	if strings.HasPrefix(string(token), "nbt_") {
		scheme = "Bearer "
	}
	req.Header.Set("Authorization", scheme+string(token))
	req.Header.Set("Accept", "application/json")
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 8 * time.Second}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, Instance{}, ErrRemote
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		delay := retryAfter(resp.Header.Get("Retry-After"), time.Now())
		s.cooldown(strings.ToLower(base.Host), delay)
		return nil, nil, Instance{}, &RateLimitError{RetryAfter: delay}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, nil, Instance{}, ErrForbidden
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, Instance{}, fmt.Errorf("%w (HTTP %d)", ErrRemote, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return nil, nil, Instance{}, ErrRemote
	}
	return body, resp.Header, instance, nil
}

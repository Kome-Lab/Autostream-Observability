package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/example/autostream-observability/internal/auth"
	"github.com/example/autostream-observability/internal/control"
	"github.com/example/autostream-observability/internal/store"
)

const maxJSONBodyBytes = 64 << 10

func (s *Server) authorizeAdmin(w http.ResponseWriter, r *http.Request, scope string) bool {
	authenticated, authorized := s.adminAuth.AuthorizeRequest(r, scope)
	if !authenticated {
		authenticated, authorized = nodeRuntimeVerifier().AuthorizeRequest(r, scope)
	}
	if !authenticated {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"code": "invalid_service_token"})
		return false
	}
	if !authorized {
		writeJSON(w, http.StatusForbidden, map[string]string{"code": "missing_admin_scope"})
		return false
	}
	return true
}

func (s *Server) ingestAuthorized(r *http.Request) bool {
	return s.ingestAuth.VerifyRequest(r) || nodeRuntimeVerifier().VerifyRequest(r)
}

func nodeRuntimeVerifier() auth.Verifier {
	return auth.WithRawTokenScopes(auth.Verifier{}, control.NodeRuntimeTokenFromEnv(), "*")
}

type rateLimiter struct {
	mu         sync.Mutex
	burst      int
	window     time.Duration
	maxBuckets int
	hits       map[string][]time.Time
	now        func() time.Time
	shared     rateLimitStore
	requireDB  bool
}

type rateLimitStore interface {
	AllowRateLimit(ctx context.Context, bucketKey string, window time.Duration, burst int, now time.Time) (bool, error)
}

func rateLimiterFromEnv(st store.Store) *rateLimiter {
	burst := envInt("OBSERVABILITY_RATE_LIMIT_BURST", 120)
	windowSec := envInt("OBSERVABILITY_RATE_LIMIT_WINDOW_SEC", 60)
	maxBuckets := envInt("OBSERVABILITY_RATE_LIMIT_MAX_BUCKETS", 10000)
	if burst <= 0 || windowSec <= 0 {
		return nil
	}
	if maxBuckets <= 0 {
		maxBuckets = 10000
	}
	limiter := &rateLimiter{
		burst:      burst,
		window:     time.Duration(windowSec) * time.Second,
		maxBuckets: maxBuckets,
		hits:       map[string][]time.Time{},
		now:        time.Now,
	}
	backend := strings.ToLower(strings.TrimSpace(os.Getenv("OBSERVABILITY_RATE_LIMIT_BACKEND")))
	if backend == "store" || backend == "mariadb" || backend == "shared" {
		shared, ok := st.(rateLimitStore)
		if !ok {
			limiter.requireDB = true
			return limiter
		}
		limiter.shared = shared
		return limiter
	}
	if backend == "" {
		if shared, ok := st.(store.MariaDBStore); ok {
			limiter.shared = shared
		}
	}
	return limiter
}

func (s *Server) rateLimitSensitive(next http.Handler) http.Handler {
	if s.rateLimiter == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isRateLimitedEndpoint(r) {
			allowed, err := s.rateLimiter.allow(r.Context(), rateLimitKey(r))
			if err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"code": "rate_limit_unavailable"})
				return
			}
			if !allowed {
				writeJSON(w, http.StatusTooManyRequests, map[string]string{"code": "rate_limited"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isRateLimitedEndpoint(r *http.Request) bool {
	path := r.URL.Path
	switch r.Method {
	case http.MethodGet:
		if path == "/signals" || path == "/metrics" || path == "/diagnostics" || path == "/incidents" || path == "/notification-deliveries" || path == "/notification-channels" || path == "/remediation-actions" {
			return true
		}
		if strings.HasPrefix(path, "/incidents/") || strings.HasPrefix(path, "/notification-channels/") || strings.HasPrefix(path, "/remediation-actions/") {
			return true
		}
	case http.MethodPost:
		if path == "/heartbeat" || path == "/signals" || path == "/notification-channels" || path == "/notification-events" {
			return true
		}
		if strings.HasPrefix(path, "/incidents/") && (strings.HasSuffix(path, "/acknowledge") || strings.HasSuffix(path, "/resolve") || strings.HasSuffix(path, "/diagnostics/rerun")) {
			return true
		}
		if strings.HasPrefix(path, "/notification-channels/") && strings.HasSuffix(path, "/test") {
			return true
		}
		if strings.HasPrefix(path, "/remediation-actions/") && (strings.HasSuffix(path, "/approve") || strings.HasSuffix(path, "/execute")) {
			return true
		}
	case http.MethodPut, http.MethodDelete:
		if strings.HasPrefix(path, "/notification-channels/") {
			return true
		}
	}
	return false
}

func rateLimitKey(r *http.Request) string {
	return r.Method + "\x00" + rateLimitPath(r) + "\x00" + clientIP(r)
}

func rateLimitPath(r *http.Request) string {
	path := r.URL.Path
	if r.Method == http.MethodGet && strings.HasPrefix(path, "/incidents/") {
		return "/incidents/{id}"
	}
	if r.Method == http.MethodGet && strings.HasPrefix(path, "/notification-channels/") {
		return "/notification-channels/{id}"
	}
	if r.Method == http.MethodGet && strings.HasPrefix(path, "/remediation-actions/") && strings.HasSuffix(path, "/dispatch-context") {
		return "/remediation-actions/{id}/dispatch-context"
	}
	if strings.HasPrefix(path, "/incidents/") && strings.HasSuffix(path, "/acknowledge") {
		return "/incidents/{id}/acknowledge"
	}
	if strings.HasPrefix(path, "/incidents/") && strings.HasSuffix(path, "/resolve") {
		return "/incidents/{id}/resolve"
	}
	if strings.HasPrefix(path, "/incidents/") && strings.HasSuffix(path, "/diagnostics/rerun") {
		return "/incidents/{id}/diagnostics/rerun"
	}
	if strings.HasPrefix(path, "/notification-channels/") && strings.HasSuffix(path, "/test") {
		return "/notification-channels/{id}/test"
	}
	if (r.Method == http.MethodPut || r.Method == http.MethodDelete) && strings.HasPrefix(path, "/notification-channels/") {
		return "/notification-channels/{id}"
	}
	if strings.HasPrefix(path, "/remediation-actions/") && strings.HasSuffix(path, "/approve") {
		return "/remediation-actions/{id}/approve"
	}
	if strings.HasPrefix(path, "/remediation-actions/") && strings.HasSuffix(path, "/execute") {
		return "/remediation-actions/{id}/execute"
	}
	return path
}

func clientIP(r *http.Request) string {
	remote := remoteHost(r.RemoteAddr)
	forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if forwarded != "" && trustedProxy(remote) {
		current, err := netip.ParseAddr(remote)
		if err != nil {
			return remote
		}
		current = current.Unmap()
		hops := strings.Split(forwarded, ",")
		for i := len(hops) - 1; i >= 0; i-- {
			hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
			if err != nil {
				return remote
			}
			if !trustedProxy(current.String()) {
				return current.String()
			}
			current = hop.Unmap()
		}
		return current.String()
	}
	if remote != "" {
		return remote
	}
	if raw := strings.TrimSpace(r.RemoteAddr); raw != "" {
		return raw
	}
	return "unknown"
}

func remoteHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && host != "" {
		return host
	}
	if idx := strings.LastIndex(remoteAddr, ":"); idx > 0 && !strings.Contains(remoteAddr[idx+1:], ":") {
		return remoteAddr[:idx]
	}
	return strings.Trim(remoteAddr, "[]")
}

func trustedProxy(host string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	raw := strings.TrimSpace(os.Getenv("OBSERVABILITY_TRUSTED_PROXIES"))
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("AUTOSTREAM_TRUSTED_PROXIES"))
	}
	if raw == "" {
		return false
	}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(item); err == nil {
			if prefix.Contains(addr) {
				return true
			}
			continue
		}
		if trustedAddr, err := netip.ParseAddr(item); err == nil && trustedAddr.Unmap() == addr {
			return true
		}
	}
	return false
}

func (l *rateLimiter) allow(ctx context.Context, key string) (bool, error) {
	now := l.now().UTC()
	if l.requireDB {
		return false, errors.New("shared rate limit store unavailable")
	}
	if l.shared != nil {
		return l.shared.AllowRateLimit(ctx, key, l.window, l.burst, now)
	}
	return l.allowMemory(key, now), nil
}

func (l *rateLimiter) allowMemory(key string, now time.Time) bool {
	cutoff := now.Add(-l.window)
	l.mu.Lock()
	defer l.mu.Unlock()

	for candidate, candidateHits := range l.hits {
		kept := candidateHits[:0]
		for _, hit := range candidateHits {
			if hit.After(cutoff) {
				kept = append(kept, hit)
			}
		}
		if len(kept) == 0 {
			delete(l.hits, candidate)
			continue
		}
		l.hits[candidate] = kept
	}

	hits := l.hits[key]
	kept := hits[:0]
	for _, hit := range hits {
		if hit.After(cutoff) {
			kept = append(kept, hit)
		}
	}
	if len(kept) >= l.burst {
		l.hits[key] = kept
		return false
	}
	if len(kept) == 0 && l.maxBuckets > 0 && len(l.hits) >= l.maxBuckets {
		return false
	}
	kept = append(kept, now)
	l.hits[key] = kept
	return true
}

func envInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/updater/version" {
			w.Header().Set("Cache-Control", "no-store")
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain a single JSON object")
	}
	return nil
}

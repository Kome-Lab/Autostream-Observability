package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/example/autostream-observability/internal/auth"
	"github.com/example/autostream-observability/internal/store"
)

func TestAdminAuthReadsNodeRuntimeTokenAfterStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	t.Setenv("AUTOSTREAM_NODE_CONFIG", path)
	handler := NewServerWithStoreAuthz("observability", store.NewMemoryStore(), auth.Verifier{}, auth.Verifier{})

	req := httptest.NewRequest(http.MethodGet, "/signals", nil)
	req.Header.Set("Authorization", "Bearer runtime-secret")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("runtime token should not verify before config exists, got %d body = %s", res.Code, res.Body.String())
	}

	writeNodeConfigForVerifierTest(t, path, "observability")
	req = httptest.NewRequest(http.MethodGet, "/signals", nil)
	req.Header.Set("Authorization", "Bearer runtime-secret")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("runtime token should verify after config is written, got %d body = %s", res.Code, res.Body.String())
	}
}

func TestAdminTokenScopesSeparateReadFromSensitiveWrites(t *testing.T) {
	st := store.NewMemoryStore()
	readToken := "read-token"
	adminVerifier := auth.NewVerifierFromRawTokens(readToken)
	adminVerifier.TokenScopes = map[string]map[string]bool{
		auth.HashToken(readToken): {
			adminScopeRead:              true,
			adminScopeNotificationsRead: true,
			adminScopeRemediationRead:   true,
		},
	}
	adminVerifier.ScopeBindingRequired = true
	handler := NewServerWithStoreAuthzNotifierAndExecutor(
		"observability",
		st,
		auth.NewVerifierFromRawTokens("ingest-token"),
		adminVerifier,
		nil,
		nil,
	)

	readReq := httptest.NewRequest(http.MethodGet, "/incidents", nil)
	readReq.Header.Set("Authorization", "Bearer "+readToken)
	readRes := httptest.NewRecorder()
	handler.ServeHTTP(readRes, readReq)
	if readRes.Code != http.StatusOK {
		t.Fatalf("read-only admin token should list incidents: status=%d body=%s", readRes.Code, readRes.Body.String())
	}

	manageReq := httptest.NewRequest(http.MethodPost, "/notification-channels", strings.NewReader(`{}`))
	manageReq.Header.Set("Authorization", "Bearer "+readToken)
	manageRes := httptest.NewRecorder()
	handler.ServeHTTP(manageRes, manageReq)
	if manageRes.Code != http.StatusForbidden || !strings.Contains(manageRes.Body.String(), "missing_admin_scope") {
		t.Fatalf("read-only admin token must not manage notification channels: status=%d body=%s", manageRes.Code, manageRes.Body.String())
	}

	executeReq := httptest.NewRequest(http.MethodPost, "/remediation-actions/action-01/execute", nil)
	executeReq.Header.Set("Authorization", "Bearer "+readToken)
	executeRes := httptest.NewRecorder()
	handler.ServeHTTP(executeRes, executeReq)
	if executeRes.Code != http.StatusForbidden || !strings.Contains(executeRes.Body.String(), "missing_admin_scope") {
		t.Fatalf("read-only admin token must not execute remediation: status=%d body=%s", executeRes.Code, executeRes.Body.String())
	}
}

func TestSensitivePostEndpointsAreRateLimitedByClientAndEndpoint(t *testing.T) {
	t.Setenv("OBSERVABILITY_RATE_LIMIT_BURST", "2")
	t.Setenv("OBSERVABILITY_RATE_LIMIT_WINDOW_SEC", "60")
	handler := newTestServer(store.NewMemoryStore())
	body := `{"type":"event","name":"encoder.process.exited","service_id":"enc-01","service_type":"encoder_recorder"}`
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(body))
		req.RemoteAddr = "203.0.113.10:12345"
		req.Header.Set("Authorization", "Bearer service-token")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusAccepted {
			t.Fatalf("request %d status = %d body = %s", i+1, res.Code, res.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(body))
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusTooManyRequests {
		t.Fatalf("third request status = %d body = %s", res.Code, res.Body.String())
	}

	otherClient := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(body))
	otherClient.RemoteAddr = "203.0.113.11:12345"
	otherClient.Header.Set("Authorization", "Bearer service-token")
	otherClientRes := httptest.NewRecorder()
	handler.ServeHTTP(otherClientRes, otherClient)
	if otherClientRes.Code != http.StatusAccepted {
		t.Fatalf("different client should have a separate rate bucket: status=%d body=%s", otherClientRes.Code, otherClientRes.Body.String())
	}
}

func TestSensitivePostRateLimitSharesBucketAcrossInvalidBearerValues(t *testing.T) {
	t.Setenv("OBSERVABILITY_RATE_LIMIT_BURST", "2")
	t.Setenv("OBSERVABILITY_RATE_LIMIT_WINDOW_SEC", "60")
	handler := newTestServer(store.NewMemoryStore())
	body := `{"type":"event","name":"x","service_id":"svc","service_type":"worker"}`
	for i, token := range []string{"wrong-token-1", "wrong-token-2"} {
		req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(body))
		req.RemoteAddr = "203.0.113.10:12345"
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusUnauthorized {
			t.Fatalf("invalid token request %d status = %d body = %s", i+1, res.Code, res.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(body))
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("Authorization", "Bearer wrong-token-3")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusTooManyRequests {
		t.Fatalf("third invalid-token request status = %d body = %s", res.Code, res.Body.String())
	}
}

func TestSensitivePostRateLimitNormalizesDynamicActionPaths(t *testing.T) {
	t.Setenv("OBSERVABILITY_RATE_LIMIT_BURST", "2")
	t.Setenv("OBSERVABILITY_RATE_LIMIT_WINDOW_SEC", "60")
	handler := newTestServer(store.NewMemoryStore())
	for i, id := range []string{"one", "two"} {
		req := httptest.NewRequest(http.MethodPost, "/notification-channels/"+id+"/test", nil)
		req.RemoteAddr = "203.0.113.10:12345"
		req.Header.Set("Authorization", "Bearer wrong-token")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusUnauthorized {
			t.Fatalf("invalid notification test %d status = %d body = %s", i+1, res.Code, res.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/notification-channels/three/test", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("Authorization", "Bearer wrong-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusTooManyRequests {
		t.Fatalf("third dynamic-path request status = %d body = %s", res.Code, res.Body.String())
	}
}

func TestSensitiveStateChangingEndpointsAreRateLimited(t *testing.T) {
	t.Setenv("OBSERVABILITY_RATE_LIMIT_BURST", "2")
	t.Setenv("OBSERVABILITY_RATE_LIMIT_WINDOW_SEC", "60")
	handler := newTestServer(store.NewMemoryStore())
	cases := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/heartbeat"},
		{http.MethodPost, "/incidents/incident-1/acknowledge"},
		{http.MethodPost, "/incidents/incident-1/resolve"},
		{http.MethodPost, "/notification-channels"},
		{http.MethodPost, "/notification-events"},
		{http.MethodPut, "/notification-channels/channel-1"},
		{http.MethodDelete, "/notification-channels/channel-1"},
		{http.MethodPost, "/notification-channels/channel-1/test"},
		{http.MethodPost, "/remediation-actions/action-1/approve"},
		{http.MethodPost, "/remediation-actions/action-1/execute"},
	}
	for i, tc := range cases {
		remoteAddr := "203.0.113." + strconv.Itoa(30+i) + ":12345"
		for requestIndex := 0; requestIndex < 2; requestIndex++ {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.RemoteAddr = remoteAddr
			req.Header.Set("Authorization", "Bearer wrong-token-"+strconv.Itoa(requestIndex))
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s request %d status = %d body = %s", tc.method, tc.path, requestIndex+1, res.Code, res.Body.String())
			}
		}
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("Authorization", "Bearer wrong-token-3")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusTooManyRequests {
			t.Fatalf("%s %s third request status = %d body = %s", tc.method, tc.path, res.Code, res.Body.String())
		}
	}
}

func TestAuthenticatedReadEndpointsAreRateLimited(t *testing.T) {
	t.Setenv("OBSERVABILITY_RATE_LIMIT_BURST", "2")
	t.Setenv("OBSERVABILITY_RATE_LIMIT_WINDOW_SEC", "60")
	handler := newTestServer(store.NewMemoryStore())
	cases := []string{
		"/signals",
		"/metrics",
		"/diagnostics",
		"/incidents",
		"/incidents/incident-1",
		"/notification-deliveries",
		"/notification-channels",
		"/notification-channels/channel-1",
		"/remediation-actions",
	}
	for i, path := range cases {
		remoteAddr := "203.0.113." + strconv.Itoa(90+i) + ":12345"
		for requestIndex := 0; requestIndex < 2; requestIndex++ {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.RemoteAddr = remoteAddr
			req.Header.Set("Authorization", "Bearer wrong-token-"+strconv.Itoa(requestIndex))
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != http.StatusUnauthorized {
				t.Fatalf("GET %s request %d status = %d body = %s", path, requestIndex+1, res.Code, res.Body.String())
			}
		}
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("Authorization", "Bearer wrong-token-3")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusTooManyRequests {
			t.Fatalf("GET %s third request status = %d body = %s", path, res.Code, res.Body.String())
		}
	}
}

func TestSensitiveRateLimitNormalizesAdditionalDynamicPaths(t *testing.T) {
	t.Setenv("OBSERVABILITY_RATE_LIMIT_BURST", "2")
	t.Setenv("OBSERVABILITY_RATE_LIMIT_WINDOW_SEC", "60")
	handler := newTestServer(store.NewMemoryStore())
	cases := []struct {
		method string
		paths  []string
	}{
		{http.MethodPost, []string{"/incidents/one/acknowledge", "/incidents/two/acknowledge", "/incidents/three/acknowledge"}},
		{http.MethodPost, []string{"/incidents/one/resolve", "/incidents/two/resolve", "/incidents/three/resolve"}},
		{http.MethodPost, []string{"/remediation-actions/one/approve", "/remediation-actions/two/approve", "/remediation-actions/three/approve"}},
		{http.MethodPost, []string{"/remediation-actions/one/execute", "/remediation-actions/two/execute", "/remediation-actions/three/execute"}},
		{http.MethodPut, []string{"/notification-channels/one", "/notification-channels/two", "/notification-channels/three"}},
		{http.MethodDelete, []string{"/notification-channels/one", "/notification-channels/two", "/notification-channels/three"}},
	}
	for i, tc := range cases {
		remoteAddr := "203.0.113." + strconv.Itoa(60+i) + ":12345"
		for requestIndex := 0; requestIndex < 2; requestIndex++ {
			req := httptest.NewRequest(tc.method, tc.paths[requestIndex], nil)
			req.RemoteAddr = remoteAddr
			req.Header.Set("Authorization", "Bearer wrong-token")
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s request %d status = %d body = %s", tc.method, tc.paths[requestIndex], requestIndex+1, res.Code, res.Body.String())
			}
		}
		req := httptest.NewRequest(tc.method, tc.paths[2], nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("Authorization", "Bearer wrong-token")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusTooManyRequests {
			t.Fatalf("%s %s third normalized request status = %d body = %s", tc.method, tc.paths[2], res.Code, res.Body.String())
		}
	}
}

func TestRateLimitClientIPOnlyTrustsForwardedForFromTrustedProxy(t *testing.T) {
	t.Setenv("OBSERVABILITY_TRUSTED_PROXIES", "10.0.0.0/8")

	untrusted := httptest.NewRequest(http.MethodGet, "/signals", nil)
	untrusted.RemoteAddr = "198.51.100.10:54321"
	untrusted.Header.Set("X-Forwarded-For", "203.0.113.99")
	if got := clientIP(untrusted); got != "198.51.100.10" {
		t.Fatalf("untrusted proxy X-Forwarded-For should be ignored, got %q", got)
	}

	trusted := httptest.NewRequest(http.MethodGet, "/signals", nil)
	trusted.RemoteAddr = "10.1.2.3:54321"
	trusted.Header.Set("X-Forwarded-For", "203.0.113.99, 10.1.2.3")
	if got := clientIP(trusted); got != "203.0.113.99" {
		t.Fatalf("trusted proxy X-Forwarded-For should be used, got %q", got)
	}

	spoofedLeftmost := httptest.NewRequest(http.MethodGet, "/signals", nil)
	spoofedLeftmost.RemoteAddr = "10.1.2.3:54321"
	spoofedLeftmost.Header.Set("X-Forwarded-For", "198.51.100.66, 203.0.113.25")
	if got := clientIP(spoofedLeftmost); got != "203.0.113.25" {
		t.Fatalf("leftmost spoof before an untrusted client hop must be ignored, got %q", got)
	}

	malformed := httptest.NewRequest(http.MethodGet, "/signals", nil)
	malformed.RemoteAddr = "10.1.2.3:54321"
	malformed.Header.Set("X-Forwarded-For", "not-an-ip, 203.0.113.25")
	if got := clientIP(malformed); got != "10.1.2.3" {
		t.Fatalf("malformed forwarded chain must fall back to the peer address, got %q", got)
	}
}

func TestRateLimitClientIPDoesNotImplicitlyTrustLoopback(t *testing.T) {
	t.Setenv("OBSERVABILITY_TRUSTED_PROXIES", "")
	t.Setenv("AUTOSTREAM_TRUSTED_PROXIES", "")

	request := httptest.NewRequest(http.MethodGet, "/signals", nil)
	request.RemoteAddr = "127.0.0.1:54321"
	request.Header.Set("X-Forwarded-For", "203.0.113.99")
	if got := clientIP(request); got != "127.0.0.1" {
		t.Fatalf("loopback proxy must be explicitly configured, got %q", got)
	}
}

func TestRateLimitMaxBucketsFailClosed(t *testing.T) {
	t.Setenv("OBSERVABILITY_RATE_LIMIT_BURST", "10")
	t.Setenv("OBSERVABILITY_RATE_LIMIT_WINDOW_SEC", "60")
	t.Setenv("OBSERVABILITY_RATE_LIMIT_MAX_BUCKETS", "1")
	handler := newTestServer(store.NewMemoryStore())
	body := `{"type":"event","name":"encoder.process.exited","service_id":"enc-01","service_type":"encoder_recorder"}`

	first := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(body))
	first.RemoteAddr = "203.0.113.10:12345"
	first.Header.Set("Authorization", "Bearer service-token")
	firstRes := httptest.NewRecorder()
	handler.ServeHTTP(firstRes, first)
	if firstRes.Code != http.StatusAccepted {
		t.Fatalf("first bucket status = %d body = %s", firstRes.Code, firstRes.Body.String())
	}

	second := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(body))
	second.RemoteAddr = "203.0.113.11:12345"
	second.Header.Set("Authorization", "Bearer service-token")
	secondRes := httptest.NewRecorder()
	handler.ServeHTTP(secondRes, second)
	if secondRes.Code != http.StatusTooManyRequests {
		t.Fatalf("new bucket over max should be rate limited, status = %d body = %s", secondRes.Code, secondRes.Body.String())
	}
}

func TestRateLimitStoreBackendIsUsedWhenConfigured(t *testing.T) {
	t.Setenv("OBSERVABILITY_RATE_LIMIT_BACKEND", "store")
	st := &fakeRateLimitStore{MemoryStore: store.NewMemoryStore(), allowed: false}
	handler := NewServerWithStoreAndAuth("observability", st, auth.NewVerifierFromRawTokens("service-token"))

	req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(`{"type":"event","name":"encoder.process.exited","service_id":"enc-01","service_type":"encoder_recorder"}`))
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusTooManyRequests {
		t.Fatalf("store-backed limiter should reject request, status = %d body = %s", res.Code, res.Body.String())
	}
	if st.calls != 1 || len(st.keys) != 1 || !strings.Contains(st.keys[0], "203.0.113.10") {
		t.Fatalf("store-backed limiter was not called with client key: calls=%d keys=%#v", st.calls, st.keys)
	}
}

func TestRateLimitStoreBackendMissingFailsClosed(t *testing.T) {
	t.Setenv("OBSERVABILITY_RATE_LIMIT_BACKEND", "store")
	handler := newTestServer(store.NewMemoryStore())
	req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(`{"type":"event","name":"encoder.process.exited","service_id":"enc-01","service_type":"encoder_recorder"}`))
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusServiceUnavailable || !strings.Contains(res.Body.String(), "rate_limit_unavailable") {
		t.Fatalf("missing shared limiter should fail closed, status = %d body = %s", res.Code, res.Body.String())
	}
}

type fakeRateLimitStore struct {
	*store.MemoryStore
	allowed bool
	err     error
	calls   int
	keys    []string
}

func (s *fakeRateLimitStore) AllowRateLimit(ctx context.Context, bucketKey string, window time.Duration, burst int, now time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.calls++
	s.keys = append(s.keys, bucketKey)
	if s.err != nil {
		return false, s.err
	}
	return s.allowed, nil
}

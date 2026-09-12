package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/example/autostream-observability/internal/auth"
	"github.com/example/autostream-observability/internal/store"
)

// These requests characterize the accepted route and middleware boundary before
// moving its handlers into domain files. Malformed bodies must not bypass auth.
func TestRouteDomainsPreserveAuthenticationBeforeDecoding(t *testing.T) {
	t.Setenv("AUTOSTREAM_NODE_CONFIG", filepath.Join(t.TempDir(), "not-yet-configured.yml"))
	t.Setenv("OBSERVABILITY_RATE_LIMIT_BACKEND", "memory")
	t.Setenv("OBSERVABILITY_RATE_LIMIT_BURST", "120")
	handler := NewServerWithStoreAndAuth("observability", store.NewMemoryStore(), auth.NewVerifierFromRawTokens("route-token"))
	for _, route := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/heartbeat"},
		{http.MethodPost, "/signals"},
		{http.MethodGet, "/signals"},
		{http.MethodGet, "/metrics"},
		{http.MethodGet, "/diagnostics"},
		{http.MethodGet, "/incidents"},
		{http.MethodGet, "/incidents/missing"},
		{http.MethodPost, "/incidents/missing/diagnostics/rerun"},
		{http.MethodPost, "/incidents/missing/acknowledge"},
		{http.MethodPost, "/incidents/missing/resolve"},
		{http.MethodGet, "/notification-deliveries"},
		{http.MethodGet, "/notification-channels"},
		{http.MethodPost, "/notification-channels"},
		{http.MethodGet, "/notification-channels/missing"},
		{http.MethodPut, "/notification-channels/missing"},
		{http.MethodDelete, "/notification-channels/missing"},
		{http.MethodPost, "/notification-channels/missing/test"},
		{http.MethodPost, "/notification-events"},
		{http.MethodGet, "/remediation-actions"},
		{http.MethodGet, "/remediation-actions/missing/dispatch-context"},
		{http.MethodPost, "/remediation-actions/missing/approve"},
		{http.MethodPost, "/remediation-actions/missing/execute"},
	} {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(route.method, route.path, strings.NewReader("{")))
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
			}
			var body map[string]string
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if len(body) != 1 || body["code"] != "invalid_service_token" {
				t.Fatalf("authentication response = %#v", body)
			}
			if response.Header().Get("Content-Type") != "application/json" || response.Header().Get("X-Content-Type-Options") != "nosniff" || response.Header().Get("X-Frame-Options") != "DENY" {
				t.Fatalf("headers = %#v", response.Header())
			}
		})
	}
}

func TestRouteDomainsPreservePendingPublicStatusAndMethodBoundary(t *testing.T) {
	t.Setenv("AUTOSTREAM_NODE_CONFIG", filepath.Join(t.TempDir(), "not-yet-configured.yml"))
	handler := NewServerWithStoreAndAuth("observability", store.NewMemoryStore(), auth.NewVerifierFromRawTokens("route-token"))
	for _, path := range []string{"/", "/health", "/status", "/updater/version"} {
		t.Run(path, func(t *testing.T) {
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, httptest.NewRequest(method, path, nil))
				want := http.StatusOK
				if path == "/updater/version" {
					want = http.StatusServiceUnavailable
					if method == http.MethodGet && response.Body.String() != "{\"code\":\"updater_identity_pending\"}\n" {
						t.Fatalf("pending identity response = %s", response.Body.String())
					}
				}
				if method == http.MethodPost {
					want = http.StatusMethodNotAllowed
					if response.Header().Get("Allow") != "GET, HEAD" {
						t.Fatalf("%s Allow = %q", method, response.Header().Get("Allow"))
					}
				}
				if response.Code != want {
					t.Fatalf("%s status = %d body = %s", method, response.Code, response.Body.String())
				}
				if response.Header().Get("X-Content-Type-Options") != "nosniff" || response.Header().Get("X-Frame-Options") != "DENY" {
					t.Fatalf("%s headers = %#v", method, response.Header())
				}
				if path == "/updater/version" && response.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("%s cache control = %q", method, response.Header().Get("Cache-Control"))
				}
			}
		})
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/unknown-route", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown route status = %d", response.Code)
	}
}

func TestPendingIdentityRoutesPreserveIncidentLifecycleAndQueries(t *testing.T) {
	t.Setenv("AUTOSTREAM_NODE_CONFIG", filepath.Join(t.TempDir(), "not-yet-configured.yml"))
	st := store.NewMemoryStore()
	notifier := &eventRecordingNotifier{}
	handler := NewServerWithStoreAuthAndNotifier("observability", st, auth.NewVerifierFromRawTokens("route-token"), notifier)
	request := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer route-token")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	var incidentID string
	for range 2 {
		response := request(http.MethodPost, "/signals", `{"type":"error","name":"encoder.process.exited","service_id":"enc-01","service_type":"encoder_recorder","stream_id":"stream-01","attributes":{"error":"exit status 1"}}`)
		if response.Code != http.StatusAccepted {
			t.Fatalf("ingest status = %d body = %s", response.Code, response.Body.String())
		}
		var ingest IngestResponse
		if err := json.Unmarshal(response.Body.Bytes(), &ingest); err != nil {
			t.Fatal(err)
		}
		if len(ingest.Incidents) != 1 || ingest.Incidents[0].Rule != "encoder_process_exited" || !strings.Contains(ingest.Incidents[0].Report.Summary, "Encoder") {
			t.Fatalf("ingest result = %#v", ingest)
		}
		if incidentID != "" && incidentID != ingest.Incidents[0].ID {
			t.Fatal("repeated signal created another incident")
		}
		incidentID = ingest.Incidents[0].ID
	}
	for path, count := range map[string]int{"/signals": 2, "/incidents": 1, "/diagnostics": 1, "/remediation-actions": 4, "/notification-deliveries": 1} {
		response := request(http.MethodGet, path, "")
		var rows []json.RawMessage
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &rows) != nil || len(rows) != count {
			t.Fatalf("query %s status=%d body=%s want rows=%d", path, response.Code, response.Body.String(), count)
		}
	}
	response := request(http.MethodPost, "/incidents/"+incidentID+"/diagnostics/rerun", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"outcome":"evaluated"`) {
		t.Fatalf("diagnostic rerun status=%d body=%s", response.Code, response.Body.String())
	}
	if !reflect.DeepEqual(notifier.events, []string{"incident.opened"}) {
		t.Fatalf("ingest dedupe or diagnostic rerun notification side effects = %#v", notifier.events)
	}
	for _, transition := range []string{"acknowledge", "resolve", "resolve"} {
		response := request(http.MethodPost, "/incidents/"+incidentID+"/"+transition, "")
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", transition, response.Code, response.Body.String())
		}
	}
	if !reflect.DeepEqual(notifier.events, []string{"incident.opened", "incident.updated", "incident.resolved"}) {
		t.Fatalf("lifecycle notification order or repeated resolve changed = %#v", notifier.events)
	}
}

func TestPendingIdentityRoutesKeepApplicationDispatchFailClosed(t *testing.T) {
	t.Setenv("AUTOSTREAM_NODE_CONFIG", filepath.Join(t.TempDir(), "not-yet-configured.yml"))
	st := store.NewMemoryStore()
	incident, _, err := st.UpsertIncident(t.Context(), store.Incident{Rule: "archive_package_failed", Severity: "error", Status: "open", ServiceID: "enc-01", StreamID: "stream-01", SignalID: "signal-1"})
	if err != nil {
		t.Fatal(err)
	}
	action, err := st.CreateRemediationAction(t.Context(), store.RemediationAction{IncidentID: incident.ID, Action: "retry_package_remux", Mode: "safe_auto", Status: "suggested", SafeAuto: true})
	if err != nil {
		t.Fatal(err)
	}
	executor := &fakeControlExecutor{}
	handler := NewServerWithStoreAuthNotifierAndExecutor("observability", st, auth.NewVerifierFromRawTokens("route-token"), nil, executor)
	req := httptest.NewRequest(http.MethodPost, "/remediation-actions/"+action.ID+"/execute", nil)
	req.Header.Set("Authorization", "Bearer route-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusForbidden || len(executor.calls) != 0 {
		t.Fatalf("pending identity dispatch status=%d calls=%#v body=%s", response.Code, executor.calls, response.Body.String())
	}
	saved, err := st.GetRemediationAction(t.Context(), action.ID)
	if err != nil || saved.Status != "blocked" || saved.ExecutedAt != nil || saved.Result != "control panel dispatch failed" {
		t.Fatalf("pending identity action state=%#v error=%v", saved, err)
	}
}

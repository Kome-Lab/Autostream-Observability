package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/example/autostream-observability/internal/version"
)

func TestExecuteRemediationDispatchesToControlPanel(t *testing.T) {
	var gotAuth string
	var gotPath string
	var gotBody RemediationRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	client := Client{BaseURL: server.URL, Token: "secret-token", HTTP: server.Client()}
	if err := client.ExecuteRemediation(t.Context(), RemediationRequest{ActionID: "action-1", Action: "retry_package_remux", IncidentID: "inc-1", StreamID: "stream-1"}); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/services/remediation-actions/execute" {
		t.Fatalf("unexpected path: %s", gotPath)
	}
	if gotAuth != "Bearer secret-token" {
		t.Fatalf("authorization header was not set")
	}
	if gotBody.ActionID != "action-1" || gotBody.Action != "retry_package_remux" || gotBody.IncidentID != "inc-1" || gotBody.StreamID != "stream-1" {
		t.Fatalf("remediation context was not sent: %#v", gotBody)
	}
}

func TestExecuteRemediationErrorsDoNotLeakToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "secret-token", http.StatusForbidden)
	}))
	defer server.Close()
	client := Client{BaseURL: server.URL, Token: "secret-token", HTTP: server.Client()}
	err := client.ExecuteRemediation(t.Context(), RemediationRequest{ActionID: "action-1", Action: "retry_gdrive_upload", IncidentID: "inc-1", StreamID: "stream-1"})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("token leaked in error: %v", err)
	}
}

func TestExecuteRemediationRejectsControlPanelURLUserinfo(t *testing.T) {
	client := Client{BaseURL: "https://user:pass@control.example.com", Token: "secret-token"}
	err := client.ExecuteRemediation(t.Context(), RemediationRequest{ActionID: "action-1", Action: "retry_gdrive_upload", IncidentID: "inc-1", StreamID: "stream-1"})
	if err == nil {
		t.Fatal("expected userinfo URL to be rejected")
	}
}

func TestExecuteRemediationRejectsRemoteHTTPControlPanelURL(t *testing.T) {
	client := Client{BaseURL: "http://control.example.com", Token: "secret-token"}
	err := client.ExecuteRemediation(t.Context(), RemediationRequest{ActionID: "action-1", Action: "retry_gdrive_upload", IncidentID: "inc-1", StreamID: "stream-1"})
	if err == nil {
		t.Fatal("expected remote http URL to be rejected")
	}
	if !strings.Contains(err.Error(), "https for remote hosts") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteRemediationAllowsLocalHTTPControlPanelURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	client := Client{BaseURL: server.URL, Token: "secret-token", HTTP: server.Client()}
	if err := client.ExecuteRemediation(t.Context(), RemediationRequest{ActionID: "action-1", Action: "retry_gdrive_upload", IncidentID: "inc-1", StreamID: "stream-1"}); err != nil {
		t.Fatalf("expected local http URL to be allowed: %v", err)
	}
}

func TestExecuteRemediationDoesNotFollowRedirectsWithBearerToken(t *testing.T) {
	var redirectedAuth string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/capture", http.StatusFound)
	}))
	defer server.Close()
	client := Client{BaseURL: server.URL, Token: "secret-token"}
	err := client.ExecuteRemediation(t.Context(), RemediationRequest{ActionID: "action-1", Action: "retry_gdrive_upload", IncidentID: "inc-1", StreamID: "stream-1"})
	if err == nil {
		t.Fatal("expected redirect response to fail dispatch")
	}
	if redirectedAuth != "" {
		t.Fatalf("authorization header followed redirect: %q", redirectedAuth)
	}
}

func TestRegisterAndHeartbeat(t *testing.T) {
	var paths []string
	var registration Registration
	var heartbeat Heartbeat
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer service-token" {
			t.Fatalf("authorization header was not set")
		}
		if r.URL.Path == "/services/register" {
			if err := json.NewDecoder(r.Body).Decode(&registration); err != nil {
				t.Fatal(err)
			}
		}
		if r.URL.Path == "/services/heartbeat" {
			if err := json.NewDecoder(r.Body).Decode(&heartbeat); err != nil {
				t.Fatal(err)
			}
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	client := Client{
		BaseURL:          server.URL,
		Token:            "service-token",
		ServiceID:        "observability-01",
		ServiceName:      "Observability",
		ServicePublicURL: "https://observability.example.com",
		Version:          "0.1.0",
		HeartbeatEvery:   time.Second,
		HTTP:             server.Client(),
	}
	if err := client.Register(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := client.Heartbeat(t.Context()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(paths, ",") != "/services/register,/services/heartbeat" {
		t.Fatalf("unexpected paths: %#v", paths)
	}
	if registration.ServiceType != "observability" || registration.ServiceID != "observability-01" || registration.Capabilities["incident_detection"] != true {
		t.Fatalf("unexpected registration: %#v", registration)
	}
	if registration.OS != runtime.GOOS || registration.Arch != runtime.GOARCH {
		t.Fatalf("registration did not include runtime platform: %#v", registration)
	}
	if registration.Commit != version.Commit || registration.BuildDate != version.BuildDate {
		t.Fatalf("registration did not include build metadata: %#v", registration)
	}
	if heartbeat.OS != runtime.GOOS || heartbeat.Arch != runtime.GOARCH || heartbeat.Capabilities["diagnostics"] != true {
		t.Fatalf("heartbeat did not include platform/capabilities: %#v", heartbeat)
	}
	if heartbeat.Commit != version.Commit || heartbeat.BuildDate != version.BuildDate {
		t.Fatalf("heartbeat did not include build metadata: %#v", heartbeat)
	}
	if heartbeat.Metrics["observability.goroutines"] == nil || heartbeat.Metrics["observability.uptime_seconds"] == nil {
		t.Fatalf("heartbeat did not include observability metrics: %#v", heartbeat.Metrics)
	}
	if heartbeat.Metrics["node.cpu_count"] == nil || heartbeat.Metrics["process.heap_alloc_bytes"] == nil || heartbeat.Metrics["process.uptime_seconds"] == nil {
		t.Fatalf("heartbeat did not include host/process metrics: %#v", heartbeat.Metrics)
	}
}

func TestRegisterRejectsInvalidPublicURL(t *testing.T) {
	client := Client{BaseURL: "https://control.example.com", Token: "service-token", ServiceID: "observability-01", ServicePublicURL: "file:///tmp/socket"}
	if err := client.Register(t.Context()); err == nil {
		t.Fatal("expected invalid service public URL to fail")
	}
}

func TestRegisterRejectsRemoteHTTPPublicURL(t *testing.T) {
	client := Client{BaseURL: "https://control.example.com", Token: "service-token", ServiceID: "observability-01", ServicePublicURL: "http://observability.example.com"}
	err := client.Register(t.Context())
	if err == nil {
		t.Fatal("expected remote http service public URL to fail")
	}
	if !strings.Contains(err.Error(), "https for remote hosts") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRegisterRejectsPublicURLQueryOrFragment(t *testing.T) {
	client := Client{BaseURL: "https://control.example.com", Token: "service-token", ServiceID: "observability-01", ServicePublicURL: "https://observability.example.com#frag"}
	err := client.Register(t.Context())
	if err == nil {
		t.Fatal("expected service public URL with fragment to fail")
	}
	if !strings.Contains(err.Error(), "query or fragment") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRegisterAllowsDockerComposeObservabilityHTTPPublicURL(t *testing.T) {
	var registration Registration
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&registration); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	const publicURL = "http://observability:8080"
	client := Client{
		BaseURL:          server.URL,
		Token:            "service-token",
		ServiceID:        "observability-01",
		ServicePublicURL: publicURL,
		HTTP:             server.Client(),
	}
	if err := client.Register(t.Context()); err != nil {
		t.Fatalf("expected exact Docker Compose observability host to be allowed: %v", err)
	}
	if registration.PublicURL != publicURL {
		t.Fatalf("unexpected registered public URL: %q", registration.PublicURL)
	}
}

func TestServicePublicURLHTTPHostExceptionIsScoped(t *testing.T) {
	if err := validateHTTPURL("http://observability:8080", "CONTROL_PANEL_URL"); err == nil {
		t.Fatal("expected Docker Compose observability HTTP host to remain rejected for the control panel")
	}
	if err := validateHTTPURL("http://:8080", "CONTROL_PANEL_URL"); err == nil {
		t.Fatal("expected empty HTTP hostname to remain rejected for the control panel")
	}

	for _, publicURL := range []string{
		"http://worker:8080",
		"http://metrics:8080",
		"http://observability.local:8080",
		"http://observability-1:8080",
	} {
		t.Run(publicURL, func(t *testing.T) {
			if err := validateServicePublicURL(publicURL, "SERVICE_PUBLIC_URL"); err == nil {
				t.Fatal("expected non-observability HTTP host to fail")
			}
		})
	}
}

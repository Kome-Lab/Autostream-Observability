package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/example/autostream-observability/internal/auth"
	"github.com/example/autostream-observability/internal/control"
	"github.com/example/autostream-observability/internal/store"
	"github.com/example/autostream-observability/internal/version"
)

func TestUpdaterVersionIsUnauthenticatedAndIdentityBound(t *testing.T) {
	previousVersion := version.Version
	version.Version = "v1.1.1"
	t.Setenv("SERVICE_VERSION", "v9.9.9")
	t.Setenv("SERVICE_ID", "wrong-fallback")
	t.Cleanup(func() { version.Version = previousVersion })

	path := filepath.Join(t.TempDir(), "config.yml")
	t.Setenv("AUTOSTREAM_NODE_CONFIG", path)
	writeNodeListenerCredentialForVerifierTest(t, path, control.ServiceType, "9")
	body := `panel:
  url: "https://panel.example.jp"
node:
  id: "observability-probe-01"
  name: "Observability Probe"
  type: "observability"
listener:
  credential: "node-listener.json"
api:
  host: "observability.example.jp"
  port: 8443
  ssl_enabled: true
auth:
  token_id: "token-id"
  token: "runtime-secret"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	handler := NewServerWithStoreAndAuth(control.ServiceType, store.NewMemoryStore(), auth.NewVerifierFromRawTokens("service-token"))
	req := httptest.NewRequest(http.MethodGet, "/updater/version", nil)
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
	}
	if got := res.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type = %q", got)
	}
	if got := res.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache control = %q", got)
	}
	var response map[string]any
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if len(response) != 4 ||
		response["version"] != version.Current() ||
		response["service_id"] != "observability-probe-01" ||
		response["service_type"] != control.ServiceType ||
		response["config_revision"] != float64(9) {
		t.Fatalf("unexpected updater identity response: %#v", response)
	}

	methodReq := httptest.NewRequest(http.MethodPost, "/updater/version", nil)
	methodRes := httptest.NewRecorder()
	handler.ServeHTTP(methodRes, methodReq)
	if methodRes.Code != http.StatusMethodNotAllowed {
		t.Fatalf("updater version POST status = %d body = %s", methodRes.Code, methodRes.Body.String())
	}
	if got := methodRes.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("updater version POST cache control = %q", got)
	}
	if got := methodRes.Header().Get("Allow"); !strings.Contains(got, http.MethodGet) {
		t.Fatalf("updater version POST Allow = %q", got)
	}
}

func TestNewServerFailsClosedOnInvalidListenerConfigRevision(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yml")
	writeNodeConfigForVerifierTest(t, configPath, control.ServiceType)
	writeNodeListenerCredentialForVerifierTest(t, configPath, control.ServiceType, "0")
	t.Setenv("AUTOSTREAM_NODE_CONFIG", configPath)
	defer func() {
		if recover() == nil {
			t.Fatal("NewServer must reject an invalid listener config_revision")
		}
	}()
	_ = NewServerWithStoreAndAuth(control.ServiceType, store.NewMemoryStore(), auth.Verifier{})
}

func TestRootAndStatusUseNodeConfigServiceID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	t.Setenv("AUTOSTREAM_NODE_CONFIG", path)
	writeNodeListenerCredentialForVerifierTest(t, path, control.ServiceType, "7")
	body := `panel:
  url: "https://panel.example.jp"
node:
  id: "o11y-lab-web-kagoya-01"
  name: "Kome-Lab Web Observability"
  type: "observability"
listener:
  credential: "node-listener.json"
api:
  host: "ass-o11y.studio-kometubu.jp"
  port: 443
  ssl_enabled: true
auth:
  token_id: "token-id"
  token: "runtime-secret"
`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	handler := NewServerWithStoreAuthz("observability", store.NewMemoryStore(), auth.Verifier{}, auth.Verifier{})

	rootReq := httptest.NewRequest(http.MethodGet, "/", nil)
	rootRes := httptest.NewRecorder()
	handler.ServeHTTP(rootRes, rootReq)
	if rootRes.Code != http.StatusOK {
		t.Fatalf("root status = %d body = %s", rootRes.Code, rootRes.Body.String())
	}
	if !strings.Contains(rootRes.Body.String(), `"service_id":"o11y-lab-web-kagoya-01"`) || !strings.Contains(rootRes.Body.String(), `"/metrics"`) || !strings.Contains(rootRes.Body.String(), `"auth_required":true`) {
		t.Fatalf("root response should expose safe operator status and protected metrics endpoint: %s", rootRes.Body.String())
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/status", nil)
	statusRes := httptest.NewRecorder()
	handler.ServeHTTP(statusRes, statusReq)
	if statusRes.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", statusRes.Code, statusRes.Body.String())
	}
	if !strings.Contains(statusRes.Body.String(), `"service_id":"o11y-lab-web-kagoya-01"`) {
		t.Fatalf("status response should use node config service_id: %s", statusRes.Body.String())
	}

	metricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metricsRes := httptest.NewRecorder()
	handler.ServeHTTP(metricsRes, metricsReq)
	if metricsRes.Code != http.StatusUnauthorized {
		t.Fatalf("metrics should remain token protected, got %d body = %s", metricsRes.Code, metricsRes.Body.String())
	}
}

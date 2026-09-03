package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/example/autostream-observability/internal/auth"
	"github.com/example/autostream-observability/internal/control"
	"github.com/example/autostream-observability/internal/store"
)

func TestUpdaterVersionPendingThenBindsAuthoritativeIdentityAndRejectsDrift(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yml")
	credentialDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credentialDir, 0700); err != nil {
		t.Fatal(err)
	}
	credentialPath := filepath.Join(credentialDir, "node-listener.json")
	t.Setenv("AUTOSTREAM_NODE_CONFIG", configPath)
	t.Setenv("SERVICE_ID", "placeholder-observability")
	t.Setenv("CREDENTIALS_DIRECTORY", credentialDir)

	latch := NewUpdaterIdentityLatch(control.ServiceType)
	handler := NewServerWithStoreAuthzAndUpdaterIdentity(control.ServiceType, store.NewMemoryStore(), auth.Verifier{}, auth.Verifier{}, latch)
	assertUpdaterIdentityStatus(t, handler, http.StatusServiceUnavailable, "")

	writeUpdaterIdentityNodeConfig(t, configPath, credentialPath, "observability-authoritative", control.ServiceType, 13)
	identity, err := latch.ResolveFromEnv()
	if err != nil {
		t.Fatalf("registration identity resolve failed: %v", err)
	}
	if identity.ServiceID != "observability-authoritative" {
		t.Fatalf("registration identity = %q, want observability-authoritative", identity.ServiceID)
	}
	assertUpdaterIdentityStatus(t, handler, http.StatusOK, "observability-authoritative")

	writeUpdaterIdentityListenerCredential(t, credentialPath, control.ServiceType, 14)
	assertUpdaterIdentityStatus(t, handler, http.StatusServiceUnavailable, "")
	writeUpdaterIdentityListenerCredential(t, credentialPath, control.ServiceType, 13)

	writeUpdaterIdentityNodeConfig(t, configPath, credentialPath, "observability-drifted", control.ServiceType, 13)
	assertUpdaterIdentityStatus(t, handler, http.StatusServiceUnavailable, "")
}

func assertUpdaterIdentityStatus(t *testing.T, handler http.Handler, wantStatus int, wantServiceID string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/updater/version", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != wantStatus {
		t.Fatalf("status = %d body = %s, want %d", res.Code, res.Body.String(), wantStatus)
	}
	if got := res.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache control = %q, want no-store", got)
	}
	if wantServiceID != "" && !strings.Contains(res.Body.String(), `"service_id":"`+wantServiceID+`"`) {
		t.Fatalf("response does not contain authoritative service id %q: %s", wantServiceID, res.Body.String())
	}
	if wantServiceID == "" && strings.Contains(res.Body.String(), "service_id") {
		t.Fatalf("unavailable response leaked a service identity: %s", res.Body.String())
	}
}

func writeUpdaterIdentityNodeConfig(t *testing.T, path, credentialPath, serviceID, serviceType string, revision int64) {
	t.Helper()
	writeUpdaterIdentityListenerCredential(t, credentialPath, serviceType, revision)
	body := fmt.Sprintf(`panel:
  url: "https://panel.example.com"
node:
  id: %q
  name: "Updater Probe"
  type: %q
listener:
  credential: "node-listener.json"
api:
  host: "observability.example.jp"
  port: 8443
  ssl_enabled: true
auth:
  token_id: "token-id"
  token: "runtime-token"
`, serviceID, serviceType)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeUpdaterIdentityListenerCredential(t *testing.T, path, serviceType string, revision int64) {
	t.Helper()
	body := fmt.Sprintf(`{"schema_version":2,"service_type":%q,"bind_address":"127.0.0.1:18082","config_revision":%d}`, serviceType, revision)
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

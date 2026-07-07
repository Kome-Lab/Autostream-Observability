package control

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFromEnvUsesNodeConfig(t *testing.T) {
	path := writeNodeConfigForTest(t, "observability")
	t.Setenv("AUTOSTREAM_NODE_CONFIG", path)
	client := FromEnv()
	if client.BaseURL != "https://panel.example.jp" || client.Token != "runtime-secret" || client.ServiceID != "observability-01" || client.ServiceName != "Observability 01" || client.ServicePublicURL != "https://observability.example.jp:8443" {
		t.Fatalf("unexpected config from node file: %#v", client)
	}
	if !client.Enabled() {
		t.Fatalf("node config should enable client: %#v", client)
	}
	if got := NodeRuntimeTokenFromEnv(); got != "runtime-secret" {
		t.Fatalf("runtime token = %q", got)
	}
}

func TestFromEnvRejectsWrongNodeType(t *testing.T) {
	path := writeNodeConfigForTest(t, "worker")
	t.Setenv("AUTOSTREAM_NODE_CONFIG", path)
	client := FromEnv()
	if client.Enabled() || client.ConfigError == "" {
		t.Fatalf("expected wrong node type to disable client: %#v", client)
	}
}

func TestFromEnvTreatsMissingNodeConfigAsPending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "config.yml")
	t.Setenv("AUTOSTREAM_NODE_CONFIG", path)
	t.Setenv("CONTROL_PANEL_URL", "")
	t.Setenv("CONTROL_PANEL_TOKEN", "")
	client := FromEnv()
	if client.ConfigError != "" {
		t.Fatalf("missing node config should not be fatal: %#v", client)
	}
	if client.Enabled() {
		t.Fatalf("missing node config must not enable client: %#v", client)
	}
	if !NodeConfigPendingFromEnv() {
		t.Fatal("missing node config should be reported as pending")
	}
	if got := NodeRuntimeTokenFromEnv(); got != "" {
		t.Fatalf("runtime token = %q, want empty", got)
	}
}

func writeNodeConfigForTest(t *testing.T, nodeType string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	body := `panel:
  url: "https://panel.example.jp"
node:
  id: "observability-01"
  name: "Observability 01"
  type: "` + nodeType + `"
api:
  host: "observability.example.jp"
  port: 8443
  ssl_enabled: true
auth:
  token_id: "token-id"
  token: "runtime-secret"
`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

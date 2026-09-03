package observability_test

import (
	"os"
	"strings"
	"testing"
)

func TestHostBindContractUsesCanonicalNodeConfig(t *testing.T) {
	env := readContractFile(t, ".env.example")
	if strings.Contains(env, "OBSERVABILITY_BIND_ADDR") {
		t.Error(".env.example must not expose the removed bind-address fallback")
	}
	for _, required := range []string{
		"AUTOSTREAM_OBSERVABILITY_PORT=8082",
		"AUTOSTREAM_OBSERVABILITY_CONTAINER_PORT=8080",
		"listener.credential: node-listener.json",
		"bind_address and config_revision",
	} {
		if !strings.Contains(env, required) {
			t.Errorf(".env.example is missing Docker port default %q", required)
		}
	}
	for _, removed := range []string{"AUTOSTREAM_CONFIG_REVISION", "api.bind_host"} {
		if strings.Contains(env, removed) {
			t.Errorf(".env.example retains removed listener environment contract %q", removed)
		}
	}

	unit := readContractFile(t, "systemd/autostream-observability.service.example")
	primaryEnv := "EnvironmentFile=/etc/autostream/observability.env"
	listenerCredential := "LoadCredential=node-listener.json:/opt/autostream/local-executor/ports/observability.json"
	if !strings.Contains(unit, primaryEnv) {
		t.Error("systemd unit must load non-node service settings from observability.env")
	}
	if !strings.Contains(unit, listenerCredential) {
		t.Error("systemd unit must load the Panel-issued listener credential")
	}
	if strings.Contains(unit, "/opt/autostream/local-executor/ports/observability.env") || strings.Contains(unit, "OBSERVABILITY_BIND_ADDR") || strings.Contains(unit, "AUTOSTREAM_CONFIG_REVISION") {
		t.Error("systemd unit retained the removed bind environment sidecar")
	}
	if strings.Contains(unit, "8082") {
		t.Error("systemd unit must not hard-code the Observability port")
	}
	install := readContractFile(t, "release/README.install.md")
	for _, required := range []string{
		"node-listener.json",
		"listener.credential",
		"bind_address",
		"config_revision",
		"version, service_id, service_type, and config_revision",
		"sudo vi /etc/autostream/observability.env",
		"sudo systemctl enable --now autostream-observability",
		"sudo systemctl restart autostream-observability",
		"http://[::1]:18082/health",
	} {
		if !strings.Contains(install, required) {
			t.Errorf("release install guide is missing %q", required)
		}
	}

	readme := readContractFile(t, "README.md")
	for _, required := range []string{
		"node-listener.json",
		"listener.credential",
		"bind_address",
		"The production health authority is the host Local Executor.",
		"intentionally omit an in-container `healthcheck`",
		"does not add or repurpose `curl`, `wget`, or another unrelated executable",
		"probes the loopback published port for both `/health` and `/updater/version`",
		"the published port is the health port",
	} {
		if !strings.Contains(readme, required) {
			t.Errorf("README is missing Docker published-port boundary %q", required)
		}
	}
}

func TestDockerBindContractSeparatesHostAndContainerPorts(t *testing.T) {
	base := readContractFile(t, "docker-compose.yml")
	for _, required := range []string{
		"AUTOSTREAM_NODE_CONFIG: /etc/autostream-observability/config.yml",
		"CREDENTIALS_DIRECTORY: /run/autostream-credentials",
		"source: node-listener",
		"target: /run/autostream-credentials/node-listener.json",
		`"service_type":"observability"`,
		`"config_revision":${AUTOSTREAM_CONFIG_REVISION:?AUTOSTREAM_CONFIG_REVISION is required}`,
		`127.0.0.1:${AUTOSTREAM_OBSERVABILITY_PORT:-8082}:${AUTOSTREAM_OBSERVABILITY_CONTAINER_PORT:-8080}`,
	} {
		if !strings.Contains(base, required) {
			t.Errorf("base compose is missing %q", required)
		}
	}
	if strings.Count(base, "${AUTOSTREAM_CONFIG_REVISION:") != 1 || strings.Contains(base, "\n      AUTOSTREAM_CONFIG_REVISION:") {
		t.Error("base compose must use the revision only as the node-listener JSON generation input")
	}

	local := readContractFile(t, "docker-compose.local.yml")
	for _, required := range []string{
		"AUTOSTREAM_NODE_CONFIG: /etc/autostream-observability/config.yml",
		`127.0.0.1:${AUTOSTREAM_OBSERVABILITY_PORT:-8082}:${AUTOSTREAM_OBSERVABILITY_CONTAINER_PORT:-8080}`,
	} {
		if !strings.Contains(local, required) {
			t.Errorf("local compose is missing %q", required)
		}
	}

	production := readContractFile(t, "docker-compose.prod.yml")
	for _, required := range []string{
		"AUTOSTREAM_NODE_CONFIG: /etc/autostream-observability/config.yml",
		"ports: !override",
		`127.0.0.1:${AUTOSTREAM_OBSERVABILITY_PORT:-8082}:${AUTOSTREAM_OBSERVABILITY_CONTAINER_PORT:-8080}`,
	} {
		if !strings.Contains(production, required) {
			t.Errorf("production compose is missing %q", required)
		}
	}
	for name, body := range map[string]string{"base": base, "local": local, "production": production} {
		for _, removed := range []string{"OBSERVABILITY_BIND_ADDR"} {
			if strings.Contains(body, removed) {
				t.Errorf("%s compose retained removed runtime env key %q", name, removed)
			}
		}
		if strings.Contains(body, "\n      AUTOSTREAM_CONFIG_REVISION:") || (name != "base" && strings.Contains(body, "AUTOSTREAM_CONFIG_REVISION")) {
			t.Errorf("%s compose injects the removed runtime revision environment key", name)
		}
	}
}

func readContractFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

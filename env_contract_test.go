package observability_test

import (
	"os"
	"strings"
	"testing"
)

func TestHostBindContractIsConfigurableAndUnprivileged(t *testing.T) {
	env := readContractFile(t, ".env.example")
	if !strings.Contains(env, "OBSERVABILITY_BIND_ADDR=127.0.0.1:8082") {
		t.Error(".env.example must retain the host default on port 8082")
	}
	for _, required := range []string{
		"AUTOSTREAM_OBSERVABILITY_PORT=8082",
		"AUTOSTREAM_OBSERVABILITY_CONTAINER_PORT=8080",
	} {
		if !strings.Contains(env, required) {
			t.Errorf(".env.example is missing Docker port default %q", required)
		}
	}
	if !strings.Contains(env, "1024") || !strings.Contains(env, "65535") {
		t.Error(".env.example must document the supported unprivileged port range")
	}
	if !strings.Contains(env, "legacy 127.0.0.1:8080 fallback") {
		t.Error(".env.example must document the env-unset legacy port fallback")
	}
	if !strings.Contains(env, "AUTOSTREAM_CONFIG_REVISION=1") ||
		!strings.Contains(strings.ToLower(env), "root-owned") {
		t.Error(".env.example must document the root-owned updater probe config revision")
	}

	unit := readContractFile(t, "systemd/autostream-observability.service.example")
	primaryEnv := "EnvironmentFile=/etc/autostream/observability.env"
	managedEnv := "EnvironmentFile=-/opt/autostream/local-executor/ports/observability.env"
	if !strings.Contains(unit, primaryEnv) {
		t.Error("systemd unit must load the configurable bind address from observability.env")
	}
	if !strings.Contains(unit, managedEnv) {
		t.Error("systemd unit must optionally load the Control Panel managed port sidecar")
	}
	if strings.Index(unit, managedEnv) <= strings.Index(unit, primaryEnv) {
		t.Error("managed port sidecar must load after observability.env so its bind address and revision win")
	}
	if strings.Contains(unit, "8082") {
		t.Error("systemd unit must not hard-code the Observability port")
	}
	if !strings.Contains(unit, "AUTOSTREAM_CONFIG_REVISION") ||
		!strings.Contains(unit, "root-owned") {
		t.Error("systemd unit must document the root-owned config revision environment")
	}

	install := readContractFile(t, "release/README.install.md")
	for _, required := range []string{
		"AUTOSTREAM_CONFIG_REVISION=1",
		"version, service_id, service_type, and config_revision",
		`PROBE_HOST="${PROBE_HOST:-127.0.0.1}"`,
		"PROBE_HOST='[::1]'",
	} {
		if !strings.Contains(install, required) {
			t.Errorf("release install guide is missing %q", required)
		}
	}

	readme := readContractFile(t, "README.md")
	for _, required := range []string{
		"host/reverse-proxy responsibility",
		"`1024` through `65535`",
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
		"AUTOSTREAM_CONFIG_REVISION: ${AUTOSTREAM_CONFIG_REVISION:-1}",
		"OBSERVABILITY_BIND_ADDR: 0.0.0.0:${AUTOSTREAM_OBSERVABILITY_CONTAINER_PORT:-8080}",
		`127.0.0.1:${AUTOSTREAM_OBSERVABILITY_PORT:-8082}:${AUTOSTREAM_OBSERVABILITY_CONTAINER_PORT:-8080}`,
	} {
		if !strings.Contains(base, required) {
			t.Errorf("base compose is missing %q", required)
		}
	}

	local := readContractFile(t, "docker-compose.local.yml")
	for _, required := range []string{
		"AUTOSTREAM_CONFIG_REVISION: ${AUTOSTREAM_CONFIG_REVISION:-1}",
		"OBSERVABILITY_BIND_ADDR: 0.0.0.0:${AUTOSTREAM_OBSERVABILITY_CONTAINER_PORT:-8080}",
		`127.0.0.1:${AUTOSTREAM_OBSERVABILITY_PORT:-8082}:${AUTOSTREAM_OBSERVABILITY_CONTAINER_PORT:-8080}`,
	} {
		if !strings.Contains(local, required) {
			t.Errorf("local compose is missing %q", required)
		}
	}

	production := readContractFile(t, "docker-compose.prod.yml")
	for _, required := range []string{
		"AUTOSTREAM_CONFIG_REVISION: ${AUTOSTREAM_CONFIG_REVISION:-1}",
		"OBSERVABILITY_BIND_ADDR: 0.0.0.0:${AUTOSTREAM_OBSERVABILITY_CONTAINER_PORT:-8080}",
		"ports: !override",
		`127.0.0.1:${AUTOSTREAM_OBSERVABILITY_PORT:-8082}:${AUTOSTREAM_OBSERVABILITY_CONTAINER_PORT:-8080}`,
	} {
		if !strings.Contains(production, required) {
			t.Errorf("production compose is missing %q", required)
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

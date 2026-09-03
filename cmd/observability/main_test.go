package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/example/autostream-observability/internal/control"
	"github.com/example/autostream-observability/internal/httpapi"
)

func TestObservabilityBindAddrRequiresNodeConfigValue(t *testing.T) {
	if _, err := observabilityBindAddr(""); err == nil {
		t.Fatal("missing node config bind address was accepted")
	}
}

func TestObservabilityBindAddrAcceptsConfiguredUnprivilegedPort(t *testing.T) {
	for _, value := range []string{
		"127.0.0.1:1024",
		"127.0.0.1:18082",
		"127.0.0.1:65535",
	} {
		t.Run(value, func(t *testing.T) {
			got, err := observabilityBindAddr(value)
			if err != nil {
				t.Fatal(err)
			}
			if got != value {
				t.Fatalf("bind address = %q, want %q", got, value)
			}
		})
	}
}

func TestObservabilityBindAddrAcceptsIPv6(t *testing.T) {
	got, err := observabilityBindAddr("[::1]:18082")
	if err != nil {
		t.Fatal(err)
	}
	if got != "[::1]:18082" {
		t.Fatalf("bind address = %q, want [::1]:18082", got)
	}
}

func TestObservabilityBindAddrRejectsInvalidOrPrivilegedPort(t *testing.T) {
	for _, value := range []string{
		"127.0.0.1",
		"127.0.0.1:0",
		"127.0.0.1:1023",
		"127.0.0.1:65536",
		"127.0.0.1:not-a-port",
	} {
		t.Run(strings.ReplaceAll(value, ":", "_"), func(t *testing.T) {
			if _, err := observabilityBindAddr(value); err == nil {
				t.Fatalf("observabilityBindAddr() accepted %q", value)
			}
		})
	}
}

func TestRequireMatchingUpdaterIdentityRejectsRegistrationIDDrift(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	credentialDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credentialDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(credentialDir, "node-listener.json"), []byte(`{"schema_version":2,"service_type":"observability","bind_address":"127.0.0.1:18082","config_revision":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("panel:\n  url: https://panel.example.jp\nnode:\n  id: observability-authoritative\n  name: Observability\n  type: observability\nlistener:\n  credential: node-listener.json\napi:\n  host: observability.example.jp\n  port: 8443\n  ssl_enabled: true\nauth:\n  token: runtime-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUTOSTREAM_NODE_CONFIG", path)
	t.Setenv("CREDENTIALS_DIRECTORY", credentialDir)
	latch := httpapi.NewUpdaterIdentityLatch(control.ServiceType)

	if err := requireMatchingUpdaterIdentity(latch, "observability-authoritative"); err != nil {
		t.Fatalf("matching registration identity failed: %v", err)
	}
	if err := requireMatchingUpdaterIdentity(latch, "observability-drifted"); !errors.Is(err, httpapi.ErrUpdaterIdentityDrift) {
		t.Fatalf("registration identity drift error = %v", err)
	}
}

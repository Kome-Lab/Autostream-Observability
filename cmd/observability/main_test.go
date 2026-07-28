package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/example/autostream-observability/internal/control"
	"github.com/example/autostream-observability/internal/httpapi"
)

func TestObservabilityBindAddrFromEnvPreservesLegacyFallbackPort8080(t *testing.T) {
	t.Setenv("OBSERVABILITY_BIND_ADDR", "")

	got, err := observabilityBindAddrFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if got != "127.0.0.1:8080" {
		t.Fatalf("default bind address = %q, want bridge-compatible 127.0.0.1:8080", got)
	}
}

func TestObservabilityBindAddrFromEnvAcceptsConfigurableUnprivilegedPort(t *testing.T) {
	for _, value := range []string{
		"127.0.0.1:1024",
		"127.0.0.1:18082",
		"127.0.0.1:65535",
	} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("OBSERVABILITY_BIND_ADDR", value)
			got, err := observabilityBindAddrFromEnv()
			if err != nil {
				t.Fatal(err)
			}
			if got != value {
				t.Fatalf("bind address = %q, want %q", got, value)
			}
		})
	}
}

func TestObservabilityBindAddrFromEnvAcceptsIPv6(t *testing.T) {
	t.Setenv("OBSERVABILITY_BIND_ADDR", "[::1]:18082")

	got, err := observabilityBindAddrFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if got != "[::1]:18082" {
		t.Fatalf("bind address = %q, want [::1]:18082", got)
	}
}

func TestObservabilityBindAddrFromEnvRejectsInvalidOrPrivilegedPort(t *testing.T) {
	for _, value := range []string{
		"127.0.0.1",
		"127.0.0.1:0",
		"127.0.0.1:1023",
		"127.0.0.1:65536",
		"127.0.0.1:not-a-port",
	} {
		t.Run(strings.ReplaceAll(value, ":", "_"), func(t *testing.T) {
			t.Setenv("OBSERVABILITY_BIND_ADDR", value)
			if _, err := observabilityBindAddrFromEnv(); err == nil {
				t.Fatalf("observabilityBindAddrFromEnv() accepted %q", value)
			}
		})
	}
}

func TestRequireMatchingUpdaterIdentityRejectsRegistrationIDDrift(t *testing.T) {
	t.Setenv("AUTOSTREAM_NODE_CONFIG", "")
	t.Setenv("SERVICE_ID", "observability-authoritative")
	latch := httpapi.NewUpdaterIdentityLatch(control.ServiceType)

	if err := requireMatchingUpdaterIdentity(latch, "observability-authoritative"); err != nil {
		t.Fatalf("matching registration identity failed: %v", err)
	}
	if err := requireMatchingUpdaterIdentity(latch, "observability-drifted"); !errors.Is(err, httpapi.ErrUpdaterIdentityDrift) {
		t.Fatalf("registration identity drift error = %v", err)
	}
}

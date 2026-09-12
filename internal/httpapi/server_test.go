package httpapi

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/example/autostream-observability/internal/auth"
	"github.com/example/autostream-observability/internal/notifications"
	"github.com/example/autostream-observability/internal/store"
)

func TestMain(m *testing.M) {
	tempDir, err := os.MkdirTemp("", "autostream-observability-httpapi-")
	if err != nil {
		panic(err)
	}
	configPath := filepath.Join(tempDir, "node-config.yml")
	credentialDir := filepath.Join(tempDir, "credentials")
	if err := os.Mkdir(credentialDir, 0700); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(credentialDir, "node-listener.json"), []byte(`{"schema_version":2,"service_type":"observability","bind_address":"127.0.0.1:18082","config_revision":1}`), 0600); err != nil {
		panic(err)
	}
	config := []byte("panel:\n  url: https://panel.example.test\nnode:\n  id: observability-test\n  name: Observability Test\n  type: observability\nlistener:\n  credential: node-listener.json\napi:\n  host: observability.example.test\n  port: 8082\n  ssl_enabled: false\nauth:\n  token_id: test-token-id\n  token: runtime-test-token\n")
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		panic(err)
	}
	previous, hadPrevious := os.LookupEnv("AUTOSTREAM_NODE_CONFIG")
	if err := os.Setenv("AUTOSTREAM_NODE_CONFIG", configPath); err != nil {
		panic(err)
	}
	previousCredentials, hadPreviousCredentials := os.LookupEnv("CREDENTIALS_DIRECTORY")
	if err := os.Setenv("CREDENTIALS_DIRECTORY", credentialDir); err != nil {
		panic(err)
	}
	code := m.Run()
	if hadPrevious {
		_ = os.Setenv("AUTOSTREAM_NODE_CONFIG", previous)
	} else {
		_ = os.Unsetenv("AUTOSTREAM_NODE_CONFIG")
	}
	if hadPreviousCredentials {
		_ = os.Setenv("CREDENTIALS_DIRECTORY", previousCredentials)
	} else {
		_ = os.Unsetenv("CREDENTIALS_DIRECTORY")
	}
	_ = os.RemoveAll(tempDir)
	os.Exit(code)
}

func newTestServer(st store.Store) http.Handler {
	return NewServerWithStoreAndAuth("observability", st, auth.NewVerifierFromRawTokens("service-token"))
}

type fakeNotifier struct {
	count int
}

type fakeEmailRelay struct {
	calls int
	err   error
}

type fakeSafeEmailError string

func (e fakeSafeEmailError) Error() string { return string(e) }

func (e fakeSafeEmailError) SafeDeliveryCode() string { return string(e) }

func (f *fakeEmailRelay) SendNotificationEmail(_ context.Context, _ []string, _, _ string) error {
	f.calls++
	return f.err
}

func (n *fakeNotifier) NotifyIncidentOpened(ctx context.Context, incident store.Incident) ([]notifications.DeliveryResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	n.count++
	return []notifications.DeliveryResult{{EventType: "incident.opened", Channel: "generic", Target: "https://<WEBHOOK_HOST>/<WEBHOOK_PATH>", Status: "success"}}, nil
}

type eventRecordingNotifier struct {
	events      []string
	incidents   []store.Incident
	deadline    time.Time
	hasDeadline bool
}

func (n *eventRecordingNotifier) NotifyIncidentOpened(ctx context.Context, incident store.Incident) ([]notifications.DeliveryResult, error) {
	return n.NotifyIncidentEvent(ctx, "incident.opened", incident)
}

func (n *eventRecordingNotifier) NotifyIncidentEvent(ctx context.Context, eventType string, incident store.Incident) ([]notifications.DeliveryResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	n.deadline, n.hasDeadline = ctx.Deadline()
	n.events = append(n.events, eventType)
	n.incidents = append(n.incidents, incident)
	return []notifications.DeliveryResult{{EventType: eventType, Channel: "slack", Target: "https://hooks.slack.com/<WEBHOOK_PATH>", Status: "success"}}, nil
}

type failingNotifier struct{}

func (f failingNotifier) NotifyIncidentOpened(ctx context.Context, incident store.Incident) ([]notifications.DeliveryResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("Post \"https://discord.com/api/webhooks/id/secret-token\": forbidden")
}

type partialFailureNotifier struct{}

func (p partialFailureNotifier) NotifyIncidentOpened(ctx context.Context, incident store.Incident) ([]notifications.DeliveryResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return []notifications.DeliveryResult{
		{EventType: "incident.opened", Channel: "email", Target: "o***s@<EMAIL_DOMAIN>", Status: "success"},
		{EventType: "incident.opened", Channel: "discord", Target: "https://discord.com/api/webhooks/id/secret-token", Status: "failure", Error: "Post \"https://discord.com/api/webhooks/id/secret-token\": forbidden with smtp-password"},
	}, errors.New("partial notification failure")
}

func writeNodeConfigForVerifierTest(t *testing.T, path, nodeType string) {
	t.Helper()
	writeNodeListenerCredentialForVerifierTest(t, path, nodeType, "7")
	body := `panel:
  url: "https://panel.example.jp"
node:
  id: "observability-01"
  name: "Observability 01"
  type: "` + nodeType + `"
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
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

func writeNodeListenerCredentialForVerifierTest(t *testing.T, configPath, serviceType, revision string) {
	t.Helper()
	credentialDir := filepath.Join(filepath.Dir(configPath), "credentials")
	if err := os.MkdirAll(credentialDir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", credentialDir)
	body := `{"schema_version":2,"service_type":"` + serviceType + `","bind_address":"127.0.0.1:18082","config_revision":` + revision + `}`
	if err := os.WriteFile(filepath.Join(credentialDir, "node-listener.json"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

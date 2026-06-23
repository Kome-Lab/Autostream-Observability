package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

var (
	captureExecMu    sync.Mutex
	captureExecQuery string
	captureExecArgs  []driver.NamedValue
)

func init() {
	sql.Register("autostream_observability_capture_exec", captureExecDriver{})
}

type captureExecDriver struct{}

func (captureExecDriver) Open(name string) (driver.Conn, error) {
	return captureExecConn{}, nil
}

type captureExecConn struct{}

func (captureExecConn) Prepare(query string) (driver.Stmt, error) {
	return nil, errors.New("prepare is not implemented by captureExecConn")
}

func (captureExecConn) Close() error {
	return nil
}

func (captureExecConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions are not implemented by captureExecConn")
}

func (captureExecConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	captureExecMu.Lock()
	defer captureExecMu.Unlock()
	captureExecQuery = query
	captureExecArgs = append([]driver.NamedValue(nil), args...)
	return driver.RowsAffected(1), nil
}

func TestMariaDBNotificationChannelStoresWebhookURLAsCiphertextAndNonce(t *testing.T) {
	db, err := sql.Open("autostream_observability_capture_exec", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	rawWebhook := "https://discord.com/api/webhooks/123456/secret-token"
	store := MariaDBStore{DB: db, SecretKey: "test-secret-key"}
	created, err := store.CreateNotificationChannel(t.Context(), NotificationChannel{
		ID:         "ntc-webhook",
		Name:       "ops webhook",
		Type:       "discord",
		Enabled:    true,
		WebhookURL: rawWebhook,
	})
	if err != nil {
		t.Fatal(err)
	}
	publicJSON, err := json.Marshal(created)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(publicJSON), rawWebhook) || strings.Contains(string(publicJSON), "secret-token") {
		t.Fatalf("public channel JSON leaked raw webhook URL: %s", publicJSON)
	}

	args := capturedExecArgs(t, "notification_channels")
	webhookCiphertext := namedArgString(t, args, 4)
	webhookNonce := namedArgString(t, args, 5)
	if webhookCiphertext == "" || webhookNonce == "" {
		t.Fatalf("expected webhook ciphertext and nonce, args=%#v", args)
	}
	if strings.Contains(webhookCiphertext, "secret-token") || strings.Contains(webhookCiphertext, rawWebhook) {
		t.Fatalf("webhook ciphertext leaked raw URL: %q", webhookCiphertext)
	}
	decrypted, err := decryptSecret(webhookCiphertext, webhookNonce, store.SecretKey)
	if err != nil {
		t.Fatalf("stored webhook ciphertext could not be decrypted: %v", err)
	}
	if decrypted != rawWebhook {
		t.Fatalf("stored webhook ciphertext decrypted to %q, want %q", decrypted, rawWebhook)
	}
}

func TestMariaDBNotificationChannelStoresSMTPPasswordAsCiphertextAndNonce(t *testing.T) {
	db, err := sql.Open("autostream_observability_capture_exec", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	rawPassword := "smtp-secret-password"
	store := MariaDBStore{DB: db, SecretKey: "test-secret-key"}
	created, err := store.CreateNotificationChannel(t.Context(), NotificationChannel{
		ID:              "ntc-email",
		Name:            "ops email",
		Type:            "email",
		Enabled:         true,
		EmailRecipients: []string{"ops@example.com"},
		SMTPHost:        "smtp.example.com",
		SMTPPort:        587,
		SMTPTLS:         true,
		SMTPFrom:        "alerts@example.com",
		SMTPUsername:    "alerts@example.com",
		SMTPPassword:    rawPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	publicJSON, err := json.Marshal(created)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(publicJSON), rawPassword) {
		t.Fatalf("public channel JSON leaked raw SMTP password: %s", publicJSON)
	}

	args := capturedExecArgs(t, "notification_channels")
	smtpCiphertext := namedArgString(t, args, 13)
	smtpNonce := namedArgString(t, args, 14)
	if smtpCiphertext == "" || smtpNonce == "" {
		t.Fatalf("expected SMTP password ciphertext and nonce, args=%#v", args)
	}
	if strings.Contains(smtpCiphertext, rawPassword) {
		t.Fatalf("SMTP password ciphertext leaked raw password: %q", smtpCiphertext)
	}
	decrypted, err := decryptSecret(smtpCiphertext, smtpNonce, store.SecretKey)
	if err != nil {
		t.Fatalf("stored SMTP password ciphertext could not be decrypted: %v", err)
	}
	if decrypted != rawPassword {
		t.Fatalf("stored SMTP password ciphertext decrypted to %q, want %q", decrypted, rawPassword)
	}
}

func capturedExecArgs(t *testing.T, queryFragment string) []driver.NamedValue {
	t.Helper()
	captureExecMu.Lock()
	defer captureExecMu.Unlock()
	if !strings.Contains(captureExecQuery, queryFragment) {
		t.Fatalf("unexpected captured query: %s", captureExecQuery)
	}
	return append([]driver.NamedValue(nil), captureExecArgs...)
}

func namedArgString(t *testing.T, args []driver.NamedValue, index int) string {
	t.Helper()
	if index >= len(args) {
		t.Fatalf("missing arg index %d in %#v", index, args)
	}
	value, ok := args[index].Value.(string)
	if !ok {
		t.Fatalf("arg index %d is %T, want string", index, args[index].Value)
	}
	return value
}

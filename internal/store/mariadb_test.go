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
	captureExecMu      sync.Mutex
	captureExecRecords []captureExecRecord
)

type captureExecRecord struct {
	query string
	args  []driver.NamedValue
}

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
	return captureExecTx{}, nil
}

type captureExecTx struct{}

func (captureExecTx) Commit() error   { return nil }
func (captureExecTx) Rollback() error { return nil }

func (captureExecConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	captureExecMu.Lock()
	defer captureExecMu.Unlock()
	captureExecRecords = append(captureExecRecords, captureExecRecord{query: query, args: append([]driver.NamedValue(nil), args...)})
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

func TestMariaDBEmailChannelPersistsOnlyGlobalSMTPReference(t *testing.T) {
	db, err := sql.Open("autostream_observability_capture_exec", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	store := MariaDBStore{DB: db, SecretKey: "test-secret-key"}
	created, err := store.CreateNotificationChannel(t.Context(), NotificationChannel{
		ID:               "ntc-global-email",
		Name:             "global email",
		Type:             "email",
		Enabled:          true,
		UseGlobalSMTP:    true,
		UseGlobalSMTPSet: true,
		EmailRecipients:  []string{"ops@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !created.UseGlobalSMTP {
		t.Fatalf("global SMTP create lost its v2 reference: %#v", created)
	}
	base := capturedExec(t, "INSERT INTO notification_channels")
	for _, legacyColumn := range []string{"smtp_host", "smtp_port", "smtp_tls", "smtp_from", "smtp_username", "smtp_password"} {
		if strings.Contains(strings.ToLower(base.query), legacyColumn) {
			t.Fatalf("legacy SMTP column %q remains in v2 insert: %s", legacyColumn, base.query)
		}
	}
	reference := capturedExec(t, "notification_channel_v2_config_references")
	if len(reference.args) != 1 || namedArgString(t, reference.args, 0) != created.ID {
		t.Fatalf("unexpected global SMTP reference insert: %#v", reference.args)
	}
}

func capturedExecArgs(t *testing.T, queryFragment string) []driver.NamedValue {
	return capturedExec(t, queryFragment).args
}

func capturedExec(t *testing.T, queryFragment string) captureExecRecord {
	t.Helper()
	captureExecMu.Lock()
	defer captureExecMu.Unlock()
	for i := len(captureExecRecords) - 1; i >= 0; i-- {
		if strings.Contains(captureExecRecords[i].query, queryFragment) {
			return captureExecRecord{query: captureExecRecords[i].query, args: append([]driver.NamedValue(nil), captureExecRecords[i].args...)}
		}
	}
	t.Fatalf("no captured query contained %q: %#v", queryFragment, captureExecRecords)
	return captureExecRecord{}
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

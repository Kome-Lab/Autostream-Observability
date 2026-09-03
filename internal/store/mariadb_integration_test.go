package store

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/example/autostream-observability/internal/database"
)

func TestMariaDBNotificationChannelIntegrationStoresWebhookSecretAndGlobalSMTPReference(t *testing.T) {
	rawDSN := os.Getenv("AUTOSTREAM_OBSERVABILITY_TEST_DATABASE_URL")
	if rawDSN == "" {
		t.Skip("AUTOSTREAM_OBSERVABILITY_TEST_DATABASE_URL not set")
	}
	dsn, err := database.NormalizeMySQLDSN(rawDSN)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping mariadb: %v", err)
	}
	if err := database.RunEmbeddedMigrations(ctx, db); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	suffix := time.Now().UTC().Format("20060102150405.000000000")
	suffix = strings.NewReplacer(".", "", ":", "", "-", "").Replace(suffix)
	webhookID := "ntc-it-webhook-" + suffix
	emailID := "ntc-it-email-" + suffix
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, "DELETE FROM notification_channels WHERE id IN (?, ?)", webhookID, emailID)
	})

	store := MariaDBStore{DB: db, SecretKey: "integration-test-secret-key"}
	rawWebhook := "https://discord.com/api/webhooks/it/plaintext-webhook-secret"
	if _, err := store.CreateNotificationChannel(ctx, NotificationChannel{
		ID:         webhookID,
		Name:       "integration webhook",
		Type:       "discord",
		Enabled:    true,
		WebhookURL: rawWebhook,
	}); err != nil {
		t.Fatalf("create webhook channel: %v", err)
	}
	if _, err := store.CreateNotificationChannel(ctx, NotificationChannel{
		ID:               emailID,
		Name:             "integration email",
		Type:             "email",
		Enabled:          true,
		UseGlobalSMTP:    true,
		UseGlobalSMTPSet: true,
		EmailRecipients:  []string{"ops@example.com"},
	}); err != nil {
		t.Fatalf("create email channel: %v", err)
	}

	assertNotificationWebhookSecretRow(t, ctx, db, store.SecretKey, webhookID, rawWebhook)
	assertGlobalSMTPReference(t, ctx, db, emailID)

	updatedWebhook := "https://discord.com/api/webhooks/it/updated-plaintext-webhook-secret"
	if _, err := store.UpdateNotificationChannel(ctx, NotificationChannel{
		ID:         webhookID,
		Name:       "integration webhook updated",
		Type:       "discord",
		Enabled:    true,
		WebhookURL: updatedWebhook,
	}); err != nil {
		t.Fatalf("update webhook channel: %v", err)
	}
	if _, err := store.UpdateNotificationChannel(ctx, NotificationChannel{
		ID:               emailID,
		Name:             "integration email updated",
		Type:             "email",
		Enabled:          true,
		UseGlobalSMTP:    true,
		UseGlobalSMTPSet: true,
		EmailRecipients:  []string{"ops@example.com"},
	}); err != nil {
		t.Fatalf("update email channel: %v", err)
	}

	assertNotificationWebhookSecretRow(t, ctx, db, store.SecretKey, webhookID, updatedWebhook)
	assertGlobalSMTPReference(t, ctx, db, emailID)
}

func assertNotificationWebhookSecretRow(t *testing.T, ctx context.Context, db *sql.DB, secretKey, id, wantPlaintext string) {
	t.Helper()
	var webhookCiphertext, webhookNonce sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT webhook_url_ciphertext, webhook_url_nonce
FROM notification_channels WHERE id = ?`, id).Scan(&webhookCiphertext, &webhookNonce); err != nil {
		t.Fatalf("read notification channel row %s: %v", id, err)
	}
	ciphertext, nonce := webhookCiphertext.String, webhookNonce.String
	if ciphertext == "" || nonce == "" {
		t.Fatalf("webhook row %s missing ciphertext/nonce: ciphertext=%q nonce=%q", id, ciphertext, nonce)
	}
	for _, raw := range []string{wantPlaintext, "plaintext-webhook-secret"} {
		if raw != "" && (strings.Contains(ciphertext, raw) || strings.Contains(nonce, raw)) {
			t.Fatalf("webhook row %s persisted plaintext secret fragment %q", id, raw)
		}
	}
	gotPlaintext, err := decryptSecret(ciphertext, nonce, secretKey)
	if err != nil {
		t.Fatalf("decrypt webhook row %s: %v", id, err)
	}
	if gotPlaintext != wantPlaintext {
		t.Fatalf("webhook row %s decrypted to %q, want %q", id, gotPlaintext, wantPlaintext)
	}
}

func assertGlobalSMTPReference(t *testing.T, ctx context.Context, db *sql.DB, id string) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM notification_channel_v2_config_references
WHERE channel_id=? AND config_owner='control_panel' AND config_key='global_smtp'`, id).Scan(&count); err != nil {
		t.Fatalf("read global SMTP reference for %s: %v", id, err)
	}
	if count != 1 {
		t.Fatalf("global SMTP reference count for %s = %d, want 1", id, count)
	}
}

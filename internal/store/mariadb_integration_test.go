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

func TestMariaDBNotificationChannelIntegrationStoresSecretsAsCiphertextAndNonce(t *testing.T) {
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
	rawSMTPPassword := "plaintext-smtp-secret"
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
		ID:              emailID,
		Name:            "integration email",
		Type:            "email",
		Enabled:         true,
		EmailRecipients: []string{"ops@example.com"},
		SMTPHost:        "smtp.example.com",
		SMTPPort:        587,
		SMTPTLS:         true,
		SMTPFrom:        "alerts@example.com",
		SMTPUsername:    "alerts@example.com",
		SMTPPassword:    rawSMTPPassword,
	}); err != nil {
		t.Fatalf("create email channel: %v", err)
	}

	assertNotificationSecretRow(t, ctx, db, store.SecretKey, webhookID, "webhook", rawWebhook)
	assertNotificationSecretRow(t, ctx, db, store.SecretKey, emailID, "smtp", rawSMTPPassword)

	updatedWebhook := "https://discord.com/api/webhooks/it/updated-plaintext-webhook-secret"
	updatedSMTPPassword := "updated-plaintext-smtp-secret"
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
		ID:              emailID,
		Name:            "integration email updated",
		Type:            "email",
		Enabled:         true,
		EmailRecipients: []string{"ops@example.com"},
		SMTPHost:        "smtp.example.com",
		SMTPPort:        587,
		SMTPTLS:         true,
		SMTPFrom:        "alerts@example.com",
		SMTPUsername:    "alerts@example.com",
		SMTPPassword:    updatedSMTPPassword,
	}); err != nil {
		t.Fatalf("update email channel: %v", err)
	}

	assertNotificationSecretRow(t, ctx, db, store.SecretKey, webhookID, "webhook", updatedWebhook)
	assertNotificationSecretRow(t, ctx, db, store.SecretKey, emailID, "smtp", updatedSMTPPassword)
}

func assertNotificationSecretRow(t *testing.T, ctx context.Context, db *sql.DB, secretKey, id, secretKind, wantPlaintext string) {
	t.Helper()
	var webhookCiphertext, webhookNonce, smtpCiphertext, smtpNonce sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT webhook_url_ciphertext, webhook_url_nonce, smtp_password_ciphertext, smtp_password_nonce
FROM notification_channels WHERE id = ?`, id).Scan(&webhookCiphertext, &webhookNonce, &smtpCiphertext, &smtpNonce); err != nil {
		t.Fatalf("read notification channel row %s: %v", id, err)
	}

	var ciphertext, nonce string
	switch secretKind {
	case "webhook":
		ciphertext = webhookCiphertext.String
		nonce = webhookNonce.String
		if smtpCiphertext.Valid || smtpNonce.Valid {
			t.Fatalf("webhook row %s unexpectedly stored SMTP secret material", id)
		}
	case "smtp":
		ciphertext = smtpCiphertext.String
		nonce = smtpNonce.String
		if webhookCiphertext.Valid || webhookNonce.Valid {
			t.Fatalf("SMTP row %s unexpectedly stored webhook secret material", id)
		}
	default:
		t.Fatalf("unknown secret kind %q", secretKind)
	}
	if ciphertext == "" || nonce == "" {
		t.Fatalf("%s row %s missing ciphertext/nonce: ciphertext=%q nonce=%q", secretKind, id, ciphertext, nonce)
	}
	for _, raw := range []string{wantPlaintext, "plaintext-webhook-secret", "plaintext-smtp-secret"} {
		if raw != "" && (strings.Contains(ciphertext, raw) || strings.Contains(nonce, raw)) {
			t.Fatalf("%s row %s persisted plaintext secret fragment %q", secretKind, id, raw)
		}
	}
	gotPlaintext, err := decryptSecret(ciphertext, nonce, secretKey)
	if err != nil {
		t.Fatalf("decrypt %s row %s: %v", secretKind, id, err)
	}
	if gotPlaintext != wantPlaintext {
		t.Fatalf("%s row %s decrypted to %q, want %q", secretKind, id, gotPlaintext, wantPlaintext)
	}
}

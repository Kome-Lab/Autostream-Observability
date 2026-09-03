package database

import (
	"context"
	"database/sql"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func TestEmbeddedNotificationChannelV2MigrationRetainsDataAndRemovesRuntimeColumns(t *testing.T) {
	body, err := fs.ReadFile(embeddedMigrations, "migrations/008_notification_channel_v2_only.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(body))
	for _, required := range []string{
		"create table if not exists notification_channel_v2_migration_backup",
		"source_fingerprint",
		"sha2(",
		"create table if not exists notification_channel_v2_config_references",
		"create table if not exists notification_channel_v2_replacement_authority",
		"authority_revision",
		"'control_panel', 'global_smtp'",
		"on duplicate key update",
		"source_fingerprint=values(source_fingerprint)",
		"notification_channel_v2_eol_guard",
		"check (failure=0)",
		"from notification_channels",
		"where channel_type='email'",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("notification channel v2 migration missing %q:\n%s", required, text)
		}
	}
	for _, column := range []string{
		"smtp_host",
		"smtp_port",
		"smtp_tls",
		"smtp_from",
		"smtp_username",
		"smtp_password_ciphertext",
		"smtp_password_nonce",
		"smtp_password_configured",
	} {
		if !strings.Contains(text, "drop column "+column) {
			t.Fatalf("notification channel v2 migration does not drop %q:\n%s", column, text)
		}
	}
	if strings.Contains(text, "foreign key (channel_id) references notification_channels(id) on delete restrict") {
		t.Fatal("retained migration backup must outlive notification channel deletion")
	}
}

func TestMariaDBNotificationChannelV2PhysicalEOL(t *testing.T) {
	rawDSN := os.Getenv("AUTOSTREAM_OBSERVABILITY_TEST_DATABASE_URL")
	if rawDSN == "" {
		t.Skip("AUTOSTREAM_OBSERVABILITY_TEST_DATABASE_URL not set")
	}
	dsn, err := NormalizeMySQLDSN(rawDSN)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	if err := runEmbeddedMigrationsThrough(ctx, db, "007_notification_delivery_suppressed_status.sql"); err != nil {
		t.Fatal(err)
	}
	id := "v2-eol-" + strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "")
	_, err = db.ExecContext(ctx, `INSERT INTO notification_channels
  (id,name,channel_type,enabled,email_recipients,smtp_host,smtp_port,smtp_tls,smtp_from,smtp_username,
   smtp_password_ciphertext,smtp_password_nonce,smtp_password_configured,severity_filter,event_type_filter,created_at,updated_at)
VALUES (?,?,'email',TRUE,'["ops@example.com"]','smtp.example.com',587,TRUE,'alerts@example.com','alerts',?,?,TRUE,'[]','[]',NOW(),NOW())`,
		id, "v2 physical EOL", "ciphertext-test-marker", "nonce-test-marker")
	if err != nil {
		t.Fatal(err)
	}
	if err := RunEmbeddedMigrations(ctx, db); err == nil {
		t.Fatal("physical EOL migration accepted legacy SMTP data without live replacement authority")
	}
	if err := RecordNotificationChannelV2Authority(ctx, db, "2026-09-04T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := RunEmbeddedMigrations(ctx, db); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, "DELETE FROM notification_channel_v2_config_references WHERE channel_id=?", id)
		_, _ = db.ExecContext(cleanupCtx, "DELETE FROM notification_channel_v2_migration_backup WHERE channel_id=?", id)
		_, _ = db.ExecContext(cleanupCtx, "DELETE FROM notification_channels WHERE id=?", id)
	})
	var backupCount, referenceCount, legacyColumnCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM notification_channel_v2_migration_backup
WHERE channel_id=? AND smtp_host='smtp.example.com' AND smtp_port=587
  AND smtp_password_ciphertext='ciphertext-test-marker' AND smtp_password_nonce='nonce-test-marker'
  AND source_fingerprint REGEXP '^[0-9a-f]{64}$'`, id).Scan(&backupCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM notification_channel_v2_config_references
WHERE channel_id=? AND config_owner='control_panel' AND config_key='global_smtp'`, id).Scan(&referenceCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.columns
WHERE table_schema=DATABASE() AND table_name='notification_channels' AND column_name IN
('smtp_host','smtp_port','smtp_tls','smtp_from','smtp_username','smtp_password_ciphertext','smtp_password_nonce','smtp_password_configured')`).Scan(&legacyColumnCount); err != nil {
		t.Fatal(err)
	}
	if backupCount != 1 || referenceCount != 1 || legacyColumnCount != 0 {
		t.Fatalf("backup=%d reference=%d legacy_columns=%d", backupCount, referenceCount, legacyColumnCount)
	}
	if err := RunEmbeddedMigrations(ctx, db); err != nil {
		t.Fatalf("migration rerun: %v", err)
	}
}

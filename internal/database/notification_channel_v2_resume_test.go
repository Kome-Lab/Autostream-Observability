package database

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMariaDBNotificationChannelV2ResumeAfterDDL(t *testing.T) {
	db, ctx := notificationV2InterruptedFixture(t, true)
	if err := RunEmbeddedMigrations(ctx, db); err != nil {
		t.Fatalf("resume after DDL before record: %v", err)
	}
	assertNotificationV2Retained(t, ctx, db)
	if err := RunEmbeddedMigrations(ctx, db); err != nil {
		t.Fatal(err)
	}
}

func TestMariaDBNotificationChannelV2ResumeBeforeDDL(t *testing.T) {
	db, ctx := notificationV2InterruptedFixture(t, false)
	if err := RunEmbeddedMigrations(ctx, db); err != nil {
		t.Fatalf("resume before destructive DDL: %v", err)
	}
	assertNotificationV2Retained(t, ctx, db)
}

func TestMariaDBNotificationChannelV2ResumeRejectsBackupMismatch(t *testing.T) {
	db, ctx := notificationV2InterruptedFixture(t, false)
	if _, err := db.ExecContext(ctx, `UPDATE notification_channel_v2_migration_backup SET smtp_port=2525 WHERE channel_id='resume-email'`); err != nil {
		t.Fatal(err)
	}
	if err := RunEmbeddedMigrations(ctx, db); err == nil || !strings.Contains(err.Error(), "backup mismatch") {
		t.Fatal("resume overwrote a mismatched saved backup")
	}
	var port int
	if err := db.QueryRowContext(ctx, `SELECT smtp_port FROM notification_channel_v2_migration_backup WHERE channel_id='resume-email'`).Scan(&port); err != nil {
		t.Fatal(err)
	}
	if port != 2525 {
		t.Fatal("backup was regenerated")
	}
	assertNotificationV2Unrecorded(t, ctx, db)
}

func TestMariaDBNotificationChannelV2ResumeRejectsReplacementMismatch(t *testing.T) {
	db, ctx := notificationV2InterruptedFixture(t, true)
	if _, err := db.ExecContext(ctx, `DELETE FROM notification_channel_v2_config_references WHERE channel_id='resume-email'`); err != nil {
		t.Fatal(err)
	}
	if err := RunEmbeddedMigrations(ctx, db); err == nil || !strings.Contains(err.Error(), "authority mismatch") {
		t.Fatal("resume accepted missing replacement")
	}
	assertNotificationV2Unrecorded(t, ctx, db)
}

func TestMariaDBNotificationChannelV2ResumeRejectsMissingAuthority(t *testing.T) {
	db, ctx := notificationV2InterruptedFixture(t, true)
	if _, err := db.ExecContext(ctx, `DELETE FROM notification_channel_v2_replacement_authority`); err != nil {
		t.Fatal(err)
	}
	if err := RunEmbeddedMigrations(ctx, db); err == nil || !strings.Contains(err.Error(), "authority mismatch") {
		t.Fatal("resume accepted missing authority")
	}
	assertNotificationV2Unrecorded(t, ctx, db)
}

func TestMariaDBNotificationChannelV2ResumeCurrentCheckpoint(t *testing.T) {
	db, ctx := notificationV2CurrentCheckpointFixture(t)
	if err := RecordNotificationChannelV2Authority(ctx, db, "fixture-revision-7"); err != nil {
		t.Fatal(err)
	}
	if err := RunEmbeddedMigrations(ctx, db); err != nil {
		t.Fatalf("resume current checkpoint: %v", err)
	}
	assertNotificationV2Retained(t, ctx, db)
}

func TestMariaDBNotificationChannelV2ResumeRejectsRetainedDataDrift(t *testing.T) {
	db, ctx := notificationV2CurrentCheckpointFixture(t)
	if _, err := db.ExecContext(ctx, `UPDATE notification_channels SET name='changed after checkpoint' WHERE id='resume-email'`); err != nil {
		t.Fatal(err)
	}
	if err := RunEmbeddedMigrations(ctx, db); err == nil || !strings.Contains(err.Error(), "changed after EOL gate") {
		t.Fatalf("expected retained data conflict, got %v", err)
	}
	assertNotificationV2Unrecorded(t, ctx, db)
}

func notificationV2CurrentCheckpointFixture(t *testing.T) (*sql.DB, context.Context) {
	t.Helper()
	db, ctx := notificationV2InterruptedFixture(t, false)
	body, err := embeddedMigrations.ReadFile("migrations/008_notification_channel_v2_only.sql")
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, []byte("\nSIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='fixture stop before record';\n")...)
	if err := applyNotificationChannelV2(ctx, db, string(body)); err == nil || !strings.Contains(err.Error(), "fixture stop before record") {
		t.Fatalf("fault injection did not reach final boundary: %v", err)
	}
	return db, ctx
}

func notificationV2InterruptedFixture(t *testing.T, afterDDL bool) (*sql.DB, context.Context) {
	t.Helper()
	raw := os.Getenv("AUTOSTREAM_OBSERVABILITY_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("AUTOSTREAM_OBSERVABILITY_TEST_DATABASE_URL not set")
	}
	dsn, err := NormalizeMySQLDSN(raw)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	t.Cleanup(cancel)
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("requires disposable empty database, tables=%d", count)
	}
	if err := runEmbeddedMigrationsThrough(ctx, db, "007_notification_delivery_suppressed_status.sql"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO notification_channels
 (id,name,channel_type,enabled,email_recipients,smtp_host,smtp_port,smtp_tls,smtp_from,smtp_username,
 smtp_password_ciphertext,smtp_password_nonce,smtp_password_configured,severity_filter,event_type_filter,created_at,updated_at)
 VALUES ('resume-email','Retained email','email',TRUE,'["ops@example.com"]','smtp.example.com',587,TRUE,'alerts@example.com','alerts',
 'synthetic-encrypted-value','synthetic-nonce',TRUE,'["critical"]','["incident"]','2026-01-02 03:04:05','2026-01-02 03:04:05')`); err != nil {
		t.Fatal(err)
	}
	if err := RecordNotificationChannelV2Authority(ctx, db, "fixture-revision-7"); err != nil {
		t.Fatal(err)
	}
	body, err := embeddedMigrations.ReadFile("migrations/008_notification_channel_v2_only.sql")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, stmt := range splitSQLStatements(string(body)) {
		if !afterDDL && strings.Contains(stmt, "DROP COLUMN smtp_host") {
			break
		}
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("interruption fixture: %v", err)
		}
	}
	// Execute the delivered SQL body without the runner's completion record.
	assertNotificationV2Unrecorded(t, ctx, db)
	return db, ctx
}

func assertNotificationV2Unrecorded(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE id='008_notification_channel_v2_only.sql'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("interrupted migration was recorded")
	}
}

func assertNotificationV2Retained(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	for _, query := range []string{
		`SELECT COUNT(*) FROM notification_channels WHERE id='resume-email' AND name='Retained email' AND enabled=TRUE AND JSON_COMPACT(email_recipients)='["ops@example.com"]' AND JSON_COMPACT(severity_filter)='["critical"]' AND created_at='2026-01-02 03:04:05'`,
		`SELECT COUNT(*) FROM notification_channel_v2_migration_backup WHERE channel_id='resume-email' AND smtp_host='smtp.example.com' AND smtp_port=587 AND smtp_password_ciphertext='synthetic-encrypted-value' AND smtp_password_nonce='synthetic-nonce'`,
		`SELECT COUNT(*) FROM notification_channel_v2_config_references WHERE channel_id='resume-email' AND config_owner='control_panel' AND config_key='global_smtp'`,
		`SELECT COUNT(*) FROM schema_migrations WHERE id='008_notification_channel_v2_only.sql'`,
	} {
		var count int
		if err := db.QueryRowContext(ctx, query).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("retained state assertion count=%d", count)
		}
	}
}

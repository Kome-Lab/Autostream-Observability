package database

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

//go:embed migrations/*.sql
var embeddedMigrations embed.FS

func RunEmbeddedMigrations(ctx context.Context, db *sql.DB) error {
	return runEmbeddedMigrationsThrough(ctx, db, "")
}

const notificationChannelV2AuthorityTableSQL = `CREATE TABLE IF NOT EXISTS notification_channel_v2_replacement_authority (
  authority_id VARCHAR(64) PRIMARY KEY,
  config_owner VARCHAR(64) NOT NULL,
  config_key VARCHAR(128) NOT NULL,
  authority_revision VARCHAR(128) NOT NULL,
  verified_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  CONSTRAINT chk_notification_channel_v2_authority
    CHECK (authority_id='global_smtp' AND config_owner='control_panel' AND config_key='global_smtp')
)`

func NotificationChannelV2AuthorityRequired(ctx context.Context, db *sql.DB) (bool, error) {
	var columnCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.columns
WHERE table_schema=DATABASE() AND table_name='notification_channels' AND column_name IN
('smtp_host','smtp_port','smtp_tls','smtp_from','smtp_username','smtp_password_ciphertext','smtp_password_nonce','smtp_password_configured')`).Scan(&columnCount); err != nil {
		return false, err
	}
	if columnCount == 0 {
		return false, nil
	}
	if columnCount != 8 {
		return false, fmt.Errorf("notification SMTP legacy schema is partial: columns=%d", columnCount)
	}
	var required bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM notification_channels
WHERE channel_type='email' AND (smtp_host IS NOT NULL OR smtp_port IS NOT NULL OR smtp_from IS NOT NULL OR
smtp_username IS NOT NULL OR smtp_password_ciphertext IS NOT NULL OR smtp_password_nonce IS NOT NULL OR smtp_password_configured=TRUE))`).Scan(&required); err != nil {
		return false, err
	}
	return required, nil
}

func RecordNotificationChannelV2Authority(ctx context.Context, db *sql.DB, revision string) error {
	revision = strings.TrimSpace(revision)
	if revision == "" || len(revision) > 128 || strings.ContainsAny(revision, "\r\n\x00") {
		return fmt.Errorf("global SMTP authority revision is invalid")
	}
	if _, err := db.ExecContext(ctx, notificationChannelV2AuthorityTableSQL); err != nil {
		return fmt.Errorf("create global SMTP authority table: %w", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO notification_channel_v2_replacement_authority
  (authority_id,config_owner,config_key,authority_revision,verified_at)
VALUES ('global_smtp','control_panel','global_smtp',?,CURRENT_TIMESTAMP(6))
ON DUPLICATE KEY UPDATE authority_revision=VALUES(authority_revision),verified_at=VALUES(verified_at)`, revision); err != nil {
		return fmt.Errorf("record global SMTP authority: %w", err)
	}
	return nil
}

func runEmbeddedMigrationsThrough(ctx context.Context, db *sql.DB, lastMigration string) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
  id VARCHAR(255) PRIMARY KEY,
  applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	entries, err := fs.ReadDir(embeddedMigrations, "migrations")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		if lastMigration != "" && entry.Name() > lastMigration {
			continue
		}
		id := entry.Name()
		var got string
		err := db.QueryRowContext(ctx, "SELECT id FROM schema_migrations WHERE id = ?", id).Scan(&got)
		if err == nil {
			continue
		}
		if err != sql.ErrNoRows {
			return err
		}
		body, err := fs.ReadFile(embeddedMigrations, filepath.ToSlash(filepath.Join("migrations", entry.Name())))
		if err != nil {
			return err
		}
		for _, stmt := range splitSQLStatements(string(body)) {
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("apply %s: %w", id, err)
			}
		}
		if _, err := db.ExecContext(ctx, "INSERT INTO schema_migrations (id) VALUES (?)", id); err != nil {
			return fmt.Errorf("record migration %s: %w", id, err)
		}
	}
	return nil
}

func splitSQLStatements(sqlText string) []string {
	parts := strings.Split(sqlText, ";")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		stmt := strings.TrimSpace(part)
		if stmt != "" {
			out = append(out, stmt)
		}
	}
	return out
}

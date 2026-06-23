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

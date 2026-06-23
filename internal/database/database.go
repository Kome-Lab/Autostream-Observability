package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func OpenFromEnv(ctx context.Context) (*sql.DB, error) {
	raw := os.Getenv("DATABASE_URL")
	if raw == "" {
		return nil, errors.New("DATABASE_URL is required")
	}
	dsn, err := NormalizeMySQLDSN(raw)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping mariadb: %w", err)
	}
	return db, nil
}

func NormalizeMySQLDSN(raw string) (string, error) {
	if strings.HasPrefix(raw, "mysql://") {
		raw = strings.TrimPrefix(raw, "mysql://")
	}
	if strings.Contains(raw, "://") {
		return "", errors.New("DATABASE_URL must use mysql:// or native go mysql dsn")
	}
	if !strings.Contains(raw, "parseTime=true") {
		sep := "?"
		if strings.Contains(raw, "?") {
			sep = "&"
		}
		raw += sep + "parseTime=true"
	}
	return raw, nil
}

func MaskDSN(raw string) string {
	if strings.HasPrefix(raw, "mysql://") {
		raw = strings.TrimPrefix(raw, "mysql://")
	}
	at := strings.LastIndex(raw, "@")
	colon := strings.Index(raw, ":")
	if at > 0 && colon > 0 && colon < at {
		return raw[:colon+1] + "****" + raw[at:]
	}
	return raw
}

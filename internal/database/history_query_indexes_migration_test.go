package database

import (
	"io/fs"
	"strings"
	"testing"
)

func TestEmbeddedMigrationsContainHistoryQueryIndexes(t *testing.T) {
	body, err := fs.ReadFile(embeddedMigrations, "migrations/006_history_query_indexes.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(body))
	for _, required := range []string{
		"idx_signals_metric_series_occurred",
		"name, service_id, service_type, stream_id, occurred_at, created_at, id",
		"idx_incidents_updated_id",
		"updated_at, id",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("history query index migration missing %q:\n%s", required, text)
		}
	}
}

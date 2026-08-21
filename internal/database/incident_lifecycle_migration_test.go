package database

import (
	"io/fs"
	"strings"
	"testing"
)

func TestEmbeddedMigrationsContainIncidentLifecycleSchema(t *testing.T) {
	body, err := fs.ReadFile(embeddedMigrations, "migrations/005_incident_lifecycle.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(body)
	for _, required := range []string{"dedupe_key", "occurrence_count", "last_seen_at", "resolved_by_signal_id", "resolution_reason", "uq_incidents_active_dedupe"} {
		if !strings.Contains(sql, required) {
			t.Fatalf("incident lifecycle migration is missing %q: %s", required, sql)
		}
	}
	consolidateAt := strings.Index(sql, "migration_duplicate_consolidated")
	populateAt := strings.Index(sql, "CONCAT(rule, CHAR(0), service_id")
	indexAt := strings.Index(sql, "CREATE UNIQUE INDEX IF NOT EXISTS uq_incidents_active_dedupe")
	if consolidateAt < 0 || populateAt < 0 || indexAt < 0 || !(consolidateAt < populateAt && populateAt < indexAt) {
		t.Fatalf("active duplicates must be consolidated before the dedupe key and unique index are populated: %s", sql)
	}
	if !strings.Contains(sql, "newer.stream_id <=> stale.stream_id") {
		t.Fatalf("duplicate consolidation must compare nullable stream ids safely: %s", sql)
	}
}

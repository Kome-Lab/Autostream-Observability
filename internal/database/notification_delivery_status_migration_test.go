package database

import (
	"io/fs"
	"strings"
	"testing"
)

func TestEmbeddedMigrationAllowsSuppressedNotificationDeliveries(t *testing.T) {
	body, err := fs.ReadFile(embeddedMigrations, "migrations/007_notification_delivery_suppressed_status.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(body))
	for _, required := range []string{"notification_deliveries", "modify column status", "'success'", "'failure'", "'suppressed'"} {
		if !strings.Contains(text, required) {
			t.Fatalf("notification delivery status migration missing %q:\n%s", required, text)
		}
	}
}

package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

type notificationDeliveryCaptureState struct {
	execArgs  [][]driver.NamedValue
	queryRows [][]driver.Value
}

type notificationDeliveryCaptureDriver struct {
	state *notificationDeliveryCaptureState
}

func (d notificationDeliveryCaptureDriver) Open(string) (driver.Conn, error) {
	return &notificationDeliveryCaptureConn{state: d.state}, nil
}

type notificationDeliveryCaptureConn struct {
	state *notificationDeliveryCaptureState
}

func (c *notificationDeliveryCaptureConn) Prepare(string) (driver.Stmt, error) {
	return nil, driver.ErrSkip
}

func (c *notificationDeliveryCaptureConn) Close() error { return nil }

func (c *notificationDeliveryCaptureConn) Begin() (driver.Tx, error) {
	return nil, driver.ErrSkip
}

func (c *notificationDeliveryCaptureConn) ExecContext(_ context.Context, _ string, args []driver.NamedValue) (driver.Result, error) {
	c.state.execArgs = append(c.state.execArgs, append([]driver.NamedValue(nil), args...))
	return driver.RowsAffected(1), nil
}

func (c *notificationDeliveryCaptureConn) QueryContext(_ context.Context, _ string, _ []driver.NamedValue) (driver.Rows, error) {
	rows := make([][]driver.Value, len(c.state.queryRows))
	for index, row := range c.state.queryRows {
		rows[index] = append([]driver.Value(nil), row...)
	}
	return &notificationDeliveryCaptureRows{rows: rows}, nil
}

type notificationDeliveryCaptureRows struct {
	rows  [][]driver.Value
	index int
}

func (r *notificationDeliveryCaptureRows) Columns() []string {
	return []string{"id", "event_type", "channel", "target", "incident_id", "status", "error_text", "metadata", "created_at"}
}

func (r *notificationDeliveryCaptureRows) Close() error { return nil }

func (r *notificationDeliveryCaptureRows) Next(dest []driver.Value) error {
	if r.index >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.index])
	r.index++
	return nil
}

func TestMariaDBNotificationDeliverySanitizesInsertAndReadBoundaries(t *testing.T) {
	state := &notificationDeliveryCaptureState{}
	driverName := fmt.Sprintf("notification-delivery-capture-%d", time.Now().UnixNano())
	sql.Register(driverName, notificationDeliveryCaptureDriver{state: state})
	db, err := sql.Open(driverName, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := MariaDBStore{DB: db}
	occurredAt := "2026-07-18T01:32:00Z"

	if _, err := store.SaveNotificationDelivery(t.Context(), NotificationDelivery{
		EventType: "admin.audit",
		Channel:   "discord",
		Status:    "success",
		Metadata: map[string]any{
			"action":      "secrets.update",
			"rule":        "secrets.update",
			"summary":     "シークレットを更新\n実行者: ops",
			"occurred_at": occurredAt,
		},
	}); err != nil {
		t.Fatal(err)
	}
	inserted := capturedNotificationMetadata(t, state.execArgs[0])
	if inserted["action"] != "secrets.update" || inserted["rule"] != "secrets.update" || inserted["summary"] != "シークレットを更新\n実行者: ops" || inserted["occurred_at"] != occurredAt {
		t.Fatalf("safe admin audit metadata changed before MariaDB INSERT: %#v", inserted)
	}

	if _, err := store.SaveNotificationDelivery(t.Context(), NotificationDelivery{
		EventType: "admin.audit",
		Channel:   "discord",
		Status:    "success",
		Metadata: map[string]any{
			"action":      "raw.secret.token",
			"rule":        "secrets.ast_svc_raw_token",
			"summary":     "<redacted> / opaque-value-that-must-not-survive",
			"occurred_at": occurredAt,
		},
	}); err != nil {
		t.Fatal(err)
	}
	unsafeInsertJSON := capturedNotificationMetadataJSON(t, state.execArgs[1])
	for _, raw := range []string{"raw.secret.token", "ast_svc_raw_token", "opaque-value-that-must-not-survive"} {
		if strings.Contains(unsafeInsertJSON, raw) {
			t.Fatalf("secret %q reached MariaDB INSERT metadata: %s", raw, unsafeInsertJSON)
		}
	}
	unsafeInserted := map[string]any{}
	if err := json.Unmarshal([]byte(unsafeInsertJSON), &unsafeInserted); err != nil {
		t.Fatal(err)
	}
	if unsafeInserted["action"] != "<redacted>" || unsafeInserted["rule"] != "<redacted>" || unsafeInserted["summary"] != "<redacted>" || unsafeInserted["occurred_at"] != occurredAt {
		t.Fatalf("unsafe MariaDB INSERT metadata was not selectively redacted: %#v", unsafeInserted)
	}

	rawMetadata := `{"action":"raw.secret.token","rule":"secrets.ast_svc_raw_token","summary":"<redacted> / opaque-value-that-must-not-survive","occurred_at":"2026-07-18T01:32:00Z"}`
	state.queryRows = [][]driver.Value{{
		"ntf-raw", "admin.audit", "discord", "", "", "success", "", []byte(rawMetadata), time.Date(2026, 7, 18, 1, 33, 0, 0, time.UTC),
	}}
	deliveries, err := store.ListNotificationDeliveries(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(deliveries)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"raw.secret.token", "ast_svc_raw_token", "opaque-value-that-must-not-survive"} {
		if strings.Contains(string(body), raw) {
			t.Fatalf("secret %q from a raw MariaDB row reached delivery JSON: %s", raw, body)
		}
	}
	if len(deliveries) != 1 || deliveries[0].Metadata["action"] != "<redacted>" || deliveries[0].Metadata["summary"] != "<redacted>" || deliveries[0].Metadata["occurred_at"] != occurredAt {
		t.Fatalf("raw MariaDB row was not safely normalized: %#v", deliveries)
	}
}

func capturedNotificationMetadata(t *testing.T, args []driver.NamedValue) map[string]any {
	t.Helper()
	raw := capturedNotificationMetadataJSON(t, args)
	metadata := map[string]any{}
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil {
		t.Fatal(err)
	}
	return metadata
}

func capturedNotificationMetadataJSON(t *testing.T, args []driver.NamedValue) string {
	t.Helper()
	if len(args) < 8 {
		t.Fatalf("notification delivery INSERT arguments = %#v", args)
	}
	raw, ok := args[7].Value.(string)
	if !ok {
		t.Fatalf("notification metadata INSERT argument = %#v", args[7].Value)
	}
	return raw
}

package v2migration

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/example/autostream-observability/internal/database"
	_ "github.com/go-sql-driver/mysql"
)

func TestMigrationStatementsAreAdditiveAndSecretSafe(t *testing.T) {
	for name, statement := range map[string]string{
		"backup":    createBackupTableSQL,
		"reference": createReferenceTableSQL,
		"copy":      backupSQL,
		"transform": transformSQL,
		"restore":   restoreSQL,
	} {
		lower := strings.ToLower(statement)
		for _, forbidden := range []string{"drop table", "drop column", "truncate table"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("%s statement contains forbidden physical deletion %q", name, forbidden)
			}
		}
	}
	if !strings.Contains(backupSQL, "smtp_password_ciphertext") || !strings.Contains(backupSQL, "source_fingerprint") {
		t.Fatal("backup must preserve encrypted material and record a non-plaintext fingerprint")
	}
	if !strings.Contains(referenceSQL, "control_panel") || !strings.Contains(referenceSQL, "global_smtp") {
		t.Fatal("migration must bind every transformed row to the replacement authority")
	}
}

func TestMariaDBV2SMTPMigrationRehearsal(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	if err := database.RunEmbeddedMigrations(ctx, db); err != nil {
		t.Fatal(err)
	}

	suffix := strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "")
	ids := []string{"v2mig-a-" + suffix, "v2mig-b-" + suffix}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, "DELETE FROM "+referenceTable+" WHERE channel_id IN (?,?)", ids[0], ids[1])
		_, _ = db.ExecContext(cleanupCtx, "DELETE FROM "+backupTable+" WHERE channel_id IN (?,?)", ids[0], ids[1])
		_, _ = db.ExecContext(cleanupCtx, "DELETE FROM notification_channels WHERE id IN (?,?)", ids[0], ids[1])
	})
	for index, id := range ids {
		_, err := db.ExecContext(ctx, `INSERT INTO notification_channels
  (id,name,channel_type,enabled,email_recipients,smtp_host,smtp_port,smtp_tls,smtp_from,smtp_username,
   smtp_password_ciphertext,smtp_password_nonce,smtp_password_configured,severity_filter,event_type_filter,created_at,updated_at)
VALUES (?,?,'email',TRUE,'["ops@example.com"]','smtp.example.com',587,TRUE,'alerts@example.com','alerts',?,?,TRUE,'[]','[]',NOW(),NOW())`,
			id, "migration rehearsal", "encrypted-value-"+suffix+string(rune('a'+index)), "nonce-value-"+suffix+string(rune('a'+index)))
		if err != nil {
			t.Fatal(err)
		}
	}
	options := Options{ReplacementReady: true, ExpectedNonEmpty: true}
	if dry, err := DryRun(ctx, db, options); err != nil || dry.PreCount != 2 || dry.PostCount != 2 {
		t.Fatalf("dry run=%#v err=%v", dry, err)
	}
	first, err := Run(ctx, db, options)
	if err != nil {
		t.Fatal(err)
	}
	assertMigrationResult(t, first, 2)
	second, err := Run(ctx, db, options)
	if err != nil {
		t.Fatal(err)
	}
	assertMigrationResult(t, second, 2)
	if _, err := db.ExecContext(ctx, "DELETE FROM "+referenceTable+" WHERE channel_id=?", ids[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, db, options); err == nil {
		t.Fatal("missing replacement reference unexpectedly passed orphan verification")
	}
	if repaired, err := Run(ctx, db, options); err != nil {
		t.Fatalf("repair orphaned reference: %v", err)
	} else {
		assertMigrationResult(t, repaired, 2)
	}
	if restored, err := Restore(ctx, db, options); err != nil || restored.RestoreStatus != "PASS" || restored.PostCount != 2 {
		t.Fatalf("restore=%#v err=%v", restored, err)
	}
	third, err := Run(ctx, db, options)
	if err != nil {
		t.Fatal(err)
	}
	assertMigrationResult(t, third, 2)

	injected := errors.New("injected migration failure")
	if _, err := Restore(ctx, db, options); err != nil {
		t.Fatal(err)
	}
	if _, err := run(ctx, db, options, func() error { return injected }); !errors.Is(err, injected) {
		t.Fatalf("partial failure=%v, want injected error", err)
	}
	var stillLegacy int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM notification_channels WHERE id IN (?,?) AND "+directLegacyPredicate, ids[0], ids[1]).Scan(&stillLegacy); err != nil || stillLegacy != 2 {
		t.Fatalf("transaction rollback legacy_count=%d err=%v", stillLegacy, err)
	}
	if _, err := Run(ctx, db, options); err != nil {
		t.Fatalf("migration after rollback: %v", err)
	}

	t.Run("negative gates", func(t *testing.T) {
		if _, err := DryRun(ctx, db, Options{ExpectedNonEmpty: true}); !errors.Is(err, ErrReplacementNotReady) {
			t.Fatalf("replacement gate error=%v", err)
		}
		emptyID := "v2mig-empty-" + suffix
		_, _ = db.ExecContext(ctx, "DELETE FROM "+referenceTable)
		_, _ = db.ExecContext(ctx, "DELETE FROM "+backupTable)
		_, _ = db.ExecContext(ctx, "DELETE FROM notification_channels WHERE id IN (?,?)", ids[0], ids[1])
		if _, err := DryRun(ctx, db, Options{ReplacementReady: true, ExpectedNonEmpty: true}); !errors.Is(err, ErrEmptyDenominator) {
			t.Fatalf("empty denominator error=%v id=%s", err, emptyID)
		}
	})
}

func assertMigrationResult(t *testing.T, result Result, want int) {
	t.Helper()
	if result.PreCount != want || result.BackupCount != want || result.PostCount != want || result.OrphanCount != 0 ||
		result.BackupStatus != "PASS" || result.IdempotenceStatus != "PASS" || result.RollbackStatus != "PASS" ||
		result.PhysicalDeletion || result.ProductionMutation {
		t.Fatalf("migration proof=%#v", result)
	}
}

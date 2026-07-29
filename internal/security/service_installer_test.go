package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestObservabilityReleaseShipsManagedServiceInstaller(t *testing.T) {
	root := filepath.Join("..", "..")
	installerPath := filepath.Join(root, "release", "install-autostream-observability")
	installerBytes, err := os.ReadFile(installerPath)
	if err != nil {
		t.Fatal(err)
	}
	installer := string(installerBytes)

	for _, marker := range []string{
		"set -euo pipefail",
		`readonly SERVICE_NAME="observability"`,
		`readonly MANAGED_ROOT="/opt/autostream/observability"`,
		`readonly PUBLIC_BINARY="/usr/local/bin/autostream-observability"`,
		`readonly PUBLIC_ALIAS="/usr/local/bin/observability"`,
		`readonly ENV_DEST="/etc/autostream/observability.env"`,
		`readonly UNIT_DEST="/etc/systemd/system/autostream-observability.service"`,
		`readonly INSTALL_MIGRATION_ROOT="/var/backups/autostream/install-migrations"`,
		`readonly INSTALL_BACKUP_DIR="${INSTALL_MIGRATION_SERVICE_ROOT}/${VERSION}-${ARCHIVE_DIGEST:0:12}"`,
		`readonly LEGACY_BINARY_BACKUP="${INSTALL_BACKUP_DIR}/usr-local-bin-autostream-observability.pre-managed"`,
		`readonly LEGACY_ALIAS_BACKUP="${INSTALL_BACKUP_DIR}/usr-local-bin-observability.pre-managed"`,
		`ensure_exact_directory "${STATE_DIR}" autostream autostream 0750 "${STATE_DIR}"`,
		`ensure_root_only_directory "${INSTALL_BACKUP_DIR}"`,
		`ensure_root_only_directory /run/autostream-updater`,
		`readonly TARGET_LOCK="/run/autostream-updater/.autostream-updater-${TARGET_LOCK_ID}.lock"`,
		`must resolve to its exact canonical path`,
		"set +e",
		"sha256sum --check --strict",
		"release-manifest.json",
		`["channel", "components", "minimum_agent_version", "published_at", "release_id", "schema_version"]`,
		`["artifacts", "commit", "database_schema", "rollback_compatible", "service", "source_version"]`,
		`(.components[0].artifacts | type == "array" and length == 2)`,
		`(.components[0].database_schema == "backward_compatible")`,
		".artifact-sha256",
		".version",
		`STAGE_DIR=$(mktemp -d "${MANAGED_ROOT}/.install.XXXXXX") ||`,
		`[[ -n ${STAGE_DIR} &&`,
		`retain_legacy_file`,
		`ln -- "${destination}" "${backup}"`,
		`mv -Tf -- "${binary_stage}" "${PUBLIC_BINARY}"`,
		`sync_required_directories`,
		`die "failed to synchronize installed filesystem state"`,
		`flock -n 9`,
		"systemctl daemon-reload",
	} {
		if !strings.Contains(installer, marker) {
			t.Fatalf("service installer is missing %q", marker)
		}
	}
	if strings.Contains(installer, `mv -T -- "${destination}" "${backup}"`) {
		t.Fatal("service installer must snapshot the existing public binary without removing ExecStart")
	}

	workflowBytes, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release-host.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(workflowBytes)
	for _, marker := range []string{
		`cp release/install-autostream-observability "${root}/install-autostream-observability"`,
		`chmod 0755 "${root}/install-autostream-observability"`,
		"bash -n release/install-autostream-observability",
		"bash -n release/test-install-autostream-observability-integration.sh",
		"sudo bash release/test-install-autostream-observability-integration.sh",
		"artifacts/autostream-observability_${{ needs.release-host.outputs.version }}_linux_amd64.tar.gz",
		"artifacts/autostream-observability_${{ needs.release-host.outputs.version }}_linux_arm64.tar.gz",
	} {
		if !strings.Contains(workflow, marker) {
			t.Fatalf("host release workflow is missing installer packaging marker %q", marker)
		}
	}
	ciBytes, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{
		"bash -n release/install-autostream-observability",
		"bash -n release/test-install-autostream-observability-integration.sh",
		"sudo bash release/test-install-autostream-observability-integration.sh",
	} {
		if !strings.Contains(string(ciBytes), marker) {
			t.Fatalf("CI workflow is missing installer integration marker %q", marker)
		}
	}

	unitBytes, err := os.ReadFile(filepath.Join(root, "systemd", "autostream-observability.service.example"))
	if err != nil {
		t.Fatal(err)
	}
	unit := string(unitBytes)
	if !strings.Contains(unit, "ExecStart=/usr/local/bin/autostream-observability") {
		t.Fatal("Observability systemd unit must use the stable public binary path")
	}
	if strings.Contains(unit, "ExecStart=/opt/autostream/observability/current/") {
		t.Fatal("Observability systemd unit exposes installer-owned release internals")
	}

	guideBytes, err := os.ReadFile(filepath.Join(root, "release", "README.install.md"))
	if err != nil {
		t.Fatal(err)
	}
	guide := string(guideBytes)
	for _, marker := range []string{
		"sudo ./install-autostream-observability",
		"gh attestation verify autostream-observability_vX.Y.Z_linux_amd64.tar.gz --repo Kome-Lab/Autostream-Observability --signer-workflow Kome-Lab/Autostream-Observability/.github/workflows/release-host.yml --deny-self-hosted-runners",
		"gh attestation verify release-manifest.json --repo Kome-Lab/Autostream-Observability --signer-workflow Kome-Lab/Autostream-Observability/.github/workflows/release-host.yml --deny-self-hosted-runners",
		"sudo install -o root -g root -m 0644 /tmp/release-manifest.json /opt/autostream/releases/artifacts/release-manifest.json",
		"root-owned archive and manifest",
		"sudo tar --no-same-owner --no-same-permissions -xzf autostream-observability_vX.Y.Z_linux_amd64.tar.gz",
		"/var/backups/autostream/install-migrations/observability",
		"installer-owned",
	} {
		if !strings.Contains(guide, marker) {
			t.Fatalf("install guide is missing simple installer marker %q", marker)
		}
	}
}

func TestObservabilityInstallerFailsClosedBeforeMutationWithoutMariaDBDump(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "release", "install-autostream-observability"))
	if err != nil {
		t.Fatal(err)
	}
	installer := string(body)
	preflight := strings.Index(installer, `[[ -f /usr/bin/mariadb-dump &&`)
	firstMutation := strings.Index(installer, `ensure_safe_root_directory /opt 0755 "/opt"`)
	if preflight < 0 || firstMutation < 0 || preflight >= firstMutation {
		t.Fatal("mariadb-dump regular-file, non-symlink, executable preflight must fail before filesystem mutation")
	}
	for _, marker := range []string{
		`! -L /usr/bin/mariadb-dump`,
		`-x /usr/bin/mariadb-dump`,
		`die "/usr/bin/mariadb-dump must be a regular non-symlink executable"`,
	} {
		if !strings.Contains(installer[preflight:firstMutation], marker) {
			t.Fatalf("mariadb-dump fail-closed preflight is missing %q", marker)
		}
	}
}

func TestObservabilityInstallerRejectsVersionPrefixCollisions(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "release", "install-autostream-observability"))
	if err != nil {
		t.Fatal(err)
	}
	const exactComparison = `== "autostream-observability ${VERSION}"`
	if count := strings.Count(string(body), exactComparison); count != 2 {
		t.Fatalf("expected exact first-line version checks before and after managed copy, got %d", count)
	}
}

func TestObservabilityInstallerIntegrationFixtureCoversPrivilegedTransitions(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(
		"..", "..", "release", "test-install-autostream-observability-integration.sh",
	))
	if err != nil {
		t.Fatal(err)
	}
	fixture := string(body)
	for _, marker := range []string{
		`mount --bind /dev/null /usr/bin/mariadb-dump`,
		`mount --bind '${FAIL_MKTEMP}' /usr/bin/mktemp`,
		`mount --bind '${FAIL_SYNC}' /usr/bin/sync`,
		`mount --bind '${FAIL_SYSTEMCTL}' /usr/bin/systemctl`,
		`mktemp failure was masked by the readonly assignment`,
		`sync failure injection did not reach the final durability boundary`,
		`daemon-reload failure injection did not reach the commit boundary`,
		`mariadb-dump failure injection did not mount the unsafe executable`,
		`failed migration did not durably retain the legacy binary before activation`,
		`failed migration did not restore the legacy binary`,
		`successful migration did not retain the legacy backup executable`,
		`idempotent reinstall replaced the running legacy process`,
		`another privileged update is already active`,
		`fresh installer did not create the autostream account`,
		`fresh installer unexpectedly started the service`,
		`fresh installer unexpectedly enabled the service`,
		`systemctl show --property MainPID`,
		`/var/backups/autostream/install-migrations/observability`,
		`published_at: "2026-07-29T00:00:00Z"`,
		`minimum_agent_version: "v2.0.0"`,
		`commit: "0123456789abcdef0123456789abcdef01234567"`,
		`database_schema: "backward_compatible"`,
		`arch: "arm64"`,
	} {
		if !strings.Contains(fixture, marker) {
			t.Fatalf("Observability installer integration fixture is missing %q", marker)
		}
	}
}

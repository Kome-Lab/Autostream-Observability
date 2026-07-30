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
		`legacy_unit_file_state="$(systemctl is-enabled "${UNIT}" 2>/dev/null || true)"`,
		`legacy fixture must begin disabled`,
		`systemctl show --property MainPID`,
		`AUTOSTREAM_OBSERVABILITY_INSTALLER_TEST_MOUNT_NS`,
		`autostream-observability-installer-test-scratch /mnt`,
		`/mnt/usr-lower \`,
		`/mnt/usr-upper/local`,
		`/mnt/usr-work \`,
		`mount --rbind /usr /mnt/usr-lower`,
		`mount --make-rprivate /mnt/usr-lower`,
		`mount --rbind /etc /mnt/etc-lower`,
		`mount --make-rprivate /mnt/etc-lower`,
		`mount --rbind /var /mnt/var-lower`,
		`mount --make-rprivate /mnt/var-lower`,
		`mount --rbind /run /mnt/run-lower`,
		`mount --make-rprivate /mnt/run-lower`,
		`lowerdir=/mnt/usr-lower,upperdir=/mnt/usr-upper,workdir=/mnt/usr-work`,
		`lowerdir=/mnt/etc-lower,upperdir=/mnt/etc-upper,workdir=/mnt/etc-work`,
		`lowerdir=/mnt/var-lower,upperdir=/mnt/var-upper,workdir=/mnt/var-work`,
		`lowerdir=/mnt/run-lower,upperdir=/mnt/run-upper,workdir=/mnt/run-work`,
		`install -d -o root -g root -m 1777 /mnt/var-upper/tmp`,
		`autostream-observability-installer-test-usr-overlay`,
		`grep -Eq ' /usr .* - overlay autostream-observability-installer-test-usr-overlay '`,
		`autostream-observability-installer-test-etc-overlay`,
		`grep -Eq ' /etc .* - overlay autostream-observability-installer-test-etc-overlay '`,
		`autostream-observability-installer-test-var-overlay`,
		`grep -Eq ' /var .* - overlay autostream-observability-installer-test-var-overlay '`,
		`autostream-observability-installer-test-run-overlay`,
		`grep -Eq ' /run .* - overlay autostream-observability-installer-test-run-overlay '`,
		`mount --rbind /mnt/run-lower/systemd /run/systemd`,
		`systemd_identity="$(stat -c "%d:%i" -- /mnt/run-lower/systemd)"`,
		`AUTOSTREAM_OBSERVABILITY_INSTALLER_TEST_SYSTEMD_IDENTITY="${systemd_identity}"`,
		`autostream-observability-installer-test-sealed /mnt`,
		`ro,nodev,nosuid,noexec,mode=0555`,
		`sealed /mnt mount is missing`,
		`sealed /mnt mount options are unsafe`,
		`sealed /mnt ownership or mode is unsafe`,
		`sealed /mnt unexpectedly accepted a write`,
		`readonly EXPECTED_SYSTEMD_IDENTITY="${AUTOSTREAM_OBSERVABILITY_INSTALLER_TEST_SYSTEMD_IDENTITY:-}"`,
		`host-backed /run/systemd mount is missing`,
		`host-backed /run/systemd mount identity is invalid`,
		`autostream-observability-installer-test-bin /usr/local/bin`,
		`autostream-observability-installer-test-sbin /usr/local/sbin`,
		`autostream-observability-installer-test-opt /opt`,
		`isolated /usr overlay mount is missing`,
		`isolated /usr/local/bin mount is missing`,
		`isolated /usr/local/sbin mount is missing`,
		`isolated /opt mount is missing`,
		`could not create an isolated safe /usr fixture`,
		`could not create an isolated safe /etc fixture`,
		`could not create an isolated safe /etc/systemd fixture`,
		`could not create an isolated safe /etc/systemd/system fixture`,
		`could not create an isolated safe /var fixture`,
		`could not create an isolated safe /var/lib fixture`,
		`could not create an isolated safe /var/backups fixture`,
		`could not create an isolated safe /var/tmp fixture`,
		`could not create an isolated safe /run fixture`,
		`could not create an isolated safe /usr/local fixture`,
		`could not create an isolated safe /usr/local/bin fixture`,
		`could not create an isolated safe /usr/local/sbin fixture`,
		`could not create an isolated safe /opt fixture`,
		`/var/backups/autostream/install-migrations/observability`,
		`published_at: "2026-07-29T00:00:00Z"`,
		`minimum_agent_version: "v2.0.0"`,
		`commit: "0123456789abcdef0123456789abcdef01234567"`,
		`database_schema: "backward_compatible"`,
		`arch: "arm64"`,
		`readonly RUNTIME_UNIT_PATH="/run/systemd/system/${UNIT}"`,
		`systemd runtime unit directory is unsafe`,
		`fixture_owns_paths=false`,
		`fixture_owns_runtime_unit=false`,
		`fixture_owns_service=false`,
		`if [[ ${fixture_owns_paths} == true ]]; then`,
		`if [[ ${fixture_owns_service} == true &&`,
		`if [[ ${fixture_owns_runtime_unit} == true &&`,
		`runtime_identity_matches=false`,
		`${runtime_identity_matches} == true`,
		`old_pid_starttime=""`,
		`/proc/${pid}/stat`,
		`${stat_fields[19]}`,
		`kill_recorded_process_if_same_starttime`,
		`PID reuse guard did not reject a mismatched process identity`,
		`PID reuse guard killed the mismatched process`,
		`cleanup_failed=false`,
		`owned runtime unit identity changed`,
		`runtime unit identity changed before service cleanup`,
		`runtime unit identity changed before removal`,
		`could not remove owned runtime unit`,
		`systemctl show --property ActiveState --value`,
		`service did not become inactive`,
		`service unit remained loaded`,
		`if [[ ${cleanup_failed} == true && ${exit_code} -eq 0 ]]; then`,
		`loaded_unit_state="$(systemctl show --property LoadState --value "${UNIT}"`,
		`runner service is already loaded`,
		`AUTOSTREAM_OBSERVABILITY_INSTALLER_TEST_PREFLIGHT_PROBE=1`,
		`run_preflight_cleanup_probe`,
		`preflight failure removed the existing runtime unit`,
		`preflight failure replaced the existing service process`,
		`preflight failure changed the existing service enablement`,
		`ln -- "${runtime_unit_staging}" "${RUNTIME_UNIT_PATH}"`,
		`mv -fT -- "${runtime_unit_staging}" "${RUNTIME_UNIT_PATH}"`,
		`owned systemd runtime unit changed before atomic commit`,
		`sync -f -- "${runtime_unit_staging}"`,
		`sync -f -- /run/systemd/system`,
		`replace_owned_runtime_unit_atomically "${UNIT_PATH}"`,
		`systemctl show --property FragmentPath --value`,
		`systemctl show --property ExecStart --value`,
		`systemctl show --property User --value`,
		`assert_legacy_runtime_unit "failed migration"`,
		`assert_legacy_runtime_unit "sync failure"`,
		`successful migration did not synchronize the managed runtime unit`,
		`idempotent reinstall changed the loaded runtime unit`,
		`"${TARGET_LOCK}"; do`,
	} {
		if !strings.Contains(fixture, marker) {
			t.Fatalf("Observability installer integration fixture is missing %q", marker)
		}
	}
	atomicReplaceStart := strings.Index(fixture, "replace_owned_runtime_unit_atomically() {")
	if atomicReplaceStart < 0 {
		t.Fatal("Observability installer fixture is missing the atomic runtime unit replacement function")
	}
	atomicReplaceEnd := strings.Index(
		fixture[atomicReplaceStart:],
		"\n}\n\nassert_loaded_runtime_unit()",
	)
	if atomicReplaceEnd < 0 {
		t.Fatal("Observability installer fixture is missing the atomic runtime unit replacement function")
	}
	atomicReplace := fixture[atomicReplaceStart : atomicReplaceStart+atomicReplaceEnd]
	stageRuntimeIndex := strings.Index(atomicReplace, `stage_runtime_unit "${source_path}"`)
	recheckIdentityIndex := strings.LastIndex(
		atomicReplace,
		`current_identity="$(stat -c '%d:%i' -- "${RUNTIME_UNIT_PATH}")"`,
	)
	rejectMismatchIndex := strings.Index(
		atomicReplace,
		`if [[ ${current_identity} != "${runtime_unit_identity}" ]]; then`,
	)
	atomicCommitIndex := strings.Index(
		atomicReplace,
		`mv -fT -- "${runtime_unit_staging}" "${RUNTIME_UNIT_PATH}"`,
	)
	if stageRuntimeIndex < 0 ||
		recheckIdentityIndex < 0 ||
		rejectMismatchIndex < 0 ||
		atomicCommitIndex < 0 ||
		stageRuntimeIndex >= recheckIdentityIndex ||
		recheckIdentityIndex >= rejectMismatchIndex ||
		rejectMismatchIndex >= atomicCommitIndex {
		t.Fatal("Observability runtime unit replacement must stage, recheck ownership, reject mismatches, then commit atomically")
	}
	namespaceIndex := strings.Index(
		fixture,
		`if [[ ${AUTOSTREAM_OBSERVABILITY_INSTALLER_TEST_MOUNT_NS:-} != "1" ]]; then`,
	)
	workDirIndex := strings.Index(fixture, `readonly WORK_DIR="$(mktemp`)
	if namespaceIndex < 0 || workDirIndex < 0 || namespaceIndex >= workDirIndex {
		t.Fatal("installer integration fixture must enter its isolated mount namespace before creating mutable state")
	}
	scratchIndex := strings.Index(
		fixture,
		`autostream-observability-installer-test-scratch /mnt`,
	)
	outerStrictIndex := strings.LastIndex(fixture, "set -euo pipefail")
	usrLowerIndex := strings.Index(fixture, `mount --rbind /usr /mnt/usr-lower`)
	usrPrivateIndex := strings.Index(fixture, `mount --make-rprivate /mnt/usr-lower`)
	etcLowerIndex := strings.Index(fixture, `mount --rbind /etc /mnt/etc-lower`)
	etcPrivateIndex := strings.Index(fixture, `mount --make-rprivate /mnt/etc-lower`)
	varLowerIndex := strings.Index(fixture, `mount --rbind /var /mnt/var-lower`)
	varPrivateIndex := strings.Index(fixture, `mount --make-rprivate /mnt/var-lower`)
	runLowerIndex := strings.Index(fixture, `mount --rbind /run /mnt/run-lower`)
	runPrivateIndex := strings.Index(fixture, `mount --make-rprivate /mnt/run-lower`)
	usrUpperIndex := strings.Index(fixture, `/mnt/usr-upper \`)
	etcUpperIndex := strings.Index(fixture, `/mnt/etc-upper \`)
	varUpperIndex := strings.Index(fixture, `/mnt/var-upper \`)
	runUpperIndex := strings.Index(fixture, `/mnt/run-upper \`)
	usrWorkIndex := strings.Index(fixture, `/mnt/usr-work \`)
	etcWorkIndex := strings.Index(fixture, `/mnt/etc-work \`)
	varWorkIndex := strings.Index(fixture, `/mnt/var-work \`)
	runWorkIndex := strings.Index(fixture, `/mnt/run-work`)
	usrOverlayIndex := strings.Index(
		fixture,
		`autostream-observability-installer-test-usr-overlay /usr`,
	)
	etcOverlayIndex := strings.Index(
		fixture,
		`autostream-observability-installer-test-etc-overlay /etc`,
	)
	varOverlayIndex := strings.Index(
		fixture,
		`autostream-observability-installer-test-var-overlay /var`,
	)
	runOverlayIndex := strings.Index(
		fixture,
		`autostream-observability-installer-test-run-overlay /run`,
	)
	systemdBindIndex := strings.Index(
		fixture,
		`mount --rbind /mnt/run-lower/systemd /run/systemd`,
	)
	systemdIdentityIndex := strings.Index(
		fixture,
		`systemd_identity="$(stat -c "%d:%i" -- /mnt/run-lower/systemd)"`,
	)
	runtimeSafetyIndex := strings.Index(
		fixture,
		`readonly RUNTIME_UNIT_PATH="/run/systemd/system/${UNIT}"`,
	)
	binMountIndex := strings.Index(
		fixture,
		`autostream-observability-installer-test-bin /usr/local/bin`,
	)
	sbinMountIndex := strings.Index(
		fixture,
		`autostream-observability-installer-test-sbin /usr/local/sbin`,
	)
	optMountIndex := strings.Index(fixture, `autostream-observability-installer-test-opt /opt`)
	sealedMountIndex := strings.Index(
		fixture,
		`autostream-observability-installer-test-sealed /mnt`,
	)
	identityExportIndex := strings.Index(
		fixture,
		`AUTOSTREAM_OBSERVABILITY_INSTALLER_TEST_SYSTEMD_IDENTITY="${systemd_identity}"`,
	)
	if outerStrictIndex < 0 || scratchIndex < 0 ||
		usrLowerIndex < 0 || usrPrivateIndex < 0 ||
		etcLowerIndex < 0 || etcPrivateIndex < 0 ||
		varLowerIndex < 0 || varPrivateIndex < 0 ||
		runLowerIndex < 0 || runPrivateIndex < 0 ||
		usrUpperIndex < 0 || etcUpperIndex < 0 ||
		varUpperIndex < 0 || runUpperIndex < 0 ||
		usrWorkIndex < 0 || etcWorkIndex < 0 ||
		varWorkIndex < 0 || runWorkIndex < 0 ||
		usrOverlayIndex < 0 || etcOverlayIndex < 0 ||
		varOverlayIndex < 0 || runOverlayIndex < 0 ||
		systemdBindIndex < 0 || systemdIdentityIndex < 0 ||
		binMountIndex < 0 || sbinMountIndex < 0 ||
		optMountIndex < 0 || sealedMountIndex < 0 || identityExportIndex < 0 ||
		workDirIndex < 0 || runtimeSafetyIndex < 0 ||
		namespaceIndex >= outerStrictIndex ||
		outerStrictIndex >= scratchIndex ||
		scratchIndex >= usrLowerIndex ||
		usrLowerIndex >= usrPrivateIndex ||
		usrPrivateIndex >= etcLowerIndex ||
		etcLowerIndex >= etcPrivateIndex ||
		etcPrivateIndex >= varLowerIndex ||
		varLowerIndex >= varPrivateIndex ||
		varPrivateIndex >= runLowerIndex ||
		runLowerIndex >= runPrivateIndex ||
		runPrivateIndex >= usrUpperIndex ||
		usrUpperIndex >= etcUpperIndex ||
		etcUpperIndex >= varUpperIndex ||
		varUpperIndex >= runUpperIndex ||
		runUpperIndex >= usrWorkIndex ||
		usrWorkIndex >= etcWorkIndex ||
		etcWorkIndex >= varWorkIndex ||
		varWorkIndex >= runWorkIndex ||
		runWorkIndex >= usrOverlayIndex ||
		usrOverlayIndex >= etcOverlayIndex ||
		etcOverlayIndex >= varOverlayIndex ||
		varOverlayIndex >= runOverlayIndex ||
		runOverlayIndex >= systemdBindIndex ||
		systemdBindIndex >= systemdIdentityIndex ||
		systemdIdentityIndex >= binMountIndex ||
		binMountIndex >= sbinMountIndex ||
		sbinMountIndex >= optMountIndex ||
		optMountIndex >= sealedMountIndex ||
		sealedMountIndex >= identityExportIndex ||
		identityExportIndex >= workDirIndex ||
		workDirIndex >= runtimeSafetyIndex {
		t.Fatal("installer integration fixture mount isolation and mutable-state ordering is incomplete")
	}
	const safeAccountReset = "userdel autostream\nif getent group autostream >/dev/null 2>&1; then\n  groupdel autostream\nfi"
	if count := strings.Count(fixture, safeAccountReset); count != 2 {
		t.Fatalf("expected two account resets that tolerate userdel removing the private group, got %d", count)
	}
	if count := strings.Count(fixture, "[Install]\nWantedBy=multi-user.target"); count != 3 {
		t.Fatalf("integration fixture must define three enable-capable but disabled units, got %d", count)
	}
	preflightIndex := strings.Index(fixture, `for path in \`)
	probeIndex := strings.Index(fixture, "\nrun_preflight_cleanup_probe\n")
	ownershipIndex := strings.Index(fixture, `fixture_owns_paths=true`)
	runtimeCreateIndex := strings.LastIndex(fixture, `create_runtime_unit_no_clobber "${UNIT_PATH}"`)
	if preflightIndex < 0 || probeIndex < 0 || ownershipIndex < 0 || runtimeCreateIndex < 0 ||
		preflightIndex >= probeIndex || probeIndex >= ownershipIndex ||
		ownershipIndex >= runtimeCreateIndex {
		t.Fatal("fixture must run the non-destructive preflight probe before claiming path ownership")
	}
	if strings.Contains(
		fixture,
		`install -o root -g root -m 0644 "${UNIT_PATH}" "${RUNTIME_UNIT_PATH}"`,
	) {
		t.Fatal("runtime unit creation must be atomic and no-clobber")
	}
	innerFixtureIndex := strings.Index(fixture, "\nfi\ngrep -Eq ' /mnt ")
	if innerFixtureIndex < 0 ||
		strings.Contains(fixture[innerFixtureIndex:], "/mnt/run-lower") {
		t.Fatal("sealed inner fixture must not retain a writable lower-directory alias")
	}
	starttimeCheckIndex := strings.Index(
		fixture,
		`[[ ${current_starttime} == "${old_pid_starttime}" ]]`,
	)
	fallbackKillIndex := strings.Index(fixture, `kill "${old_pid}" || return 1`)
	if starttimeCheckIndex < 0 || fallbackKillIndex < 0 ||
		starttimeCheckIndex >= fallbackKillIndex {
		t.Fatal("raw PID fallback must verify the recorded /proc start time before kill")
	}
}

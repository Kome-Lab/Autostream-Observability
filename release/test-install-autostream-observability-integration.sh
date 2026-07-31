#!/bin/bash
set -euo pipefail

umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C

die() {
  printf 'observability installer integration test: %s\n' "$*" >&2
  exit 1
}

[[ ${EUID} -eq 0 ]] || die "must run as root"
[[ $(uname -m) == "x86_64" ]] || die "this integration fixture requires an amd64 Linux runner"

if [[ ${AUTOSTREAM_OBSERVABILITY_INSTALLER_TEST_MOUNT_NS:-} != "1" ]]; then
  exec unshare --mount --propagation private bash -c '
    set -euo pipefail
    mount -t tmpfs -o nodev,nosuid,mode=0755,uid=0,gid=0 \
      autostream-observability-installer-test-scratch /mnt
    install -d -o root -g root -m 0755 \
      /mnt/usr-lower \
      /mnt/etc-lower \
      /mnt/var-lower \
      /mnt/run-lower
    mount --rbind /usr /mnt/usr-lower
    mount --make-rprivate /mnt/usr-lower
    mount --rbind /etc /mnt/etc-lower
    mount --make-rprivate /mnt/etc-lower
    mount --rbind /var /mnt/var-lower
    mount --make-rprivate /mnt/var-lower
    mount --rbind /run /mnt/run-lower
    mount --make-rprivate /mnt/run-lower
    install -d -o root -g root -m 0755 \
      /mnt/usr-upper \
      /mnt/usr-upper/local \
      /mnt/etc-upper \
      /mnt/etc-upper/systemd \
      /mnt/etc-upper/systemd/system \
      /mnt/var-upper \
      /mnt/var-upper/lib \
      /mnt/var-upper/backups \
      /mnt/run-upper \
      /mnt/run-upper/systemd
    install -d -o root -g root -m 1777 /mnt/var-upper/tmp
    install -d -o root -g root -m 0700 \
      /mnt/usr-work \
      /mnt/etc-work \
      /mnt/var-work \
      /mnt/run-work
    mount -t overlay -o nodev,nosuid,lowerdir=/mnt/usr-lower,upperdir=/mnt/usr-upper,workdir=/mnt/usr-work \
      autostream-observability-installer-test-usr-overlay /usr
    mount -t overlay -o nodev,nosuid,lowerdir=/mnt/etc-lower,upperdir=/mnt/etc-upper,workdir=/mnt/etc-work \
      autostream-observability-installer-test-etc-overlay /etc
    mount -t overlay -o nodev,nosuid,lowerdir=/mnt/var-lower,upperdir=/mnt/var-upper,workdir=/mnt/var-work \
      autostream-observability-installer-test-var-overlay /var
    mount -t overlay -o nodev,nosuid,lowerdir=/mnt/run-lower,upperdir=/mnt/run-upper,workdir=/mnt/run-work \
      autostream-observability-installer-test-run-overlay /run
    mount --rbind /mnt/run-lower/systemd /run/systemd
    mount --make-rprivate /run/systemd
    systemd_identity="$(stat -c "%d:%i" -- /mnt/run-lower/systemd)"
    [[ ${systemd_identity} =~ ^[0-9]+:[0-9]+$ &&
      $(stat -c "%d:%i" -- /run/systemd) == "${systemd_identity}" ]]
    mount -t tmpfs -o nodev,nosuid,mode=0755,uid=0,gid=0 \
      autostream-observability-installer-test-bin /usr/local/bin
    mount -t tmpfs -o nodev,nosuid,mode=0755,uid=0,gid=0 \
      autostream-observability-installer-test-sbin /usr/local/sbin
    mount -t tmpfs -o nodev,nosuid,mode=0755,uid=0,gid=0 \
      autostream-observability-installer-test-opt /opt
    mount -t tmpfs -o ro,nodev,nosuid,noexec,mode=0555,uid=0,gid=0 \
      autostream-observability-installer-test-sealed /mnt
    exec env \
      AUTOSTREAM_OBSERVABILITY_INSTALLER_TEST_MOUNT_NS=1 \
      AUTOSTREAM_OBSERVABILITY_INSTALLER_TEST_SYSTEMD_IDENTITY="${systemd_identity}" \
      bash "$1"
  ' autostream-observability-installer-test-mount "$0"
fi
grep -Eq ' /mnt .* - tmpfs autostream-observability-installer-test-sealed ' \
  /proc/self/mountinfo || die "sealed /mnt mount is missing"
awk '$5 == "/mnt" &&
  $6 ~ /(^|,)ro(,|$)/ &&
  $6 ~ /(^|,)nodev(,|$)/ &&
  $6 ~ /(^|,)nosuid(,|$)/ &&
  $6 ~ /(^|,)noexec(,|$)/ { found = 1 }
  END { exit !found }' /proc/self/mountinfo || \
  die "sealed /mnt mount options are unsafe"
[[ $(stat -c '%U:%G:%a' -- /mnt) == "root:root:555" ]] || \
  die "sealed /mnt ownership or mode is unsafe"
if touch /mnt/.autostream-observability-write-probe 2>/dev/null; then
  rm -f -- /mnt/.autostream-observability-write-probe
  die "sealed /mnt unexpectedly accepted a write"
fi
grep -Eq ' /usr .* - overlay autostream-observability-installer-test-usr-overlay ' \
  /proc/self/mountinfo || die "isolated /usr overlay mount is missing"
grep -Eq ' /etc .* - overlay autostream-observability-installer-test-etc-overlay ' \
  /proc/self/mountinfo || die "isolated /etc overlay mount is missing"
grep -Eq ' /var .* - overlay autostream-observability-installer-test-var-overlay ' \
  /proc/self/mountinfo || die "isolated /var overlay mount is missing"
grep -Eq ' /run .* - overlay autostream-observability-installer-test-run-overlay ' \
  /proc/self/mountinfo || die "isolated /run overlay mount is missing"
grep -Eq ' /run/systemd ' /proc/self/mountinfo || \
  die "host-backed /run/systemd mount is missing"
readonly EXPECTED_SYSTEMD_IDENTITY="${AUTOSTREAM_OBSERVABILITY_INSTALLER_TEST_SYSTEMD_IDENTITY:-}"
[[ ${EXPECTED_SYSTEMD_IDENTITY} =~ ^[0-9]+:[0-9]+$ &&
  $(stat -c '%d:%i' -- /run/systemd) == "${EXPECTED_SYSTEMD_IDENTITY}" ]] || \
  die "host-backed /run/systemd mount identity is invalid"
grep -Eq ' /usr/local/bin .* - tmpfs autostream-observability-installer-test-bin ' \
  /proc/self/mountinfo || die "isolated /usr/local/bin mount is missing"
grep -Eq ' /usr/local/sbin .* - tmpfs autostream-observability-installer-test-sbin ' \
  /proc/self/mountinfo || die "isolated /usr/local/sbin mount is missing"
grep -Eq ' /opt .* - tmpfs autostream-observability-installer-test-opt ' \
  /proc/self/mountinfo || die "isolated /opt mount is missing"
[[ $(stat -c '%U:%G:%a' -- /usr) == "root:root:755" ]] || \
  die "could not create an isolated safe /usr fixture"
[[ $(stat -c '%U:%G:%a' -- /etc) == "root:root:755" ]] || \
  die "could not create an isolated safe /etc fixture"
[[ $(stat -c '%U:%G:%a' -- /etc/systemd) == "root:root:755" ]] || \
  die "could not create an isolated safe /etc/systemd fixture"
[[ $(stat -c '%U:%G:%a' -- /etc/systemd/system) == "root:root:755" ]] || \
  die "could not create an isolated safe /etc/systemd/system fixture"
[[ $(stat -c '%U:%G:%a' -- /var) == "root:root:755" ]] || \
  die "could not create an isolated safe /var fixture"
[[ $(stat -c '%U:%G:%a' -- /var/lib) == "root:root:755" ]] || \
  die "could not create an isolated safe /var/lib fixture"
[[ $(stat -c '%U:%G:%a' -- /var/backups) == "root:root:755" ]] || \
  die "could not create an isolated safe /var/backups fixture"
[[ $(stat -c '%U:%G:%a' -- /var/tmp) == "root:root:1777" ]] || \
  die "could not create an isolated safe /var/tmp fixture"
[[ $(stat -c '%U:%G:%a' -- /run) == "root:root:755" ]] || \
  die "could not create an isolated safe /run fixture"
[[ $(stat -c '%U:%G:%a' -- /usr/local) == "root:root:755" ]] || \
  die "could not create an isolated safe /usr/local fixture"
[[ $(stat -c '%U:%G:%a' -- /usr/local/bin) == "root:root:755" ]] || \
  die "could not create an isolated safe /usr/local/bin fixture"
[[ $(stat -c '%U:%G:%a' -- /usr/local/sbin) == "root:root:755" ]] || \
  die "could not create an isolated safe /usr/local/sbin fixture"
[[ $(stat -c '%U:%G:%a' -- /opt) == "root:root:755" ]] || \
  die "could not create an isolated safe /opt fixture"

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly INSTALLER_SOURCE="${SCRIPT_DIR}/install-autostream-observability"
readonly VERSION="v9.9.9"
readonly ARTIFACT_ID="autostream-observability_${VERSION}_linux_amd64"
readonly FIXTURE_COMMIT="0123456789abcdef0123456789abcdef01234567"
readonly FIXTURE_BUILD_DATE="2026-07-31T00:00:00Z"
readonly WORK_DIR="$(mktemp -d /var/tmp/autostream-observability-installer-test.XXXXXXXX)"
readonly ARTIFACTS_DIR="${WORK_DIR}/artifacts"
readonly EXTRACTED_ROOT="${ARTIFACTS_DIR}/${ARTIFACT_ID}"
readonly ARCHIVE="${ARTIFACTS_DIR}/${ARTIFACT_ID}.tar.gz"
readonly BAD_ARTIFACTS_DIR="${WORK_DIR}/bad-artifacts"
readonly BAD_EXTRACTED_ROOT="${BAD_ARTIFACTS_DIR}/${ARTIFACT_ID}"
readonly BAD_ARCHIVE="${BAD_ARTIFACTS_DIR}/${ARTIFACT_ID}.tar.gz"
readonly REAL_SYSTEMCTL_COPY="${WORK_DIR}/systemctl.real"
readonly FAIL_SYSTEMCTL="${WORK_DIR}/systemctl.fail"
readonly TERM_SYSTEMCTL="${WORK_DIR}/systemctl.term"
readonly TERM_SYSTEMCTL_CALL_COUNT="${WORK_DIR}/systemctl.term.calls"
readonly CLEANUP_SECOND_TERM_MARKER="${WORK_DIR}/cleanup-second-term-delivered"
readonly SYSTEMCTL_CALL_LOG="${WORK_DIR}/systemctl.calls"
readonly SYSTEMCTL_MOUNT_MARKER="${WORK_DIR}/systemctl.mount.ok"
readonly REAL_GROUPADD_COPY="${WORK_DIR}/groupadd.real"
readonly TERM_GROUPADD="${WORK_DIR}/groupadd.term"
readonly GROUPADD_TERM_MARKER="${WORK_DIR}/groupadd-term-delivered"
readonly REAL_USERADD_COPY="${WORK_DIR}/useradd.real"
readonly TERM_USERADD="${WORK_DIR}/useradd.term"
readonly USERADD_TERM_MARKER="${WORK_DIR}/useradd-term-delivered"
readonly JOURNAL_TERM_BASH_ENV="${WORK_DIR}/journal-term.bash-env"
readonly JOURNAL_FIELD_TERM_MARKER="${WORK_DIR}/journal-field-term-delivered"
readonly JOURNAL_ORDER_TERM_MARKER="${WORK_DIR}/journal-order-term-delivered"
readonly REAL_MKTEMP_COPY="${WORK_DIR}/mktemp.real"
readonly FAIL_MKTEMP="${WORK_DIR}/mktemp.fail"
readonly MKTEMP_CALL_LOG="${WORK_DIR}/mktemp.calls"
readonly MKTEMP_MOUNT_MARKER="${WORK_DIR}/mktemp.mount.ok"
readonly REAL_SYNC_COPY="${WORK_DIR}/sync.real"
readonly FAIL_SYNC="${WORK_DIR}/sync.fail"
readonly SYNC_CALL_LOG="${WORK_DIR}/sync.calls"
readonly SYNC_FAILURE_MARKER="${WORK_DIR}/sync.failed.once"
readonly SYNC_MOUNT_MARKER="${WORK_DIR}/sync.mount.ok"
readonly MARIADB_MOUNT_MARKER="${WORK_DIR}/mariadb.mount.ok"
readonly UNIT="autostream-observability.service"
readonly UNIT_PATH="/etc/systemd/system/${UNIT}"
readonly RUNTIME_UNIT_PATH="/run/systemd/system/${UNIT}"
[[ -d /run/systemd/system && ! -L /run/systemd/system &&
  $(readlink -f -- /run/systemd/system) == "/run/systemd/system" &&
  $(stat -c '%U:%G:%a' -- /run/systemd/system) == "root:root:755" ]] || \
  die "systemd runtime unit directory is unsafe"
readonly PUBLIC_BINARY="/usr/local/bin/autostream-observability"
readonly PUBLIC_ALIAS="/usr/local/bin/observability"
readonly ENV_PATH="/etc/autostream/observability.env"
readonly STATE_DIR="/var/lib/autostream/observability"
readonly STATE_SENTINEL="${STATE_DIR}/rollback-sentinel"
readonly MANAGED_ROOT="/opt/autostream/observability"
readonly BACKUP_EXECUTABLE="/usr/local/sbin/autostream-backup-observability"
readonly DATABASE_BACKUP_DIR="/var/backups/autostream/observability"
readonly INSTALL_BACKUP_ROOT="/var/backups/autostream/install-migrations/observability"
readonly MARIADB_DEFAULTS="/etc/autostream-local-executor/mariadb-backup.cnf"
TARGET_LOCK_ID=$(printf '%s' "${UNIT}" | sha256sum | awk 'NR == 1 { print substr($1, 1, 12) }')
[[ ${TARGET_LOCK_ID} =~ ^[0-9a-f]{12}$ ]] || die "could not derive target lock identifier"
readonly TARGET_LOCK_ID
readonly TARGET_LOCK="/run/autostream-updater/.autostream-updater-${TARGET_LOCK_ID}.lock"
readonly SHARED_HOST_SETUP_LOCK="/run/autostream-updater/.autostream-runtime-host-setup.lock"
readonly LEGACY_UNIT_CONTENT="observability-installer-integration-legacy-unit"
readonly LEGACY_BINARY_CONTENT="observability-installer-integration-legacy-binary"
readonly LEGACY_ALIAS_CONTENT="observability-installer-integration-legacy-alias"
readonly LEGACY_HELPER_CONTENT="observability-installer-integration-legacy-helper"
readonly LEGACY_ENV_CONTENT="OBSERVABILITY_INSTALLER_INTEGRATION_ENV=preserve-exactly"
readonly LEGACY_DB_CONTENT="[client]
password=observability-installer-integration-preserve-exactly"

created_autostream_user=false
created_mariadb_dump=false
fixture_owns_paths=false
fixture_owns_runtime_unit=false
fixture_owns_service=false
runtime_unit_identity=""
runtime_unit_staging=""
old_pid=""
old_pid_starttime=""

assert_state_preserved() {
  local label=$1
  [[ -d ${STATE_DIR} && ! -L ${STATE_DIR} ]] || \
    die "${label} changed existing state existence"
  [[ $(stat -c '%d:%i' -- "${STATE_DIR}") == "${state_identity_before}" ]] || \
    die "${label} replaced the existing state directory"
  [[ $(stat -c '%u:%g:%a' -- "${STATE_DIR}") == "${state_metadata_before}" ]] || \
    die "${label} changed existing state owner or mode"
  [[ -f ${STATE_SENTINEL} && ! -L ${STATE_SENTINEL} ]] || \
    die "${label} removed the state sentinel"
  [[ $(sha256sum "${STATE_SENTINEL}" | awk 'NR == 1 { print $1 }') == \
    "${state_sentinel_before}" ]] || \
    die "${label} changed existing state content"
}

read_process_starttime() {
  local pid=$1
  local stat_line=""
  local stat_tail=""
  local -a stat_fields=()

  [[ ${pid} =~ ^[1-9][0-9]*$ && -r /proc/${pid}/stat ]] || return 1
  IFS= read -r stat_line < "/proc/${pid}/stat" || return 1
  stat_tail="${stat_line##*) }"
  read -r -a stat_fields <<< "${stat_tail}"
  [[ ${#stat_fields[@]} -ge 20 && ${stat_fields[19]} =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "${stat_fields[19]}"
}

kill_recorded_process_if_same_starttime() {
  local current_starttime=""

  [[ -n ${old_pid} && -n ${old_pid_starttime} ]] || return 0
  if [[ ! -e /proc/${old_pid} ]]; then
    old_pid=""
    old_pid_starttime=""
    return 0
  fi
  current_starttime="$(read_process_starttime "${old_pid}")" || return 1
  [[ ${current_starttime} == "${old_pid_starttime}" ]] || return 2
  kill "${old_pid}" || return 1
  old_pid=""
  old_pid_starttime=""
}

stage_runtime_unit() {
  local source_path=$1
  local staged_path=""

  if ! staged_path="$(mktemp "/run/systemd/system/.${UNIT}.fixture.XXXXXXXX")"; then
    die "could not stage the systemd runtime unit"
  fi
  runtime_unit_staging="${staged_path}"
  install -o root -g root -m 0644 "${source_path}" "${runtime_unit_staging}"
  sync -f -- "${runtime_unit_staging}"
}

create_runtime_unit_no_clobber() {
  local source_path=$1

  stage_runtime_unit "${source_path}"
  if ! ln -- "${runtime_unit_staging}" "${RUNTIME_UNIT_PATH}"; then
    rm -f -- "${runtime_unit_staging}"
    runtime_unit_staging=""
    die "runner became unclean at ${RUNTIME_UNIT_PATH}"
  fi
  fixture_owns_runtime_unit=true
  runtime_unit_identity="$(stat -c '%d:%i' -- "${RUNTIME_UNIT_PATH}")"
  rm -f -- "${runtime_unit_staging}"
  runtime_unit_staging=""
  sync -f -- /run/systemd/system
}

replace_owned_runtime_unit_atomically() {
  local source_path=$1
  local current_identity=""

  [[ ${fixture_owns_runtime_unit} == true ]] || \
    die "refusing to replace an unowned systemd runtime unit"
  [[ -f ${RUNTIME_UNIT_PATH} && ! -L ${RUNTIME_UNIT_PATH} ]] || \
    die "owned systemd runtime unit disappeared or became unsafe"
  current_identity="$(stat -c '%d:%i' -- "${RUNTIME_UNIT_PATH}")"
  [[ ${current_identity} == "${runtime_unit_identity}" ]] || \
    die "owned systemd runtime unit was replaced externally"

  stage_runtime_unit "${source_path}"
  current_identity="$(stat -c '%d:%i' -- "${RUNTIME_UNIT_PATH}")"
  if [[ ${current_identity} != "${runtime_unit_identity}" ]]; then
    rm -f -- "${runtime_unit_staging}"
    runtime_unit_staging=""
    die "owned systemd runtime unit changed before atomic commit"
  fi
  mv -fT -- "${runtime_unit_staging}" "${RUNTIME_UNIT_PATH}"
  runtime_unit_staging=""
  runtime_unit_identity="$(stat -c '%d:%i' -- "${RUNTIME_UNIT_PATH}")"
  sync -f -- /run/systemd/system
}

assert_loaded_runtime_unit() {
  local expected_exec=$1
  local expected_user=$2
  local scenario=$3
  local fragment_path=""
  local exec_start=""
  local service_user=""

  fragment_path="$(systemctl show --property FragmentPath --value "${UNIT}")"
  [[ ${fragment_path} == "${RUNTIME_UNIT_PATH}" ]] || \
    die "${scenario} loaded unit from ${fragment_path:-unknown}, expected ${RUNTIME_UNIT_PATH}"
  exec_start="$(systemctl show --property ExecStart --value "${UNIT}")"
  [[ ${exec_start} == *"${expected_exec}"* ]] || \
    die "${scenario} loaded unexpected ExecStart: ${exec_start:-empty}"
  service_user="$(systemctl show --property User --value "${UNIT}")"
  [[ ${service_user} == "${expected_user}" ]] || \
    die "${scenario} loaded unexpected User: ${service_user:-root}"
}

assert_legacy_runtime_unit() {
  local scenario=$1

  [[ -f ${RUNTIME_UNIT_PATH} && ! -L ${RUNTIME_UNIT_PATH} ]] || \
    die "${scenario} lost the legacy runtime unit"
  [[ $(sha256sum "${RUNTIME_UNIT_PATH}" | awk 'NR == 1 { print $1 }') == \
    "${runtime_unit_before}" ]] || \
    die "${scenario} changed the legacy runtime unit"
  [[ $(sha256sum "${RUNTIME_UNIT_PATH}" | awk 'NR == 1 { print $1 }') == \
    "$(sha256sum "${UNIT_PATH}" | awk 'NR == 1 { print $1 }')" ]] || \
    die "${scenario} runtime unit diverged from the restored legacy unit"
  assert_loaded_runtime_unit "/usr/bin/sleep" "" "${scenario}"
}

run_preflight_cleanup_probe() {
  local probe_enabled_state=""
  local probe_hash=""
  local probe_identity=""
  local probe_pid=""
  local probe_status=0
  local mismatch_status=0
  local saved_starttime=""
  local current_identity=""

  [[ ${fixture_owns_paths} == false &&
    ${fixture_owns_runtime_unit} == false &&
    ${fixture_owns_service} == false ]] || \
    die "preflight cleanup probe began after fixture ownership"

  cat > "${UNIT_PATH}" <<EOF
[Unit]
Description=AutoStream Observability preflight cleanup sentinel

[Service]
Type=simple
ExecStart=/usr/bin/sleep infinity

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 "${UNIT_PATH}"
  create_runtime_unit_no_clobber "${UNIT_PATH}"
  systemctl daemon-reload
  fixture_owns_service=true
  systemctl start "${UNIT}"
  probe_pid="$(systemctl show --property MainPID --value "${UNIT}")"
  [[ ${probe_pid} =~ ^[1-9][0-9]*$ ]] || \
    die "preflight cleanup sentinel did not start"
  old_pid="${probe_pid}"
  if ! old_pid_starttime="$(read_process_starttime "${old_pid}")"; then
    die "could not record the preflight cleanup sentinel process identity"
  fi
  assert_loaded_runtime_unit "/usr/bin/sleep" "" "preflight cleanup sentinel"
  saved_starttime="${old_pid_starttime}"
  old_pid_starttime=0
  set +e
  kill_recorded_process_if_same_starttime
  mismatch_status=$?
  set -e
  [[ ${mismatch_status} -eq 2 ]] || \
    die "PID reuse guard did not reject a mismatched process identity"
  kill -0 "${probe_pid}" || die "PID reuse guard killed the mismatched process"
  old_pid_starttime="${saved_starttime}"
  probe_identity="$(stat -c '%d:%i' -- "${RUNTIME_UNIT_PATH}")"
  probe_hash="$(sha256sum "${RUNTIME_UNIT_PATH}" | awk 'NR == 1 { print $1 }')"
  probe_enabled_state="$(systemctl is-enabled "${UNIT}" 2>/dev/null || true)"
  rm -f -- "${UNIT_PATH}"

  set +e
  AUTOSTREAM_OBSERVABILITY_INSTALLER_TEST_MOUNT_NS=1 \
    AUTOSTREAM_OBSERVABILITY_INSTALLER_TEST_PREFLIGHT_PROBE=1 \
    bash "$0" > "${WORK_DIR}/preflight-cleanup-probe.out" 2>&1
  probe_status=$?
  set -e
  [[ ${probe_status} -ne 0 ]] || \
    die "preflight cleanup probe unexpectedly passed"
  grep -Fx -- \
    "observability installer integration test: runner is not clean at ${RUNTIME_UNIT_PATH}" \
    "${WORK_DIR}/preflight-cleanup-probe.out" >/dev/null || \
    die "preflight cleanup probe did not stop at the runtime unit conflict"
  [[ -f ${RUNTIME_UNIT_PATH} && ! -L ${RUNTIME_UNIT_PATH} ]] || \
    die "preflight failure removed the existing runtime unit"
  [[ $(stat -c '%d:%i' -- "${RUNTIME_UNIT_PATH}") == "${probe_identity}" ]] || \
    die "preflight failure replaced the existing runtime unit"
  [[ $(sha256sum "${RUNTIME_UNIT_PATH}" | awk 'NR == 1 { print $1 }') == \
    "${probe_hash}" ]] || \
    die "preflight failure changed the existing runtime unit"
  [[ $(systemctl show --property MainPID --value "${UNIT}") == "${probe_pid}" ]] || \
    die "preflight failure replaced the existing service process"
  kill -0 "${probe_pid}" || die "preflight failure stopped the existing service process"
  [[ $(systemctl is-enabled "${UNIT}" 2>/dev/null || true) == \
    "${probe_enabled_state}" ]] || \
    die "preflight failure changed the existing service enablement"
  assert_loaded_runtime_unit "/usr/bin/sleep" "" "preflight failure"

  current_identity="$(stat -c '%d:%i' -- "${RUNTIME_UNIT_PATH}")"
  [[ ${current_identity} == "${runtime_unit_identity}" ]] || \
    die "preflight cleanup sentinel runtime unit was replaced externally"
  systemctl stop "${UNIT}"
  current_identity="$(stat -c '%d:%i' -- "${RUNTIME_UNIT_PATH}")"
  [[ ${current_identity} == "${runtime_unit_identity}" ]] || \
    die "preflight cleanup sentinel runtime unit was replaced externally"
  fixture_owns_service=false
  old_pid=""
  old_pid_starttime=""
  rm -f -- "${RUNTIME_UNIT_PATH}"
  fixture_owns_runtime_unit=false
  runtime_unit_identity=""
  sync -f -- /run/systemd/system
  systemctl daemon-reload
  [[ $(systemctl show --property LoadState --value "${UNIT}") == "not-found" ]] || \
    die "preflight cleanup sentinel remained loaded"
}

cleanup() {
  local exit_code=$?
  local current_identity=""
  local active_state=""
  local load_state=""
  local kill_status=0
  local cleanup_failed=false
  local runtime_identity_matches=false
  local should_reload=false

  set +e
  if [[ ${fixture_owns_runtime_unit} == true &&
    -f ${RUNTIME_UNIT_PATH} && ! -L ${RUNTIME_UNIT_PATH} ]]; then
    current_identity="$(stat -c '%d:%i' -- "${RUNTIME_UNIT_PATH}" 2>/dev/null)"
    if [[ -n ${runtime_unit_identity} &&
      ${current_identity} == "${runtime_unit_identity}" ]]; then
      runtime_identity_matches=true
    else
      printf '%s\n' "observability installer integration test cleanup: owned runtime unit identity changed" >&2
      cleanup_failed=true
    fi
  elif [[ ${fixture_owns_runtime_unit} == true ]]; then
    printf '%s\n' "observability installer integration test cleanup: owned runtime unit is missing or unsafe" >&2
    cleanup_failed=true
    [[ ! -e ${RUNTIME_UNIT_PATH} && ! -L ${RUNTIME_UNIT_PATH} ]] && should_reload=true
  fi
  if [[ ${fixture_owns_service} == true &&
    ${runtime_identity_matches} == true ]]; then
    current_identity="$(stat -c '%d:%i' -- "${RUNTIME_UNIT_PATH}" 2>/dev/null)"
    if [[ ${current_identity} != "${runtime_unit_identity}" ]]; then
      runtime_identity_matches=false
      printf '%s\n' "observability installer integration test cleanup: runtime unit identity changed before service cleanup" >&2
      cleanup_failed=true
    else
      if systemctl stop "${UNIT}" >/dev/null 2>&1; then
        old_pid=""
        old_pid_starttime=""
      else
        printf '%s\n' "observability installer integration test cleanup: could not stop owned service" >&2
        cleanup_failed=true
      fi
      if ! systemctl disable "${UNIT}" >/dev/null 2>&1; then
        printf '%s\n' "observability installer integration test cleanup: could not disable owned service" >&2
        cleanup_failed=true
      fi
    fi
  fi
  if [[ ${fixture_owns_service} == true && -n ${old_pid} ]]; then
    kill_recorded_process_if_same_starttime
    kill_status=$?
    case ${kill_status} in
      0)
        ;;
      2)
        printf '%s\n' "observability installer integration test cleanup: refusing to kill a reused PID" >&2
        ;;
      *)
        printf '%s\n' "observability installer integration test cleanup: could not terminate recorded service process" >&2
        cleanup_failed=true
        ;;
    esac
  fi
  if [[ ${fixture_owns_runtime_unit} == true &&
    ${runtime_identity_matches} == true ]]; then
    current_identity="$(stat -c '%d:%i' -- "${RUNTIME_UNIT_PATH}" 2>/dev/null)"
    if [[ ${current_identity} != "${runtime_unit_identity}" ]]; then
      runtime_identity_matches=false
      printf '%s\n' "observability installer integration test cleanup: runtime unit identity changed before removal" >&2
      cleanup_failed=true
    else
      if rm -f -- "${RUNTIME_UNIT_PATH}" &&
        [[ ! -e ${RUNTIME_UNIT_PATH} && ! -L ${RUNTIME_UNIT_PATH} ]]; then
        should_reload=true
      else
        printf '%s\n' "observability installer integration test cleanup: could not remove owned runtime unit" >&2
        cleanup_failed=true
      fi
    fi
  fi
  if [[ -n ${runtime_unit_staging} ]]; then
    if ! rm -f -- "${runtime_unit_staging}"; then
      printf '%s\n' "observability installer integration test cleanup: could not remove runtime staging file" >&2
      cleanup_failed=true
    fi
  fi
  if [[ ${fixture_owns_paths} == true ]]; then
    if ! rm -f -- "${UNIT_PATH}"; then
      printf '%s\n' "observability installer integration test cleanup: could not remove private systemd unit" >&2
      cleanup_failed=true
    fi
  fi
  if [[ ${should_reload} == true ]]; then
    if ! sync -f -- /run/systemd/system ||
      ! systemctl daemon-reload >/dev/null 2>&1; then
      printf '%s\n' "observability installer integration test cleanup: could not reload systemd after runtime cleanup" >&2
      cleanup_failed=true
    fi
  fi
  if [[ ${fixture_owns_service} == true || ${fixture_owns_runtime_unit} == true ]]; then
    active_state="$(systemctl show --property ActiveState --value "${UNIT}" 2>/dev/null)"
    if [[ ${active_state} != "inactive" ]]; then
      printf '%s\n' "observability installer integration test cleanup: service did not become inactive" >&2
      cleanup_failed=true
    fi
    load_state="$(systemctl show --property LoadState --value "${UNIT}" 2>/dev/null)"
    if [[ ${load_state} != "not-found" ]]; then
      printf '%s\n' "observability installer integration test cleanup: service unit remained loaded" >&2
      cleanup_failed=true
    fi
  fi
  if [[ ${fixture_owns_paths} == true ]]; then
    rm -f -- \
      "${PUBLIC_BINARY}" \
      "${PUBLIC_ALIAS}" \
      "${BACKUP_EXECUTABLE}" \
      "${ENV_PATH}" \
      "${MARIADB_DEFAULTS}" \
      "${SHARED_HOST_SETUP_LOCK}" \
      "${TARGET_LOCK}"
    rm -rf -- \
      "${STATE_DIR}" \
      "${MANAGED_ROOT}" \
      "${DATABASE_BACKUP_DIR}" \
      "${INSTALL_BACKUP_ROOT}"
    rmdir \
      /var/backups/autostream/install-migrations \
      /var/backups/autostream \
      /var/lib/autostream \
      /opt/autostream \
      /etc/autostream \
      /etc/autostream-local-executor \
      /run/autostream-updater >/dev/null 2>&1
  fi
  if [[ ${created_mariadb_dump} == true ]]; then
    rm -f /usr/bin/mariadb-dump
  fi
  if [[ ${fixture_owns_paths} == true && ${created_autostream_user} == true ]]; then
    userdel autostream >/dev/null 2>&1
    groupdel autostream >/dev/null 2>&1
  fi
  rm -rf -- "${WORK_DIR}"
  if [[ ${cleanup_failed} == true && ${exit_code} -eq 0 ]]; then
    exit_code=1
  fi
  exit "${exit_code}"
}
trap cleanup EXIT

chmod 0755 "${WORK_DIR}"

for path in \
  "${UNIT_PATH}" \
  "${RUNTIME_UNIT_PATH}" \
  "${PUBLIC_BINARY}" \
  "${PUBLIC_ALIAS}" \
  "${ENV_PATH}" \
  "${STATE_DIR}" \
  "${MANAGED_ROOT}" \
  "${BACKUP_EXECUTABLE}" \
  "${DATABASE_BACKUP_DIR}" \
  "${INSTALL_BACKUP_ROOT}" \
  "${MARIADB_DEFAULTS}" \
  "${SHARED_HOST_SETUP_LOCK}" \
  "${TARGET_LOCK}"; do
  [[ ! -e ${path} && ! -L ${path} ]] || die "runner is not clean at ${path}"
done
loaded_unit_state="$(systemctl show --property LoadState --value "${UNIT}" 2>/dev/null || true)"
[[ ${loaded_unit_state} == "not-found" ]] || \
  die "runner service is already loaded: ${UNIT} (${loaded_unit_state:-unknown})"
if id autostream >/dev/null 2>&1 || getent group autostream >/dev/null 2>&1; then
  die "runner already has an autostream account"
fi

if [[ ! -e /usr/bin/mariadb-dump && ! -L /usr/bin/mariadb-dump ]]; then
  install -o root -g root -m 0755 /dev/null /usr/bin/mariadb-dump
  created_mariadb_dump=true
fi
[[ -f /usr/bin/mariadb-dump && ! -L /usr/bin/mariadb-dump && -x /usr/bin/mariadb-dump ]] || \
  die "runner has an unsafe /usr/bin/mariadb-dump"
if [[ ${AUTOSTREAM_OBSERVABILITY_INSTALLER_TEST_PREFLIGHT_PROBE:-} == "1" ]]; then
  die "preflight probe unexpectedly reached the mutation boundary"
fi
run_preflight_cleanup_probe
fixture_owns_paths=true
created_autostream_user=true

install -d -o root -g root -m 0755 \
  "${ARTIFACTS_DIR}" \
  "${EXTRACTED_ROOT}/bin" \
  "${EXTRACTED_ROOT}/backup" \
  "${EXTRACTED_ROOT}/systemd"
install -o root -g root -m 0755 "${INSTALLER_SOURCE}" \
  "${EXTRACTED_ROOT}/install-autostream-observability"

cat > "${EXTRACTED_ROOT}/bin/autostream-observability" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "--version" ]; then
  printf '%s\n' 'autostream-observability v9.9.9'
  printf '%s\n' 'commit: 0123456789abcdef0123456789abcdef01234567'
  printf '%s\n' 'build_date: 2026-07-31T00:00:00Z'
  exit 0
fi
exit 99
EOF
chmod 0755 "${EXTRACTED_ROOT}/bin/autostream-observability"
cp "${EXTRACTED_ROOT}/bin/autostream-observability" \
  "${EXTRACTED_ROOT}/bin/observability"
chmod 0755 "${EXTRACTED_ROOT}/bin/observability"

cat > "${EXTRACTED_ROOT}/backup/autostream-backup-observability" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 0755 "${EXTRACTED_ROOT}/backup/autostream-backup-observability"

cat > "${EXTRACTED_ROOT}/systemd/autostream-observability.service.example" <<'EOF'
[Unit]
Description=AutoStream Observability integration fixture

[Service]
Type=simple
User=autostream
Group=autostream
EnvironmentFile=-/etc/autostream/observability.env
ExecStart=/usr/local/bin/autostream-observability

[Install]
WantedBy=multi-user.target
EOF
printf '%s\n' 'OBSERVABILITY_BIND_ADDR=127.0.0.1:18082' \
  > "${EXTRACTED_ROOT}/.env.example"
printf '%s\n' 'integration fixture' > "${EXTRACTED_ROOT}/README.install.md"
jq -n \
  --arg version "${VERSION}" \
  --arg commit "${FIXTURE_COMMIT}" \
  --arg build_date "${FIXTURE_BUILD_DATE}" \
  --arg name "${ARTIFACT_ID}.tar.gz" \
  --arg root "${ARTIFACT_ID}" \
  '{
    schema_version: 1,
    component: "observability",
    source_version: $version,
    commit: $commit,
    build_date: $build_date,
    platform: {
      os: "linux",
      arch: "amd64"
    },
    archive: {
      name: $name,
      root: $root
    },
    compatibility: {
      minimum_agent_version: "v1.0.0",
      minimum_panel_version: null,
      rollback_compatible: true,
      database_schema: "backward_compatible"
    }
  }' > "${EXTRACTED_ROOT}/artifact-manifest.json"

(
  cd -- "${EXTRACTED_ROOT}"
  find . -type f ! -path './checksums.txt' -print0 |
    sort -z |
    xargs -0 sha256sum > checksums.txt
)
tar -C "${ARTIFACTS_DIR}" -czf "${ARCHIVE}" "${ARTIFACT_ID}"
archive_sha256="$(sha256sum "${ARCHIVE}" | awk 'NR == 1 { print $1 }')"
for external_metadata in \
  "${ARCHIVE}.sha256" \
  "${ARTIFACTS_DIR}/release-manifest.json" \
  "${ARTIFACTS_DIR}/release-manifest.json.sha256"; do
  [[ ! -e ${external_metadata} && ! -L ${external_metadata} ]] || \
    die "archive-only fixture unexpectedly created ${external_metadata}"
done

install -d -o root -g root -m 0755 "${BAD_ARTIFACTS_DIR}"
cp -a -- "${EXTRACTED_ROOT}" "${BAD_EXTRACTED_ROOT}"
tar \
  --transform='s#bin/observability#bin//observability#' \
  -C "${BAD_ARTIFACTS_DIR}" \
  -czf "${BAD_ARCHIVE}" \
  "${ARTIFACT_ID}"

set +e
"${BAD_EXTRACTED_ROOT}/install-autostream-observability" \
  > "${WORK_DIR}/noncanonical-archive.out" 2>&1
noncanonical_archive_status=$?
set -e
[[ ${noncanonical_archive_status} -ne 0 ]] || \
  die "noncanonical archive path unexpectedly succeeded"
grep -F -- "release archive contains a noncanonical path" \
  "${WORK_DIR}/noncanonical-archive.out" >/dev/null || \
  die "noncanonical archive path did not report the expected failure"
[[ ! -e ${MANAGED_ROOT} && ! -L ${MANAGED_ROOT} ]] || \
  die "noncanonical archive path mutated the managed root"
if id autostream >/dev/null 2>&1 || getent group autostream >/dev/null 2>&1; then
  die "noncanonical archive path created the autostream account"
fi

printf '%s\n' "not declared by checksums.txt" \
  > "${BAD_EXTRACTED_ROOT}/unlisted.txt"
tar -C "${BAD_ARTIFACTS_DIR}" -czf "${BAD_ARCHIVE}" "${ARTIFACT_ID}"

set +e
"${BAD_EXTRACTED_ROOT}/install-autostream-observability" \
  > "${WORK_DIR}/bad-checksum-inventory.out" 2>&1
bad_inventory_status=$?
set -e
[[ ${bad_inventory_status} -ne 0 ]] || \
  die "incomplete embedded checksum inventory unexpectedly succeeded"
grep -F -- "release archive checksum inventory is incomplete or unsafe" \
  "${WORK_DIR}/bad-checksum-inventory.out" >/dev/null || \
  die "incomplete embedded checksum inventory did not report the expected failure"
[[ ! -e ${MANAGED_ROOT} && ! -L ${MANAGED_ROOT} ]] || \
  die "incomplete embedded checksum inventory mutated the managed root"
if id autostream >/dev/null 2>&1 || getent group autostream >/dev/null 2>&1; then
  die "incomplete embedded checksum inventory created the autostream account"
fi
rm -f -- "${BAD_EXTRACTED_ROOT}/unlisted.txt"

jq '.component = "worker"' \
  "${BAD_EXTRACTED_ROOT}/artifact-manifest.json" \
  > "${BAD_EXTRACTED_ROOT}/artifact-manifest.json.next"
mv -T \
  "${BAD_EXTRACTED_ROOT}/artifact-manifest.json.next" \
  "${BAD_EXTRACTED_ROOT}/artifact-manifest.json"
(
  cd -- "${BAD_EXTRACTED_ROOT}"
  find . -type f ! -path './checksums.txt' -print0 |
    sort -z |
    xargs -0 sha256sum > checksums.txt
)
tar -C "${BAD_ARTIFACTS_DIR}" -czf "${BAD_ARCHIVE}" "${ARTIFACT_ID}"

set +e
"${BAD_EXTRACTED_ROOT}/install-autostream-observability" \
  > "${WORK_DIR}/bad-manifest.out" 2>&1
bad_manifest_status=$?
set -e
[[ ${bad_manifest_status} -ne 0 ]] || \
  die "mismatched embedded artifact manifest unexpectedly succeeded"
grep -F -- "release artifact manifest does not bind the expected Observability archive" \
  "${WORK_DIR}/bad-manifest.out" >/dev/null || \
  die "mismatched embedded artifact manifest did not report the expected failure"
[[ ! -e ${MANAGED_ROOT} && ! -L ${MANAGED_ROOT} ]] || \
  die "mismatched embedded artifact manifest mutated the managed root"
[[ ! -e ${TARGET_LOCK} && ! -L ${TARGET_LOCK} ]] || \
  die "mismatched embedded artifact manifest created the updater lock"
[[ ! -e ${SHARED_HOST_SETUP_LOCK} && ! -L ${SHARED_HOST_SETUP_LOCK} ]] || \
  die "mismatched embedded artifact manifest created the shared host-setup lock"
if id autostream >/dev/null 2>&1 || getent group autostream >/dev/null 2>&1; then
  die "mismatched embedded artifact manifest created the autostream account"
fi

install -o root -g root -m 0755 /usr/bin/systemctl "${REAL_SYSTEMCTL_COPY}"
cat > "${FAIL_SYSTEMCTL}" <<EOF
#!/bin/bash
printf '%s\n' "\$*" >> "${SYSTEMCTL_CALL_LOG}"
if [[ \$# -eq 1 && \$1 == "daemon-reload" ]]; then
  exit 97
fi
exec "${REAL_SYSTEMCTL_COPY}" "\$@"
EOF
chmod 0755 "${FAIL_SYSTEMCTL}"

cat > "${TERM_SYSTEMCTL}" <<EOF
#!/bin/bash
if [[ \$# -eq 1 && \$1 == "daemon-reload" ]]; then
  call_count=0
  if [[ -f "${TERM_SYSTEMCTL_CALL_COUNT}" ]]; then
    call_count=\$(<"${TERM_SYSTEMCTL_CALL_COUNT}")
  fi
  call_count=\$((call_count + 1))
  printf '%s\n' "\${call_count}" > "${TERM_SYSTEMCTL_CALL_COUNT}"
  if [[ \${call_count} -eq 1 ]]; then
    kill -TERM "\${PPID}"
    exit 0
  fi
  if [[ \${call_count} -eq 2 ]]; then
    printf '%s\n' delivered > "${CLEANUP_SECOND_TERM_MARKER}"
    kill -TERM "\${PPID}"
  fi
fi
exec "${REAL_SYSTEMCTL_COPY}" "\$@"
EOF
chmod 0755 "${TERM_SYSTEMCTL}"

install -o root -g root -m 0755 "$(command -v groupadd)" "${REAL_GROUPADD_COPY}"
cat > "${TERM_GROUPADD}" <<EOF
#!/bin/bash
"${REAL_GROUPADD_COPY}" "\$@"
printf '%s\n' delivered > "${GROUPADD_TERM_MARKER}"
kill -TERM "\${PPID}"
exit 0
EOF
chmod 0755 "${TERM_GROUPADD}"

install -o root -g root -m 0755 "$(command -v useradd)" "${REAL_USERADD_COPY}"
cat > "${TERM_USERADD}" <<EOF
#!/bin/bash
"${REAL_USERADD_COPY}" "\$@"
printf '%s\n' delivered > "${USERADD_TERM_MARKER}"
kill -TERM "\${PPID}"
exit 0
EOF
chmod 0755 "${TERM_USERADD}"

cat > "${JOURNAL_TERM_BASH_ENV}" <<EOF
set -T
autostream_observability_inject_journal_term() {
  local command=\$1
  case "\${AUTOSTREAM_OBSERVABILITY_INSTALLER_TEST_JOURNAL_TERM_TARGET:-}" in
    field)
      if [[ \${command} == directory_journaled*'=true' ]]; then
        trap - DEBUG
        printf '%s\n' delivered > "${JOURNAL_FIELD_TERM_MARKER}"
        kill -TERM "\$\$"
      fi
      ;;
    order)
      if [[ \${command} == journaled_directory_paths*'+='* ]]; then
        trap - DEBUG
        printf '%s\n' delivered > "${JOURNAL_ORDER_TERM_MARKER}"
        kill -TERM "\$\$"
      fi
      ;;
  esac
}
trap 'autostream_observability_inject_journal_term "\$BASH_COMMAND"' DEBUG
EOF
chmod 0600 "${JOURNAL_TERM_BASH_ENV}"

install -o root -g root -m 0755 /usr/bin/mktemp "${REAL_MKTEMP_COPY}"
cat > "${FAIL_MKTEMP}" <<EOF
#!/bin/bash
printf '%s\n' "\$*" >> "${MKTEMP_CALL_LOG}"
if [[ \$# -eq 2 &&
  \$1 == "-d" &&
  \$2 == "/opt/autostream/observability/.install.XXXXXX" ]]; then
  exit 96
fi
exec "${REAL_MKTEMP_COPY}" "\$@"
EOF
chmod 0755 "${FAIL_MKTEMP}"

install -o root -g root -m 0755 /usr/bin/sync "${REAL_SYNC_COPY}"
cat > "${FAIL_SYNC}" <<EOF
#!/bin/bash
printf '%s\n' "\$*" >> "${SYNC_CALL_LOG}"
if [[ \$# -eq 3 &&
  \$1 == "-f" &&
  \$2 == "--" &&
  \$3 == "/" &&
  ! -e "${SYNC_FAILURE_MARKER}" ]]; then
  printf '%s\n' failed > "${SYNC_FAILURE_MARKER}"
  exit 95
fi
exec "${REAL_SYNC_COPY}" "\$@"
EOF
chmod 0755 "${FAIL_SYNC}"

set +e
unshare --mount --propagation private bash -c \
  "mount --bind /dev/null /usr/bin/mariadb-dump && printf '%s\n' mounted > '${MARIADB_MOUNT_MARKER}' && '${EXTRACTED_ROOT}/install-autostream-observability'" \
  > "${WORK_DIR}/missing-mariadb-dump.out" 2>&1
missing_dump_status=$?
set -e
[[ ${missing_dump_status} -ne 0 ]] || die "unsafe mariadb-dump preflight unexpectedly succeeded"
grep -Fx -- "mounted" "${MARIADB_MOUNT_MARKER}" >/dev/null || \
  die "mariadb-dump failure injection did not mount the unsafe executable"
grep -F -- "must be a regular non-symlink executable" \
  "${WORK_DIR}/missing-mariadb-dump.out" >/dev/null || \
  die "unsafe mariadb-dump preflight did not report the expected failure"
[[ ! -e ${MANAGED_ROOT} && ! -L ${MANAGED_ROOT} ]] || \
  die "mariadb-dump preflight failure mutated the managed root"

set +e
unshare --mount --propagation private bash -c \
  "mount --bind '${FAIL_MKTEMP}' /usr/bin/mktemp && printf '%s\n' mounted > '${MKTEMP_MOUNT_MARKER}' && '${EXTRACTED_ROOT}/install-autostream-observability'" \
  > "${WORK_DIR}/mktemp-failure.out" 2>&1
mktemp_failure_status=$?
set -e
[[ ${mktemp_failure_status} -ne 0 ]] || die "mktemp failure injection unexpectedly succeeded"
grep -Fx -- "mounted" "${MKTEMP_MOUNT_MARKER}" >/dev/null || \
  die "mktemp failure injection did not mount the wrapper"
if [[ ! -f ${MKTEMP_CALL_LOG} || -L ${MKTEMP_CALL_LOG} ]]; then
  printf '%s\n' "mktemp failure injection exited before the production mktemp call:" >&2
  cat "${WORK_DIR}/mktemp-failure.out" >&2
  die "mktemp failure injection did not reach the staging call"
fi
if [[ $(wc -l < "${MKTEMP_CALL_LOG}") -ne 4 ]]; then
  printf '%s\n' "observed production mktemp calls:" >&2
  cat "${MKTEMP_CALL_LOG}" >&2
  printf '%s\n' "installer output before the mktemp assertion:" >&2
  cat "${WORK_DIR}/mktemp-failure.out" >&2
  die "mktemp failure injection did not reach archive, shared lock, target lock, and managed staging calls"
fi
if [[ $(head -n 1 "${MKTEMP_CALL_LOG}") != \
  "-d /var/tmp/autostream-observability-install.XXXXXXXX" ]]; then
  cat "${MKTEMP_CALL_LOG}" >&2
  die "mktemp failure injection did not begin with archive preflight staging"
fi
if [[ $(sed -n '2p' "${MKTEMP_CALL_LOG}") != \
  "/run/autostream-updater/.host-lock-create.XXXXXX" ]]; then
  cat "${MKTEMP_CALL_LOG}" >&2
  die "mktemp failure injection did not atomically stage the shared host-setup lock"
fi
if [[ $(sed -n '3p' "${MKTEMP_CALL_LOG}") != \
  "/run/autostream-updater/.lock-create.XXXXXX" ]]; then
  cat "${MKTEMP_CALL_LOG}" >&2
  die "mktemp failure injection did not atomically stage the permanent lock"
fi
if [[ $(tail -n 1 "${MKTEMP_CALL_LOG}") != \
  "-d /opt/autostream/observability/.install.XXXXXX" ]]; then
  cat "${MKTEMP_CALL_LOG}" >&2
  die "mktemp failure injection did not reach the managed staging call"
fi
grep -F -- "failed to create installer staging directory" \
  "${WORK_DIR}/mktemp-failure.out" >/dev/null || \
  die "mktemp failure was masked by the readonly assignment"
[[ ! -e ${MANAGED_ROOT}/current && ! -L ${MANAGED_ROOT}/current ]] || \
  die "mktemp failure activated current"
[[ ! -e ${PUBLIC_BINARY} && ! -L ${PUBLIC_BINARY} ]] || \
  die "mktemp failure installed the public binary"
[[ ! -e ${UNIT_PATH} && ! -L ${UNIT_PATH} ]] || \
  die "mktemp failure installed the systemd unit"
[[ ! -e ${ENV_PATH} && ! -L ${ENV_PATH} ]] || \
  die "mktemp failure installed the environment"
[[ -f ${TARGET_LOCK} && ! -L ${TARGET_LOCK} &&
  $(stat -c '%U:%G:%a' -- "${TARGET_LOCK}") == "root:root:600" ]] || \
  die "mktemp failure did not retain the permanent safe updater lock"
[[ -f ${SHARED_HOST_SETUP_LOCK} && ! -L ${SHARED_HOST_SETUP_LOCK} &&
  $(stat -c '%U:%G:%a' -- "${SHARED_HOST_SETUP_LOCK}") == "root:root:600" ]] || \
  die "mktemp failure did not retain the permanent safe shared host-setup lock"
lock_identity_after_rollback="$(stat -c '%d:%i' -- "${TARGET_LOCK}")"
shared_lock_identity_after_rollback="$(stat -c '%d:%i' -- "${SHARED_HOST_SETUP_LOCK}")"
for path in \
  "${STATE_DIR}" \
  "${MANAGED_ROOT}" \
  "${DATABASE_BACKUP_DIR}" \
  "${INSTALL_BACKUP_ROOT}" \
  /var/backups/autostream/install-migrations \
  /var/backups/autostream \
  /var/lib/autostream \
  /opt/autostream \
  /etc/autostream \
  /etc/autostream-local-executor; do
  [[ ! -e ${path} && ! -L ${path} ]] || \
    die "mktemp failure left installer-created residue: ${path}"
done
if id autostream >/dev/null 2>&1 || getent group autostream >/dev/null 2>&1; then
  die "mktemp failure retained the installer-created autostream account"
fi

assert_signal_setup_paths_rolled_back() {
  local label=$1
  local unexpected_path

  for unexpected_path in \
    "${STATE_DIR}" \
    "${MANAGED_ROOT}" \
    "${DATABASE_BACKUP_DIR}" \
    "${INSTALL_BACKUP_ROOT}" \
    /var/backups/autostream/install-migrations \
    /var/backups/autostream \
    /var/lib/autostream \
    /opt/autostream \
    /etc/autostream \
    /etc/autostream-local-executor; do
    [[ ! -e ${unexpected_path} && ! -L ${unexpected_path} ]] || \
      die "${label} left installer-created residue: ${unexpected_path}"
  done
  [[ $(stat -c '%d:%i' -- "${TARGET_LOCK}") == "${lock_identity_after_rollback}" ]] || \
    die "${label} replaced the permanent updater lock inode"
  [[ $(stat -c '%d:%i' -- "${SHARED_HOST_SETUP_LOCK}") == \
    "${shared_lock_identity_after_rollback}" ]] || \
    die "${label} replaced the permanent shared host-setup lock inode"
}

opt_metadata_before_journal_term="$(stat -c '%d:%i:%u:%g:%a:%Y:%Z' -- /opt)"
for journal_term_target in field order; do
  if [[ ${journal_term_target} == "field" ]]; then
    journal_term_marker="${JOURNAL_FIELD_TERM_MARKER}"
  else
    journal_term_marker="${JOURNAL_ORDER_TERM_MARKER}"
  fi
  rm -f -- "${journal_term_marker}"
  set +e
  BASH_ENV="${JOURNAL_TERM_BASH_ENV}" \
    AUTOSTREAM_OBSERVABILITY_INSTALLER_TEST_JOURNAL_TERM_TARGET="${journal_term_target}" \
    "${EXTRACTED_ROOT}/install-autostream-observability" \
    > "${WORK_DIR}/journal-${journal_term_target}-term.out" 2>&1
  journal_term_status=$?
  set -e
  [[ ${journal_term_status} -eq 143 ]] || \
    die "journal ${journal_term_target} TERM exited with ${journal_term_status}, expected 143"
  grep -Fx -- "delivered" "${journal_term_marker}" >/dev/null || \
    die "journal-${journal_term_target}-term-delivered marker is missing"
  if grep -F -- "unbound variable" \
    "${WORK_DIR}/journal-${journal_term_target}-term.out" >/dev/null; then
    die "journal ${journal_term_target} TERM aborted cleanup through set -u"
  fi
  [[ $(stat -c '%d:%i:%u:%g:%a:%Y:%Z' -- /opt) == \
    "${opt_metadata_before_journal_term}" ]] || \
    die "journal ${journal_term_target} TERM changed the pre-existing /opt directory"
  if id autostream >/dev/null 2>&1 || getent group autostream >/dev/null 2>&1; then
    die "journal ${journal_term_target} TERM retained an autostream account"
  fi
  assert_signal_setup_paths_rolled_back "journal ${journal_term_target} TERM"
done

set +e
unshare --mount --propagation private bash -c \
  "mount --bind '${TERM_GROUPADD}' '$(command -v groupadd)' && '${EXTRACTED_ROOT}/install-autostream-observability'" \
  > "${WORK_DIR}/groupadd-term.out" 2>&1
groupadd_term_status=$?
set -e
[[ ${groupadd_term_status} -eq 143 ]] || \
  die "groupadd TERM transaction exited with ${groupadd_term_status}, expected 143"
grep -Fx -- "delivered" "${GROUPADD_TERM_MARKER}" >/dev/null || \
  die "groupadd-term-delivered marker is missing"
if id autostream >/dev/null 2>&1 || getent group autostream >/dev/null 2>&1; then
  die "groupadd TERM transaction retained the installer-created autostream account"
fi
assert_signal_setup_paths_rolled_back "groupadd TERM transaction"

groupadd --system autostream
preexisting_group_record="$(getent group autostream)"
set +e
unshare --mount --propagation private bash -c \
  "mount --bind '${TERM_USERADD}' '$(command -v useradd)' && '${EXTRACTED_ROOT}/install-autostream-observability'" \
  > "${WORK_DIR}/useradd-term.out" 2>&1
useradd_term_status=$?
set -e
[[ ${useradd_term_status} -eq 143 ]] || \
  die "useradd TERM transaction exited with ${useradd_term_status}, expected 143"
grep -Fx -- "delivered" "${USERADD_TERM_MARKER}" >/dev/null || \
  die "useradd-term-delivered marker is missing"
id autostream >/dev/null 2>&1 && \
  die "useradd TERM transaction retained the installer-created autostream user"
[[ $(getent group autostream) == "${preexisting_group_record}" ]] || \
  die "useradd TERM transaction changed the pre-existing autostream group"
assert_signal_setup_paths_rolled_back "useradd TERM transaction"
groupdel autostream

"${EXTRACTED_ROOT}/install-autostream-observability" > "${WORK_DIR}/fresh.out"
[[ $(stat -c '%d:%i' -- "${TARGET_LOCK}") == "${lock_identity_after_rollback}" ]] || \
  die "fresh install replaced the permanent updater lock inode"
[[ $(stat -c '%d:%i' -- "${SHARED_HOST_SETUP_LOCK}") == \
  "${shared_lock_identity_after_rollback}" ]] || \
  die "fresh install replaced the permanent shared host-setup lock inode"
[[ -L ${MANAGED_ROOT}/current ]] || die "fresh install did not create the managed current link"
[[ -L ${PUBLIC_BINARY} && -L ${PUBLIC_ALIAS} ]] || \
  die "fresh install did not install stable public links"
[[ -f ${ENV_PATH} && ! -L ${ENV_PATH} ]] || die "fresh install did not seed the environment"
[[ -f ${MARIADB_DEFAULTS} && ! -L ${MARIADB_DEFAULTS} ]] || \
  die "fresh install did not seed the MariaDB defaults"
[[ $(stat -c '%U:%G:%a' -- "${ENV_PATH}") == "root:root:640" ]] || \
  die "fresh environment ownership or mode is invalid"
[[ $(stat -c '%U:%G:%a' -- "${MARIADB_DEFAULTS}") == "root:root:600" ]] || \
  die "fresh MariaDB defaults ownership or mode is invalid"
[[ $(stat -c '%U:%G:%a' -- "${STATE_DIR}") == "autostream:autostream:750" ]] || \
  die "fresh state ownership or mode is invalid"
id autostream >/dev/null 2>&1 || die "fresh installer did not create the autostream account"
systemctl is-active --quiet "${UNIT}" && die "fresh installer unexpectedly started the service"
systemctl is-enabled --quiet "${UNIT}" && die "fresh installer unexpectedly enabled the service"
grep -F -- "sudo systemctl enable --now autostream-observability" \
  "${WORK_DIR}/fresh.out" >/dev/null || \
  die "fresh install did not print the explicit start command"

rm -f -- \
  "${PUBLIC_BINARY}" \
  "${PUBLIC_ALIAS}" \
  "${ENV_PATH}" \
  "${UNIT_PATH}" \
  "${BACKUP_EXECUTABLE}" \
  "${MARIADB_DEFAULTS}" \
  "${SHARED_HOST_SETUP_LOCK}" \
  "${TARGET_LOCK}"
rm -rf -- \
  "${STATE_DIR}" \
  "${MANAGED_ROOT}" \
  "${DATABASE_BACKUP_DIR}" \
  "${INSTALL_BACKUP_ROOT}"
systemctl daemon-reload
rmdir \
  /var/backups/autostream/install-migrations \
  /var/backups/autostream \
  /var/lib/autostream \
  /opt/autostream \
  /etc/autostream \
  /etc/autostream-local-executor \
  /run/autostream-updater >/dev/null 2>&1 || \
  die "fresh-install reset left an unexpected directory"
userdel autostream
if getent group autostream >/dev/null 2>&1; then
  groupdel autostream
fi
[[ ! -e ${MANAGED_ROOT} && ! -L ${MANAGED_ROOT} ]] || \
  die "fresh-install reset retained the managed root"
if id autostream >/dev/null 2>&1 || getent group autostream >/dev/null 2>&1; then
  die "fresh-install reset retained the autostream account"
fi

install -d -o root -g root -m 0750 /etc/autostream
printf '%s\n' "invalid preflight mode before account creation" > "${ENV_PATH}"
chmod 0600 "${ENV_PATH}"
set +e
"${EXTRACTED_ROOT}/install-autostream-observability" \
  > "${WORK_DIR}/fresh-late-preflight-failure.out" 2>&1
fresh_late_preflight_status=$?
set -e
[[ ${fresh_late_preflight_status} -ne 0 ]] || \
  die "fresh late preflight failure unexpectedly succeeded"
grep -F -- "${ENV_PATH} owner or mode is invalid" \
  "${WORK_DIR}/fresh-late-preflight-failure.out" >/dev/null || \
  die "fresh late preflight failure did not reach existing environment validation"
if id autostream >/dev/null 2>&1 || getent group autostream >/dev/null 2>&1; then
  die "fresh late preflight failure created the autostream account"
fi
for unexpected_path in \
  /opt/autostream \
  "${MANAGED_ROOT}" \
  /var/lib/autostream \
  "${STATE_DIR}" \
  /var/backups/autostream \
  "${DATABASE_BACKUP_DIR}" \
  "${INSTALL_BACKUP_ROOT}" \
  /etc/autostream-local-executor \
  "${MARIADB_DEFAULTS}" \
  "${SHARED_HOST_SETUP_LOCK}" \
  "${TARGET_LOCK}" \
  /run/autostream-updater; do
  [[ ! -e ${unexpected_path} && ! -L ${unexpected_path} ]] || \
    die "fresh late preflight failure created ${unexpected_path}"
done
rm -f -- "${ENV_PATH}"

groupadd --system autostream
useradd --system --gid autostream --home-dir /var/lib/autostream \
  --no-create-home --shell /usr/sbin/nologin autostream
install -d -o root -g root -m 0755 /etc/autostream /var/lib/autostream
install -d -o autostream -g autostream -m 0700 "${STATE_DIR}"
printf '%s\n' "preserve state exactly across a later preflight failure" > "${STATE_SENTINEL}"
chown autostream:autostream "${STATE_SENTINEL}"
chmod 0600 "${STATE_SENTINEL}"
state_identity_before="$(stat -c '%d:%i' -- "${STATE_DIR}")"
state_metadata_before="$(stat -c '%u:%g:%a' -- "${STATE_DIR}")"
state_sentinel_before="$(sha256sum "${STATE_SENTINEL}" | awk 'NR == 1 { print $1 }')"
printf '%s\n' "invalid preflight mode" > "${ENV_PATH}"
chmod 0600 "${ENV_PATH}"

set +e
"${EXTRACTED_ROOT}/install-autostream-observability" \
  > "${WORK_DIR}/state-preflight-failure.out" 2>&1
state_preflight_status=$?
set -e
[[ ${state_preflight_status} -ne 0 ]] || \
  die "late preflight failure with existing state unexpectedly succeeded"
grep -F -- "${ENV_PATH} owner or mode is invalid" \
  "${WORK_DIR}/state-preflight-failure.out" >/dev/null || \
  die "late preflight failure did not reach existing environment validation"
assert_state_preserved "late preflight failure"

printf '%s\n' "${LEGACY_BINARY_CONTENT}" > "${PUBLIC_BINARY}"
chmod 0755 "${PUBLIC_BINARY}"
printf '%s\n' "${LEGACY_ALIAS_CONTENT}" > "${PUBLIC_ALIAS}"
chmod 0755 "${PUBLIC_ALIAS}"
printf '%s\n' "${LEGACY_ENV_CONTENT}" > "${ENV_PATH}"
chmod 0640 "${ENV_PATH}"
printf '%s\n' "${LEGACY_HELPER_CONTENT}" > "${BACKUP_EXECUTABLE}"
chmod 0700 "${BACKUP_EXECUTABLE}"
install -d -o root -g root -m 0700 /etc/autostream-local-executor
printf '%s\n' "${LEGACY_DB_CONTENT}" > "${MARIADB_DEFAULTS}"
chmod 0600 "${MARIADB_DEFAULTS}"
cat > "${UNIT_PATH}" <<EOF
[Unit]
Description=${LEGACY_UNIT_CONTENT}

[Service]
Type=simple
ExecStart=/usr/bin/sleep infinity

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "${UNIT_PATH}"
create_runtime_unit_no_clobber "${UNIT_PATH}"
systemctl daemon-reload
fixture_owns_service=true
systemctl start "${UNIT}"
old_pid="$(systemctl show --property MainPID --value "${UNIT}")"
[[ ${old_pid} =~ ^[1-9][0-9]*$ ]] || die "legacy service did not start"
if ! old_pid_starttime="$(read_process_starttime "${old_pid}")"; then
  die "could not record the legacy service process identity"
fi
kill -0 "${old_pid}" || die "legacy service PID is not alive"
assert_loaded_runtime_unit "/usr/bin/sleep" "" "legacy startup"
legacy_unit_file_state="$(systemctl is-enabled "${UNIT}" 2>/dev/null || true)"
[[ ${legacy_unit_file_state} == "disabled" ]] || \
  die "legacy fixture must begin disabled, got ${legacy_unit_file_state:-unknown}"

env_before="$(sha256sum "${ENV_PATH}" | awk 'NR == 1 { print $1 }')"
db_before="$(sha256sum "${MARIADB_DEFAULTS}" | awk 'NR == 1 { print $1 }')"
unit_before="$(sha256sum "${UNIT_PATH}" | awk 'NR == 1 { print $1 }')"
runtime_unit_before="$(sha256sum "${RUNTIME_UNIT_PATH}" | awk 'NR == 1 { print $1 }')"
helper_before="$(sha256sum "${BACKUP_EXECUTABLE}" | awk 'NR == 1 { print $1 }')"
readonly RETAINED_DIR="${INSTALL_BACKUP_ROOT}/${VERSION}-${archive_sha256:0:12}"

rm -f -- "${TERM_SYSTEMCTL_CALL_COUNT}" "${CLEANUP_SECOND_TERM_MARKER}"
set +e
unshare --mount --propagation private bash -c \
  "mount --bind '${TERM_SYSTEMCTL}' /usr/bin/systemctl && '${EXTRACTED_ROOT}/install-autostream-observability'" \
  > "${WORK_DIR}/signal-rollback.out" 2>&1
signal_rollback_status=$?
set -e
[[ ${signal_rollback_status} -eq 143 ]] || \
  die "signal rollback exited with ${signal_rollback_status}, expected 143"
[[ $(<"${TERM_SYSTEMCTL_CALL_COUNT}") == "2" ]] || \
  die "signal rollback did not reach install and cleanup daemon-reload calls"
grep -Fx -- "delivered" "${CLEANUP_SECOND_TERM_MARKER}" >/dev/null || \
  die "cleanup-second-term-delivered marker is missing"
[[ $(<"${PUBLIC_BINARY}") == "${LEGACY_BINARY_CONTENT}" ]] || \
  die "signal rollback did not restore the legacy binary"
[[ $(<"${PUBLIC_ALIAS}") == "${LEGACY_ALIAS_CONTENT}" ]] || \
  die "signal rollback did not restore the legacy alias"
[[ $(sha256sum "${ENV_PATH}" | awk 'NR == 1 { print $1 }') == "${env_before}" ]] || \
  die "signal rollback changed the environment"
[[ $(sha256sum "${MARIADB_DEFAULTS}" | awk 'NR == 1 { print $1 }') == "${db_before}" ]] || \
  die "signal rollback changed the MariaDB defaults"
[[ $(sha256sum "${UNIT_PATH}" | awk 'NR == 1 { print $1 }') == "${unit_before}" ]] || \
  die "signal rollback did not restore the systemd unit"
[[ $(sha256sum "${BACKUP_EXECUTABLE}" | awk 'NR == 1 { print $1 }') == "${helper_before}" ]] || \
  die "signal rollback did not restore the backup executable"
[[ $(systemctl show --property MainPID --value "${UNIT}") == "${old_pid}" ]] || \
  die "signal rollback replaced the running legacy process"
kill -0 "${old_pid}" || die "signal rollback stopped the running legacy process"
assert_legacy_runtime_unit "signal rollback"
systemctl is-enabled --quiet "${UNIT}" && \
  die "signal rollback unexpectedly enabled the service"
assert_state_preserved "signal rollback"

set +e
unshare --mount --propagation private bash -c \
  "mount --bind '${FAIL_SYSTEMCTL}' /usr/bin/systemctl && printf '%s\n' mounted > '${SYSTEMCTL_MOUNT_MARKER}' && '${EXTRACTED_ROOT}/install-autostream-observability'" \
  > "${WORK_DIR}/failed-install.out" 2>&1
failed_status=$?
set -e
[[ ${failed_status} -ne 0 ]] || die "daemon-reload failure injection unexpectedly succeeded"
grep -Fx -- "mounted" "${SYSTEMCTL_MOUNT_MARKER}" >/dev/null || \
  die "daemon-reload failure injection did not mount the systemctl wrapper"
grep -Fx -- "daemon-reload" "${SYSTEMCTL_CALL_LOG}" >/dev/null || \
  die "daemon-reload failure injection did not reach the commit boundary"
[[ ! -e ${MANAGED_ROOT}/current && ! -L ${MANAGED_ROOT}/current ]] || \
  die "failed migration left current activated"
[[ -f ${PUBLIC_BINARY} && ! -L ${PUBLIC_BINARY} ]] || \
  die "failed migration did not restore the legacy binary"
[[ -f ${PUBLIC_ALIAS} && ! -L ${PUBLIC_ALIAS} ]] || \
  die "failed migration did not restore the legacy alias"
grep -Fx -- "${LEGACY_BINARY_CONTENT}" "${PUBLIC_BINARY}" >/dev/null || \
  die "failed migration changed the legacy binary"
grep -Fx -- "${LEGACY_ALIAS_CONTENT}" "${PUBLIC_ALIAS}" >/dev/null || \
  die "failed migration changed the legacy alias"
[[ $(sha256sum "${ENV_PATH}" | awk 'NR == 1 { print $1 }') == "${env_before}" ]] || \
  die "failed migration changed the existing environment"
[[ $(sha256sum "${MARIADB_DEFAULTS}" | awk 'NR == 1 { print $1 }') == "${db_before}" ]] || \
  die "failed migration changed the existing MariaDB defaults"
[[ $(sha256sum "${UNIT_PATH}" | awk 'NR == 1 { print $1 }') == "${unit_before}" ]] || \
  die "failed migration did not restore the systemd unit"
[[ $(sha256sum "${BACKUP_EXECUTABLE}" | awk 'NR == 1 { print $1 }') == "${helper_before}" ]] || \
  die "failed migration did not restore the backup executable"
[[ $(systemctl show --property MainPID --value "${UNIT}") == "${old_pid}" ]] || \
  die "failed migration replaced the running legacy process"
kill -0 "${old_pid}" || die "failed migration stopped the running legacy process"
assert_legacy_runtime_unit "failed migration"
systemctl is-enabled --quiet "${UNIT}" && die "failed migration unexpectedly enabled the service"
assert_state_preserved "daemon-reload failure"
grep -Fx -- "${LEGACY_BINARY_CONTENT}" \
  "${RETAINED_DIR}/usr-local-bin-autostream-observability.pre-managed" >/dev/null || \
  die "failed migration did not durably retain the legacy binary before activation"
grep -Fx -- "${LEGACY_ALIAS_CONTENT}" \
  "${RETAINED_DIR}/usr-local-bin-observability.pre-managed" >/dev/null || \
  die "failed migration did not durably retain the legacy alias before activation"
grep -F -- "${LEGACY_UNIT_CONTENT}" \
  "${RETAINED_DIR}/etc-systemd-system-autostream-observability.service.pre-managed" >/dev/null || \
  die "failed migration did not durably retain the legacy systemd unit before activation"
grep -Fx -- "${LEGACY_HELPER_CONTENT}" \
  "${RETAINED_DIR}/usr-local-sbin-autostream-backup-observability.pre-managed" >/dev/null || \
  die "failed migration did not durably retain the legacy backup executable before activation"
declare -A retained_identity_before_retry=()
declare -A retained_digest_before_retry=()
for retained_file in \
  "${RETAINED_DIR}/usr-local-bin-autostream-observability.pre-managed" \
  "${RETAINED_DIR}/usr-local-bin-observability.pre-managed" \
  "${RETAINED_DIR}/etc-systemd-system-autostream-observability.service.pre-managed" \
  "${RETAINED_DIR}/usr-local-sbin-autostream-backup-observability.pre-managed"; do
  retained_identity_before_retry["${retained_file}"]="$(stat -c '%d:%i:%s:%Y:%Z:%f:%u:%g:%a' -- "${retained_file}")"
  retained_digest_before_retry["${retained_file}"]="$(sha256sum -- "${retained_file}" | awk 'NR == 1 { print $1 }')"
done

set +e
unshare --mount --propagation private bash -c \
  "mount --bind '${FAIL_SYNC}' /usr/bin/sync && printf '%s\n' mounted > '${SYNC_MOUNT_MARKER}' && '${EXTRACTED_ROOT}/install-autostream-observability'" \
  > "${WORK_DIR}/sync-failure.out" 2>&1
sync_failure_status=$?
set -e
[[ ${sync_failure_status} -ne 0 ]] || die "sync failure injection unexpectedly succeeded"
grep -Fx -- "mounted" "${SYNC_MOUNT_MARKER}" >/dev/null || \
  die "sync failure injection did not mount the wrapper"
grep -Fx -- "failed" "${SYNC_FAILURE_MARKER}" >/dev/null || \
  die "sync failure injection did not reach the final durability boundary"
grep -Fx -- "-f -- /" "${SYNC_CALL_LOG}" >/dev/null || \
  die "sync failure injection did not exercise the root filesystem parent"
grep -F -- "failed to synchronize installed filesystem state" \
  "${WORK_DIR}/sync-failure.out" >/dev/null || \
  die "sync failure did not report the expected durability error"
[[ ! -e ${MANAGED_ROOT}/current && ! -L ${MANAGED_ROOT}/current ]] || \
  die "sync failure left current activated"
grep -Fx -- "${LEGACY_BINARY_CONTENT}" "${PUBLIC_BINARY}" >/dev/null || \
  die "sync failure did not restore the legacy binary"
grep -Fx -- "${LEGACY_ALIAS_CONTENT}" "${PUBLIC_ALIAS}" >/dev/null || \
  die "sync failure did not restore the legacy alias"
[[ $(sha256sum "${UNIT_PATH}" | awk 'NR == 1 { print $1 }') == "${unit_before}" ]] || \
  die "sync failure did not restore the systemd unit"
[[ $(sha256sum "${BACKUP_EXECUTABLE}" | awk 'NR == 1 { print $1 }') == "${helper_before}" ]] || \
  die "sync failure did not restore the backup executable"
[[ $(systemctl show --property MainPID --value "${UNIT}") == "${old_pid}" ]] || \
  die "sync failure replaced the running legacy process"
kill -0 "${old_pid}" || die "sync failure stopped the running legacy process"
assert_legacy_runtime_unit "sync failure"
assert_state_preserved "sync failure"
for retained_file in "${!retained_identity_before_retry[@]}"; do
  [[ $(stat -c '%d:%i:%s:%Y:%Z:%f:%u:%g:%a' -- "${retained_file}") == \
    "${retained_identity_before_retry["${retained_file}"]}" ]] || \
    die "sync failure changed pre-existing retained backup identity or metadata: ${retained_file}"
  [[ $(sha256sum -- "${retained_file}" | awk 'NR == 1 { print $1 }') == \
    "${retained_digest_before_retry["${retained_file}"]}" ]] || \
    die "sync failure changed pre-existing retained backup content: ${retained_file}"
done

"${EXTRACTED_ROOT}/install-autostream-observability" > "${WORK_DIR}/migration.out"
replace_owned_runtime_unit_atomically "${UNIT_PATH}"
systemctl daemon-reload
assert_loaded_runtime_unit "${PUBLIC_BINARY}" "autostream" "successful migration"
[[ $(sha256sum "${RUNTIME_UNIT_PATH}" | awk 'NR == 1 { print $1 }') == \
  "$(sha256sum "${UNIT_PATH}" | awk 'NR == 1 { print $1 }')" ]] || \
  die "successful migration did not synchronize the managed runtime unit"
[[ -L ${MANAGED_ROOT}/current ]] || die "successful migration did not activate current"
[[ -L ${PUBLIC_BINARY} && -L ${PUBLIC_ALIAS} ]] || \
  die "successful migration did not install stable public links"
[[ $(readlink -f -- "${PUBLIC_BINARY}") == \
  "${MANAGED_ROOT}/releases/${VERSION}-${archive_sha256:0:12}/bin/autostream-observability" ]] || \
  die "public binary does not resolve to the verified release"
[[ $(sha256sum "${ENV_PATH}" | awk 'NR == 1 { print $1 }') == "${env_before}" ]] || \
  die "successful migration changed the existing environment"
[[ $(sha256sum "${MARIADB_DEFAULTS}" | awk 'NR == 1 { print $1 }') == "${db_before}" ]] || \
  die "successful migration changed the existing MariaDB defaults"
grep -Fx -- "${LEGACY_BINARY_CONTENT}" \
  "${RETAINED_DIR}/usr-local-bin-autostream-observability.pre-managed" >/dev/null || \
  die "successful migration did not retain the legacy binary"
grep -Fx -- "${LEGACY_ALIAS_CONTENT}" \
  "${RETAINED_DIR}/usr-local-bin-observability.pre-managed" >/dev/null || \
  die "successful migration did not retain the legacy alias"
grep -F -- "${LEGACY_UNIT_CONTENT}" \
  "${RETAINED_DIR}/etc-systemd-system-autostream-observability.service.pre-managed" >/dev/null || \
  die "successful migration did not retain the legacy systemd unit"
grep -Fx -- "${LEGACY_HELPER_CONTENT}" \
  "${RETAINED_DIR}/usr-local-sbin-autostream-backup-observability.pre-managed" >/dev/null || \
  die "successful migration did not retain the legacy backup executable"
[[ $(stat -c '%U:%G:%a' -- "${STATE_DIR}") == "autostream:autostream:750" ]] || \
  die "successful migration changed the service state ownership contract"
[[ $(sha256sum "${STATE_SENTINEL}" | awk 'NR == 1 { print $1 }') == \
  "${state_sentinel_before}" ]] || \
  die "successful migration changed existing state content"
state_metadata_before="$(stat -c '%u:%g:%a' -- "${STATE_DIR}")"
grep -F -- "sudo systemctl restart autostream-observability" \
  "${WORK_DIR}/migration.out" >/dev/null || \
  die "active migration did not print the explicit restart command"
[[ $(systemctl show --property MainPID --value "${UNIT}") == "${old_pid}" ]] || \
  die "successful migration replaced the running legacy process"
kill -0 "${old_pid}" || die "successful migration stopped the running legacy process"
systemctl is-enabled --quiet "${UNIT}" && die "successful migration unexpectedly enabled the service"

managed_release_dir="${MANAGED_ROOT}/releases/${VERSION}-${archive_sha256:0:12}"
printf '%s\n' "not declared by trusted checksums" > "${managed_release_dir}/unexpected.txt"
set +e
"${EXTRACTED_ROOT}/install-autostream-observability" \
  > "${WORK_DIR}/existing-release-extra-file.out" 2>&1
existing_release_extra_file_status=$?
set -e
[[ ${existing_release_extra_file_status} -ne 0 ]] || \
  die "existing release with an extra regular file unexpectedly succeeded"
grep -F -- "existing managed release checksum inventory is incomplete or unsafe" \
  "${WORK_DIR}/existing-release-extra-file.out" >/dev/null || \
  die "existing release extra file did not fail exact trusted checksum inventory validation"
[[ $(systemctl show --property MainPID --value "${UNIT}") == "${old_pid}" ]] || \
  die "existing release extra file validation replaced the running legacy process"
assert_state_preserved "existing release extra file validation"
rm -f -- "${managed_release_dir}/unexpected.txt"

ln -s -- /etc/passwd "${managed_release_dir}/unexpected-link"
set +e
"${EXTRACTED_ROOT}/install-autostream-observability" \
  > "${WORK_DIR}/existing-release-symlink.out" 2>&1
existing_release_symlink_status=$?
set -e
[[ ${existing_release_symlink_status} -ne 0 ]] || \
  die "existing release with a symlink unexpectedly succeeded"
grep -F -- "existing managed release contains a link or special entry" \
  "${WORK_DIR}/existing-release-symlink.out" >/dev/null || \
  die "existing release symlink did not report the expected failure"
assert_state_preserved "existing release symlink validation"
rm -f -- "${managed_release_dir}/unexpected-link"

mkfifo "${managed_release_dir}/unexpected-fifo"
set +e
"${EXTRACTED_ROOT}/install-autostream-observability" \
  > "${WORK_DIR}/existing-release-special.out" 2>&1
existing_release_special_status=$?
set -e
[[ ${existing_release_special_status} -ne 0 ]] || \
  die "existing release with a special entry unexpectedly succeeded"
grep -F -- "existing managed release contains a link or special entry" \
  "${WORK_DIR}/existing-release-special.out" >/dev/null || \
  die "existing release special entry did not report the expected failure"
assert_state_preserved "existing release special-entry validation"
rm -f -- "${managed_release_dir}/unexpected-fifo"

printf '%s\n' "permanent updater lock sentinel" > "${TARGET_LOCK}"
lock_identity_before_reinstall="$(stat -c '%d:%i:%u:%g:%a' -- "${TARGET_LOCK}")"
lock_digest_before_reinstall="$(sha256sum -- "${TARGET_LOCK}" | awk 'NR == 1 { print $1 }')"
"${EXTRACTED_ROOT}/install-autostream-observability" > "${WORK_DIR}/idempotent.out"
[[ $(stat -c '%d:%i:%u:%g:%a' -- "${TARGET_LOCK}") == "${lock_identity_before_reinstall}" ]] || \
  die "idempotent reinstall changed the permanent lock inode or metadata"
[[ $(sha256sum -- "${TARGET_LOCK}" | awk 'NR == 1 { print $1 }') == \
  "${lock_digest_before_reinstall}" ]] || \
  die "idempotent reinstall truncated or changed the permanent lock content"
[[ $(systemctl show --property MainPID --value "${UNIT}") == "${old_pid}" ]] || \
  die "idempotent reinstall replaced the running legacy process"
assert_loaded_runtime_unit "${PUBLIC_BINARY}" "autostream" "idempotent reinstall"
[[ $(sha256sum "${RUNTIME_UNIT_PATH}" | awk 'NR == 1 { print $1 }') == \
  "$(sha256sum "${UNIT_PATH}" | awk 'NR == 1 { print $1 }')" ]] || \
  die "idempotent reinstall changed the loaded runtime unit"
[[ $(sha256sum "${ENV_PATH}" | awk 'NR == 1 { print $1 }') == "${env_before}" ]] || \
  die "idempotent reinstall changed the existing environment"
[[ $(sha256sum "${MARIADB_DEFAULTS}" | awk 'NR == 1 { print $1 }') == "${db_before}" ]] || \
  die "idempotent reinstall changed the existing MariaDB defaults"
assert_state_preserved "idempotent reinstall"
systemctl is-enabled --quiet "${UNIT}" && die "idempotent reinstall unexpectedly enabled the service"

(
  exec 8<>"${TARGET_LOCK}"
  flock -n 8 || die "test could not acquire the updater target lock"
  set +e
  "${EXTRACTED_ROOT}/install-autostream-observability" \
    > "${WORK_DIR}/contention.out" 2>&1
  contention_status=$?
  set -e
  [[ ${contention_status} -ne 0 ]] || die "installer ignored updater lock contention"
)
grep -F -- "another privileged update is already active for ${UNIT}" \
  "${WORK_DIR}/contention.out" >/dev/null || \
  die "lock contention did not fail with the expected message"
[[ $(stat -c '%d:%i:%u:%g:%a' -- "${TARGET_LOCK}") == "${lock_identity_before_reinstall}" ]] || \
  die "lock contention changed the permanent lock inode or metadata"
[[ $(sha256sum -- "${TARGET_LOCK}" | awk 'NR == 1 { print $1 }') == \
  "${lock_digest_before_reinstall}" ]] || \
  die "lock contention truncated or changed the permanent lock content"
[[ $(systemctl show --property MainPID --value "${UNIT}") == "${old_pid}" ]] || \
  die "lock contention changed the running legacy process"
kill -0 "${old_pid}" || die "lock contention stopped the running legacy process"

printf '%s\n' "Observability installer integration scenarios passed."

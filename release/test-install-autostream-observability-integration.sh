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

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly INSTALLER_SOURCE="${SCRIPT_DIR}/install-autostream-observability"
readonly VERSION="v9.9.9"
readonly ARTIFACT_ID="autostream-observability_${VERSION}_linux_amd64"
readonly WORK_DIR="$(mktemp -d /var/tmp/autostream-observability-installer-test.XXXXXXXX)"
readonly ARTIFACTS_DIR="${WORK_DIR}/artifacts"
readonly EXTRACTED_ROOT="${ARTIFACTS_DIR}/${ARTIFACT_ID}"
readonly ARCHIVE="${ARTIFACTS_DIR}/${ARTIFACT_ID}.tar.gz"
readonly REAL_SYSTEMCTL_COPY="${WORK_DIR}/systemctl.real"
readonly FAIL_SYSTEMCTL="${WORK_DIR}/systemctl.fail"
readonly SYSTEMCTL_CALL_LOG="${WORK_DIR}/systemctl.calls"
readonly SYSTEMCTL_MOUNT_MARKER="${WORK_DIR}/systemctl.mount.ok"
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
readonly PUBLIC_BINARY="/usr/local/bin/autostream-observability"
readonly PUBLIC_ALIAS="/usr/local/bin/observability"
readonly ENV_PATH="/etc/autostream/observability.env"
readonly STATE_DIR="/var/lib/autostream/observability"
readonly MANAGED_ROOT="/opt/autostream/observability"
readonly BACKUP_EXECUTABLE="/usr/local/sbin/autostream-backup-observability"
readonly DATABASE_BACKUP_DIR="/var/backups/autostream/observability"
readonly INSTALL_BACKUP_ROOT="/var/backups/autostream/install-migrations/observability"
readonly MARIADB_DEFAULTS="/etc/autostream-local-executor/mariadb-backup.cnf"
TARGET_LOCK_ID=$(printf '%s' "${UNIT}" | sha256sum | awk 'NR == 1 { print substr($1, 1, 12) }')
[[ ${TARGET_LOCK_ID} =~ ^[0-9a-f]{12}$ ]] || die "could not derive target lock identifier"
readonly TARGET_LOCK_ID
readonly TARGET_LOCK="/run/autostream-updater/.autostream-updater-${TARGET_LOCK_ID}.lock"
readonly LEGACY_UNIT_CONTENT="observability-installer-integration-legacy-unit"
readonly LEGACY_BINARY_CONTENT="observability-installer-integration-legacy-binary"
readonly LEGACY_ALIAS_CONTENT="observability-installer-integration-legacy-alias"
readonly LEGACY_HELPER_CONTENT="observability-installer-integration-legacy-helper"
readonly LEGACY_ENV_CONTENT="OBSERVABILITY_INSTALLER_INTEGRATION_ENV=preserve-exactly"
readonly LEGACY_DB_CONTENT="[client]
password=observability-installer-integration-preserve-exactly"

created_autostream_user=false
created_mariadb_dump=false
old_pid=""
declare -a normalized_boundary_paths=()
declare -a normalized_boundary_original_modes=()
declare -a normalized_boundary_original_identities=()

normalize_boundary_directory() {
  local path=$1
  local normalized_mode=$2
  local expected_mode=${normalized_mode#0}
  local original_mode
  local original_identity

  [[ -d ${path} && ! -L ${path} ]] || \
    die "${path} must be a real directory"
  [[ $(readlink -f -- "${path}") == "${path}" ]] || \
    die "${path} must resolve to its canonical path"
  [[ $(stat -c '%U:%G' -- "${path}") == "root:root" ]] || \
    die "${path} must be owned by root:root"
  original_mode=$(stat -c '%a' -- "${path}") || \
    die "could not capture ${path} mode"
  [[ ${original_mode} =~ ^[0-7]{3,4}$ ]] || \
    die "${path} mode is invalid"
  original_identity=$(stat -c '%d:%i' -- "${path}") || \
    die "could not capture ${path} identity"
  [[ ${original_identity} =~ ^[0-9]+:[0-9]+$ ]] || \
    die "${path} identity is invalid"

  normalized_boundary_paths+=("${path}")
  normalized_boundary_original_modes+=("${original_mode}")
  normalized_boundary_original_identities+=("${original_identity}")

  chmod "${normalized_mode}" -- "${path}" || \
    die "failed to normalize ${path} to root:root mode ${normalized_mode}"
  [[ $(stat -c '%U:%G:%a' -- "${path}") == "root:root:${expected_mode}" ]] || \
    die "failed to normalize ${path} to root:root mode ${normalized_mode}"
}

restore_normalized_boundary_directories() {
  local index
  local path
  local original_mode
  local original_identity
  local restore_failed=false

  for ((index=${#normalized_boundary_paths[@]} - 1; index >= 0; index--)); do
    path=${normalized_boundary_paths[index]}
    original_mode=${normalized_boundary_original_modes[index]}
    original_identity=${normalized_boundary_original_identities[index]}

    if [[ -d ${path} &&
      ! -L ${path} &&
      $(readlink -f -- "${path}") == "${path}" &&
      $(stat -c '%U:%G' -- "${path}") == "root:root" &&
      $(stat -c '%d:%i' -- "${path}") == "${original_identity}" ]] &&
      chmod "${original_mode}" -- "${path}" &&
      [[ $(stat -c '%U:%G:%a' -- "${path}") == "root:root:${original_mode}" ]]; then
      :
    else
      printf 'observability installer integration test: failed to restore %s mode %s\n' \
        "${path}" \
        "${original_mode}" \
        >&2
      restore_failed=true
    fi
  done

  [[ ${restore_failed} == false ]]
}

cleanup() {
  local exit_code=$?
  local cleanup_failed=false
  set +e
  systemctl stop "${UNIT}" >/dev/null 2>&1
  systemctl disable "${UNIT}" >/dev/null 2>&1
  rm -f -- "${UNIT_PATH}"
  systemctl daemon-reload >/dev/null 2>&1
  if [[ -n ${old_pid} ]]; then
    kill "${old_pid}" >/dev/null 2>&1
  fi
  rm -f -- \
    "${PUBLIC_BINARY}" \
    "${PUBLIC_ALIAS}" \
    "${BACKUP_EXECUTABLE}" \
    "${ENV_PATH}" \
    "${MARIADB_DEFAULTS}" \
    "${TARGET_LOCK}"
  rm -rf -- \
    "${STATE_DIR}" \
    "${MANAGED_ROOT}" \
    "${DATABASE_BACKUP_DIR}" \
    "${INSTALL_BACKUP_ROOT}" \
    "${WORK_DIR}"
  rmdir \
    /var/backups/autostream/install-migrations \
    /var/backups/autostream \
    /var/lib/autostream \
    /opt/autostream \
    /etc/autostream \
    /etc/autostream-local-executor \
    /run/autostream-updater >/dev/null 2>&1
  if [[ ${created_mariadb_dump} == true ]]; then
    rm -f /usr/bin/mariadb-dump
  fi
  if [[ ${created_autostream_user} == true ]]; then
    userdel autostream >/dev/null 2>&1
    groupdel autostream >/dev/null 2>&1
  fi
  if ! restore_normalized_boundary_directories; then
    cleanup_failed=true
  fi
  if [[ ${cleanup_failed} == true && ${exit_code} -eq 0 ]]; then
    exit_code=1
  fi
  exit "${exit_code}"
}
trap cleanup EXIT

normalize_boundary_directory /opt 0755
normalize_boundary_directory /usr/local/bin 0755

chmod 0755 "${WORK_DIR}"

for path in \
  "${UNIT_PATH}" \
  "${PUBLIC_BINARY}" \
  "${PUBLIC_ALIAS}" \
  "${ENV_PATH}" \
  "${STATE_DIR}" \
  "${MANAGED_ROOT}" \
  "${BACKUP_EXECUTABLE}" \
  "${DATABASE_BACKUP_DIR}" \
  "${INSTALL_BACKUP_ROOT}" \
  "${MARIADB_DEFAULTS}" \
  "${TARGET_LOCK}"; do
  [[ ! -e ${path} && ! -L ${path} ]] || die "runner is not clean at ${path}"
done
if id autostream >/dev/null 2>&1 || getent group autostream >/dev/null 2>&1; then
  die "runner already has an autostream account"
fi
created_autostream_user=true

if [[ ! -e /usr/bin/mariadb-dump && ! -L /usr/bin/mariadb-dump ]]; then
  install -o root -g root -m 0755 /dev/null /usr/bin/mariadb-dump
  created_mariadb_dump=true
fi
[[ -f /usr/bin/mariadb-dump && ! -L /usr/bin/mariadb-dump && -x /usr/bin/mariadb-dump ]] || \
  die "runner has an unsafe /usr/bin/mariadb-dump"

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
  printf '%s\n' 'commit: integration-test'
  printf '%s\n' 'build_date: integration-test'
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

(
  cd -- "${EXTRACTED_ROOT}"
  find . -type f ! -path './checksums.txt' -print0 |
    sort -z |
    xargs -0 sha256sum > checksums.txt
)
tar -C "${ARTIFACTS_DIR}" -czf "${ARCHIVE}" "${ARTIFACT_ID}"
(
  cd -- "${ARTIFACTS_DIR}"
  sha256sum "${ARTIFACT_ID}.tar.gz" > "${ARTIFACT_ID}.tar.gz.sha256"
)
archive_sha256="$(sha256sum "${ARCHIVE}" | awk 'NR == 1 { print $1 }')"
archive_size="$(stat -c %s "${ARCHIVE}")"
jq -n \
  --arg version "${VERSION}" \
  --arg name "${ARTIFACT_ID}.tar.gz" \
  --arg sha256 "${archive_sha256}" \
  --argjson size "${archive_size}" \
  '{
    schema_version: 1,
    release_id: $version,
    channel: "host",
    published_at: "2026-07-29T00:00:00Z",
    minimum_agent_version: "v2.0.0",
    components: [{
      service: "observability",
      source_version: $version,
      commit: "0123456789abcdef0123456789abcdef01234567",
      rollback_compatible: true,
      database_schema: "backward_compatible",
      artifacts: [{
        os: "linux",
        arch: "amd64",
        name: $name,
        sha256: $sha256,
        size: $size
      }, {
        os: "linux",
        arch: "arm64",
        name: ("autostream-observability_" + $version + "_linux_arm64.tar.gz"),
        sha256: "89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567",
        size: 1
      }]
    }]
  }' > "${ARTIFACTS_DIR}/release-manifest.json"
(
  cd -- "${ARTIFACTS_DIR}"
  sha256sum release-manifest.json > release-manifest.json.sha256
)

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
[[ $(wc -l < "${MKTEMP_CALL_LOG}") -eq 1 ]] || \
  die "mktemp failure injection did not reach exactly the staging call"
grep -Fx -- "-d /opt/autostream/observability/.install.XXXXXX" \
  "${MKTEMP_CALL_LOG}" >/dev/null || \
  die "mktemp failure injection did not reach the expected staging call"
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

rm -f -- "${TARGET_LOCK}"
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
  /run/autostream-updater >/dev/null 2>&1 || \
  die "mktemp-failure reset left an unexpected directory"
userdel autostream
if getent group autostream >/dev/null 2>&1; then
  groupdel autostream
fi
if id autostream >/dev/null 2>&1 || getent group autostream >/dev/null 2>&1; then
  die "mktemp-failure reset retained the autostream account"
fi

"${EXTRACTED_ROOT}/install-autostream-observability" > "${WORK_DIR}/fresh.out"
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

groupadd --system autostream
useradd --system --gid autostream --home-dir /var/lib/autostream \
  --no-create-home --shell /usr/sbin/nologin autostream
install -d -o root -g root -m 0755 /etc/autostream /var/lib/autostream
install -d -o autostream -g autostream -m 0750 "${STATE_DIR}"
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
systemctl daemon-reload
systemctl start "${UNIT}"
old_pid="$(systemctl show --property MainPID --value "${UNIT}")"
[[ ${old_pid} =~ ^[1-9][0-9]*$ ]] || die "legacy service did not start"
kill -0 "${old_pid}" || die "legacy service PID is not alive"
legacy_unit_file_state="$(systemctl is-enabled "${UNIT}" 2>/dev/null || true)"
[[ ${legacy_unit_file_state} == "disabled" ]] || \
  die "legacy fixture must begin disabled, got ${legacy_unit_file_state:-unknown}"

env_before="$(sha256sum "${ENV_PATH}" | awk 'NR == 1 { print $1 }')"
db_before="$(sha256sum "${MARIADB_DEFAULTS}" | awk 'NR == 1 { print $1 }')"
unit_before="$(sha256sum "${UNIT_PATH}" | awk 'NR == 1 { print $1 }')"
helper_before="$(sha256sum "${BACKUP_EXECUTABLE}" | awk 'NR == 1 { print $1 }')"
readonly RETAINED_DIR="${INSTALL_BACKUP_ROOT}/${VERSION}-${archive_sha256:0:12}"

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
systemctl is-enabled --quiet "${UNIT}" && die "failed migration unexpectedly enabled the service"
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

"${EXTRACTED_ROOT}/install-autostream-observability" > "${WORK_DIR}/migration.out"
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
grep -F -- "sudo systemctl restart autostream-observability" \
  "${WORK_DIR}/migration.out" >/dev/null || \
  die "active migration did not print the explicit restart command"
[[ $(systemctl show --property MainPID --value "${UNIT}") == "${old_pid}" ]] || \
  die "successful migration replaced the running legacy process"
kill -0 "${old_pid}" || die "successful migration stopped the running legacy process"
systemctl is-enabled --quiet "${UNIT}" && die "successful migration unexpectedly enabled the service"

"${EXTRACTED_ROOT}/install-autostream-observability" > "${WORK_DIR}/idempotent.out"
[[ $(systemctl show --property MainPID --value "${UNIT}") == "${old_pid}" ]] || \
  die "idempotent reinstall replaced the running legacy process"
[[ $(sha256sum "${ENV_PATH}" | awk 'NR == 1 { print $1 }') == "${env_before}" ]] || \
  die "idempotent reinstall changed the existing environment"
[[ $(sha256sum "${MARIADB_DEFAULTS}" | awk 'NR == 1 { print $1 }') == "${db_before}" ]] || \
  die "idempotent reinstall changed the existing MariaDB defaults"
systemctl is-enabled --quiet "${UNIT}" && die "idempotent reinstall unexpectedly enabled the service"

(
  exec 8>"${TARGET_LOCK}"
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
[[ $(systemctl show --property MainPID --value "${UNIT}") == "${old_pid}" ]] || \
  die "lock contention changed the running legacy process"
kill -0 "${old_pid}" || die "lock contention stopped the running legacy process"

printf '%s\n' "Observability installer integration scenarios passed."

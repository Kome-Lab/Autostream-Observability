ARCHIVE_SOURCE_SIZE=$(stat -c '%s' -- "${ARCHIVE_SOURCE}") || \
  die "failed to read the source archive size"
[[ ${ARCHIVE_SOURCE_SIZE} =~ ^[1-9][0-9]*$ &&
  ${ARCHIVE_SOURCE_SIZE} -le 268435456 ]] || \
  die "source archive size is invalid"
readonly ARCHIVE_SOURCE_SIZE

STAGE_DIR=
trap cleanup EXIT
restore_installer_signal_traps
create_bound_stage_directory \
  STAGE_DIR \
  stage_dir_identity \
  /var/tmp/autostream-observability-install.XXXXXXXX \
  /var/tmp/autostream-observability-install. \
  /var/tmp || \
  die "failed to create archive preflight directory"
[[ -n ${STAGE_DIR} &&
  ${STAGE_DIR} == /var/tmp/autostream-observability-install.* &&
  -d ${STAGE_DIR} &&
  ! -L ${STAGE_DIR} ]] || \
  die "archive preflight directory path is invalid"
[[ $(readlink -f -- "${STAGE_DIR}") == "${STAGE_DIR}" &&
  $(stat -c '%U:%G:%a' -- "${STAGE_DIR}") == "root:root:700" ]] || \
  die "archive preflight directory is invalid"
readonly STAGE_DIR
readonly STAGED_ARCHIVE="${STAGE_DIR}/${ASSET_NAME}"
readonly PREFLIGHT_EXTRACT_DIR="${STAGE_DIR}/release"

copy_bound_source "${ARCHIVE_SOURCE}" "${STAGED_ARCHIVE}" "release archive"
ARCHIVE_DIGEST=$(sha256sum -- "${STAGED_ARCHIVE}" | awk 'NR == 1 { print $1 }') || \
  die "failed to hash the release archive"
[[ ${ARCHIVE_DIGEST} =~ ^[0-9a-f]{64}$ ]] || die "archive digest is invalid"
readonly ARCHIVE_DIGEST
ARCHIVE_SIZE=$(stat -c '%s' -- "${STAGED_ARCHIVE}") || \
  die "failed to read the archive size"
[[ ${ARCHIVE_SIZE} == "${ARCHIVE_SOURCE_SIZE}" ]] || \
  die "staged archive size differs from its source"
readonly ARCHIVE_SIZE

validate_archive_layout \
  "${STAGED_ARCHIVE}" \
  "${STAGE_DIR}/archive.names" \
  "${STAGE_DIR}/archive.verbose"
install -d -o root -g root -m 0700 "${PREFLIGHT_EXTRACT_DIR}"
tar \
  --extract \
  --gzip \
  --file "${STAGED_ARCHIVE}" \
  --directory "${PREFLIGHT_EXTRACT_DIR}" \
  --strip-components=1 \
  --no-same-owner \
  --no-same-permissions \
  --delay-directory-restore

if find "${PREFLIGHT_EXTRACT_DIR}" -type l -print -quit | grep -q .; then
  die "release archive contains a symlink"
fi
for required in \
  "${RELEASE_BINARY}" \
  "bin/observability" \
  "${BACKUP_SOURCE_REL}" \
  ".env.example" \
  "systemd/autostream-observability.service.example" \
  "README.install.md" \
  "${ARTIFACT_MANIFEST_REL}" \
  "checksums.txt" \
  "install-autostream-observability"; do
  [[ -f ${PREFLIGHT_EXTRACT_DIR}/${required} &&
    ! -L ${PREFLIGHT_EXTRACT_DIR}/${required} ]] || \
    die "release archive is missing ${required}"
done
[[ ! -e ${PREFLIGHT_EXTRACT_DIR}/.artifact-sha256 &&
  ! -L ${PREFLIGHT_EXTRACT_DIR}/.artifact-sha256 ]] || \
  die "release archive must not provide .artifact-sha256"
[[ ! -e ${PREFLIGHT_EXTRACT_DIR}/.version &&
  ! -L ${PREFLIGHT_EXTRACT_DIR}/.version ]] || \
  die "release archive must not provide .version"
validate_checksum_inventory \
  "${PREFLIGHT_EXTRACT_DIR}" \
  "${STAGE_DIR}/preflight-checksums" || \
  die "release archive checksum inventory is incomplete or unsafe"
(
  cd -- "${PREFLIGHT_EXTRACT_DIR}"
  sha256sum --check --strict checksums.txt
) || die "release archive content verification failed"
validate_artifact_manifest "${PREFLIGHT_EXTRACT_DIR}/${ARTIFACT_MANIFEST_REL}" || \
  die "release artifact manifest does not bind the expected Observability archive"

chmod 0700 "${PREFLIGHT_EXTRACT_DIR}/${RELEASE_BINARY}"
EXPECTED_BINARY_IDENTITY=$(expected_binary_identity \
  "${PREFLIGHT_EXTRACT_DIR}/${ARTIFACT_MANIFEST_REL}") || \
  die "could not read the expected release binary identity"
readonly EXPECTED_BINARY_IDENTITY
PREFLIGHT_BINARY_IDENTITY=$("${PREFLIGHT_EXTRACT_DIR}/${RELEASE_BINARY}" --version) || \
  die "release binary identity probe failed"
[[ ${PREFLIGHT_BINARY_IDENTITY} == "${EXPECTED_BINARY_IDENTITY}" ]] || \
  die "release binary identity does not match the artifact manifest"
readonly PREFLIGHT_BINARY_IDENTITY

validate_safe_root_directory / "/"
validate_safe_root_directory /usr "/usr"
validate_safe_root_directory /etc "/etc"
validate_safe_root_directory /var "/var"
validate_safe_root_directory /run "/run"
TARGET_LOCK_ID=$(printf '%s' "${UNIT_NAME}" | sha256sum | awk 'NR == 1 { print substr($1, 1, 12) }') || \
  die "could not derive the updater target lock identifier"
[[ ${TARGET_LOCK_ID} =~ ^[0-9a-f]{12}$ ]] || \
  die "could not derive the updater target lock identifier"
readonly TARGET_LOCK_ID
readonly TARGET_LOCK="/run/autostream-updater/.autostream-updater-${TARGET_LOCK_ID}.lock"
readonly SHARED_HOST_SETUP_LOCK="/run/autostream-updater/.autostream-runtime-host-setup.lock"
readonly INSTALL_BACKUP_DIR="${INSTALL_MIGRATION_SERVICE_ROOT}/${VERSION}-${ARCHIVE_DIGEST:0:12}"
readonly LEGACY_BINARY_BACKUP="${INSTALL_BACKUP_DIR}/usr-local-bin-autostream-observability.pre-managed"
readonly LEGACY_ALIAS_BACKUP="${INSTALL_BACKUP_DIR}/usr-local-bin-observability.pre-managed"
readonly LEGACY_UNIT_BACKUP="${INSTALL_BACKUP_DIR}/etc-systemd-system-autostream-observability.service.pre-managed"
readonly LEGACY_BACKUP_EXEC_BACKUP="${INSTALL_BACKUP_DIR}/usr-local-sbin-autostream-backup-observability.pre-managed"
validate_safe_root_directory_candidate /opt "/opt"
validate_safe_root_directory_candidate /opt/autostream "/opt/autostream"
validate_safe_root_directory_candidate "${MANAGED_ROOT}" "${MANAGED_ROOT}"
validate_safe_root_directory_candidate "${RELEASE_ROOT}" "${RELEASE_ROOT}"
validate_safe_root_directory_candidate /usr/local "/usr/local"
validate_safe_root_directory_candidate /usr/local/bin "/usr/local/bin"
validate_safe_root_directory_candidate /usr/local/sbin "/usr/local/sbin"
validate_safe_root_directory_candidate /etc/systemd "/etc/systemd"
validate_safe_root_directory_candidate /etc/systemd/system "/etc/systemd/system"
validate_safe_root_directory_candidate /etc/autostream "/etc/autostream"
validate_safe_root_directory_candidate /var/lib "/var/lib"
validate_safe_root_directory_candidate /var/lib/autostream "/var/lib/autostream"
validate_safe_root_directory_candidate /var/backups "/var/backups"
validate_root_only_directory_candidate /var/backups/autostream
validate_root_only_directory_candidate "${INSTALL_MIGRATION_ROOT}"
validate_root_only_directory_candidate "${INSTALL_MIGRATION_SERVICE_ROOT}"
validate_root_only_directory_candidate "${INSTALL_BACKUP_DIR}"
validate_safe_root_directory_candidate "${BACKUP_CONFIG_DIR}" "${BACKUP_CONFIG_DIR}"
validate_root_only_directory_candidate /run/autostream-updater
validate_exact_directory_candidate "${STATE_DIR}" autostream autostream 0750 "${STATE_DIR}"
validate_exact_directory_candidate "${BACKUP_DIR}" root root 0700 "${BACKUP_DIR}"
if [[ -e ${TARGET_LOCK} || -L ${TARGET_LOCK} ]]; then
  [[ -f ${TARGET_LOCK} && ! -L ${TARGET_LOCK} ]] || die "updater target lock path is unsafe"
  [[ $(stat -c '%U:%G:%a' -- "${TARGET_LOCK}") == "root:root:600" ]] || \
    die "updater target lock must be owned by root:root with mode 0600"
fi
if [[ -e ${SHARED_HOST_SETUP_LOCK} || -L ${SHARED_HOST_SETUP_LOCK} ]]; then
  [[ -f ${SHARED_HOST_SETUP_LOCK} && ! -L ${SHARED_HOST_SETUP_LOCK} &&
    $(stat -c '%U:%G:%a' -- "${SHARED_HOST_SETUP_LOCK}") == "root:root:600" ]] || \
    die "shared runtime host-setup lock must be a root:root mode 0600 regular file"
fi

validate_current_release
legacy_install_detected=false
legacy_binary_regular=false
legacy_alias_regular=false
legacy_unit_regular=false
legacy_backup_exec_regular=false
if [[ -f ${PUBLIC_BINARY} && ! -L ${PUBLIC_BINARY} ]]; then
  legacy_install_detected=true
  legacy_binary_regular=true
fi
if [[ -f ${PUBLIC_ALIAS} && ! -L ${PUBLIC_ALIAS} ]]; then
  legacy_install_detected=true
  legacy_alias_regular=true
fi
if [[ ${legacy_install_detected} == true && -f ${UNIT_DEST} && ! -L ${UNIT_DEST} ]]; then
  legacy_unit_regular=true
fi
if [[ ${legacy_install_detected} == true && -f ${BACKUP_DEST} && ! -L ${BACKUP_DEST} ]]; then
  legacy_backup_exec_regular=true
fi
validate_public_path "${PUBLIC_BINARY}" "${CURRENT_LINK}/${RELEASE_BINARY}" "${PUBLIC_BINARY}"
validate_public_path "${PUBLIC_ALIAS}" "${PUBLIC_BINARY}" "${PUBLIC_ALIAS}"
if [[ -e ${UNIT_DEST} || -L ${UNIT_DEST} ]]; then
  validate_replaceable_regular_file "${UNIT_DEST}" "${UNIT_DEST}"
fi
if [[ -e ${BACKUP_DEST} || -L ${BACKUP_DEST} ]]; then
  validate_replaceable_regular_file "${BACKUP_DEST}" "${BACKUP_DEST}"
fi

env_existed=false
env_sha_before=
if [[ -e ${ENV_DEST} || -L ${ENV_DEST} ]]; then
  validate_secure_existing_file "${ENV_DEST}" "root:root:640" "${ENV_DEST}"
  env_existed=true
  env_sha_before=$(sha256sum -- "${ENV_DEST}" | awk 'NR == 1 { print $1 }')
fi

backup_config_existed=false
backup_config_sha_before=
if [[ -e ${BACKUP_CONFIG_DEST} || -L ${BACKUP_CONFIG_DEST} ]]; then
  validate_secure_existing_file "${BACKUP_CONFIG_DEST}" "root:root:600" "${BACKUP_CONFIG_DEST}"
  backup_config_existed=true
  backup_config_sha_before=$(sha256sum -- "${BACKUP_CONFIG_DEST}" | awk 'NR == 1 { print $1 }')
fi

snapshot_legacy_backup_path "${LEGACY_BINARY_BACKUP}"
snapshot_legacy_backup_path "${LEGACY_ALIAS_BACKUP}"
snapshot_legacy_backup_path "${LEGACY_UNIT_BACKUP}"
snapshot_legacy_backup_path "${LEGACY_BACKUP_EXEC_BACKUP}"
preflight_autostream_account

if [[ -e ${STATE_DIR} || -L ${STATE_DIR} ]]; then
  state_dir_existed=true
  state_dir_original_uid=$(stat -c '%u' -- "${STATE_DIR}")
  state_dir_original_gid=$(stat -c '%g' -- "${STATE_DIR}")
  state_dir_original_mode=$(stat -c '%a' -- "${STATE_DIR}")
  state_dir_original_identity=$(stat -c '%d:%i' -- "${STATE_DIR}")
fi
if [[ -e ${BACKUP_DIR} || -L ${BACKUP_DIR} ]]; then
  backup_dir_existed=true
  backup_dir_original_uid=$(stat -c '%u' -- "${BACKUP_DIR}")
  backup_dir_original_gid=$(stat -c '%g' -- "${BACKUP_DIR}")
  backup_dir_original_mode=$(stat -c '%a' -- "${BACKUP_DIR}")
  backup_dir_original_identity=$(stat -c '%d:%i' -- "${BACKUP_DIR}")
fi

service_was_active=false
if systemctl is-active --quiet autostream-observability.service >/dev/null 2>&1; then
  service_was_active=true
fi

ensure_permanent_lock_directory /run/autostream-updater
if [[ ! -e ${SHARED_HOST_SETUP_LOCK} && ! -L ${SHARED_HOST_SETUP_LOCK} ]]; then
  reserve_path \
    shared_lock_create_stage \
    /run/autostream-updater \
    ".host-lock-create" || \
    die "could not create shared runtime host-setup lock candidate"
  lock_creation_failed=false
  begin_installer_signal_transaction
  if ! install -o root -g root -m 0600 /dev/null "${shared_lock_create_stage}"; then
    lock_creation_failed=true
  elif [[ ! -f ${shared_lock_create_stage} || -L ${shared_lock_create_stage} ||
    $(stat -c '%U:%G:%a' -- "${shared_lock_create_stage}") != "root:root:600" ]]; then
    lock_creation_failed=true
  elif ln -- "${shared_lock_create_stage}" "${SHARED_HOST_SETUP_LOCK}" 2>/dev/null; then
    sync -f -- /run/autostream-updater || lock_creation_failed=true
  elif [[ ! -e ${SHARED_HOST_SETUP_LOCK} && ! -L ${SHARED_HOST_SETUP_LOCK} ]]; then
    lock_creation_failed=true
  fi
  rm -f -- "${shared_lock_create_stage}" || lock_creation_failed=true
  shared_lock_create_stage=
  finish_installer_signal_transaction
  if [[ ${lock_creation_failed} == true ]]; then
    die "could not atomically create the permanent shared runtime host-setup lock"
  fi
fi
[[ -f ${SHARED_HOST_SETUP_LOCK} && ! -L ${SHARED_HOST_SETUP_LOCK} &&
  $(stat -c '%U:%G:%a' -- "${SHARED_HOST_SETUP_LOCK}") == "root:root:600" ]] || \
  die "shared runtime host-setup lock path is unsafe"
exec 8<>"${SHARED_HOST_SETUP_LOCK}"
chown root:root /proc/self/fd/8
chmod 0600 /proc/self/fd/8
shared_lock_fd_identity=$(stat -Lc '%d:%i' -- /proc/self/fd/8)
[[ -f ${SHARED_HOST_SETUP_LOCK} && ! -L ${SHARED_HOST_SETUP_LOCK} &&
  -f /proc/self/fd/8 &&
  $(stat -Lc '%U:%G:%a' -- /proc/self/fd/8) == "root:root:600" &&
  $(stat -c '%U:%G:%a' -- "${SHARED_HOST_SETUP_LOCK}") == "root:root:600" &&
  ${shared_lock_fd_identity} == "$(stat -c '%d:%i' -- "${SHARED_HOST_SETUP_LOCK}")" ]] || \
  die "shared runtime host-setup lock identity changed while being opened"
flock -n 8 || die "another runtime installer is provisioning shared host state"
[[ -f ${SHARED_HOST_SETUP_LOCK} && ! -L ${SHARED_HOST_SETUP_LOCK} &&
  -f /proc/self/fd/8 &&
  $(stat -Lc '%U:%G:%a' -- /proc/self/fd/8) == "root:root:600" &&
  $(stat -c '%U:%G:%a' -- "${SHARED_HOST_SETUP_LOCK}") == "root:root:600" &&
  ${shared_lock_fd_identity} == "$(stat -c '%d:%i' -- "${SHARED_HOST_SETUP_LOCK}")" ]] || \
  die "shared runtime host-setup lock identity changed after acquisition"
if [[ ! -e ${TARGET_LOCK} && ! -L ${TARGET_LOCK} ]]; then
  reserve_path \
    lock_create_stage \
    /run/autostream-updater \
    ".lock-create" || \
    die "could not create updater target lock candidate"
  lock_creation_failed=false
  begin_installer_signal_transaction
  if ! install -o root -g root -m 0600 /dev/null "${lock_create_stage}"; then
    lock_creation_failed=true
  elif [[ ! -f ${lock_create_stage} || -L ${lock_create_stage} ||
    $(stat -c '%U:%G:%a' -- "${lock_create_stage}") != "root:root:600" ]]; then
    lock_creation_failed=true
  elif ln -- "${lock_create_stage}" "${TARGET_LOCK}" 2>/dev/null; then
    sync -f -- /run/autostream-updater || lock_creation_failed=true
  elif [[ ! -e ${TARGET_LOCK} && ! -L ${TARGET_LOCK} ]]; then
    lock_creation_failed=true
  fi
  rm -f -- "${lock_create_stage}" || lock_creation_failed=true
  lock_create_stage=
  finish_installer_signal_transaction
  if [[ ${lock_creation_failed} == true ]]; then
    die "could not atomically create the permanent updater target lock"
  fi
fi
[[ -f ${TARGET_LOCK} && ! -L ${TARGET_LOCK} &&
  $(stat -c '%U:%G:%a' -- "${TARGET_LOCK}") == "root:root:600" ]] || \
  die "updater target lock path is unsafe"
exec 9<>"${TARGET_LOCK}"
chown root:root /proc/self/fd/9
chmod 0600 /proc/self/fd/9
target_lock_fd_identity=$(stat -Lc '%d:%i' -- /proc/self/fd/9)
[[ -f ${TARGET_LOCK} && ! -L ${TARGET_LOCK} &&
  -f /proc/self/fd/9 &&
  $(stat -Lc '%U:%G:%a' -- /proc/self/fd/9) == "root:root:600" &&
  $(stat -c '%U:%G:%a' -- "${TARGET_LOCK}") == "root:root:600" &&
  ${target_lock_fd_identity} == "$(stat -c '%d:%i' -- "${TARGET_LOCK}")" ]] || \
  die "updater target lock identity changed while being opened"
flock -n 9 || die "another privileged update is already active for ${UNIT_NAME}"
[[ -f ${TARGET_LOCK} && ! -L ${TARGET_LOCK} &&
  -f /proc/self/fd/9 &&
  $(stat -Lc '%U:%G:%a' -- /proc/self/fd/9) == "root:root:600" &&
  $(stat -c '%U:%G:%a' -- "${TARGET_LOCK}") == "root:root:600" &&
  ${target_lock_fd_identity} == "$(stat -c '%d:%i' -- "${TARGET_LOCK}")" ]] || \
  die "updater target lock identity changed after acquisition"

transaction_journal_active=true
ensure_safe_root_directory /opt 0755 "/opt"
ensure_safe_root_directory /opt/autostream 0755 "/opt/autostream"
ensure_safe_root_directory "${MANAGED_ROOT}" 0755 "${MANAGED_ROOT}"
ensure_safe_root_directory "${RELEASE_ROOT}" 0755 "${RELEASE_ROOT}"
ensure_safe_root_directory /usr/local 0755 "/usr/local"
ensure_safe_root_directory /usr/local/bin 0755 "/usr/local/bin"
ensure_safe_root_directory /usr/local/sbin 0755 "/usr/local/sbin"
ensure_safe_root_directory /etc/systemd 0755 "/etc/systemd"
ensure_safe_root_directory /etc/systemd/system 0755 "/etc/systemd/system"
ensure_safe_root_directory /etc/autostream 0750 "/etc/autostream"
ensure_safe_root_directory /var/lib 0755 "/var/lib"
ensure_safe_root_directory /var/lib/autostream 0755 "/var/lib/autostream"
ensure_safe_root_directory /var/backups 0755 "/var/backups"
ensure_root_only_directory /var/backups/autostream true
ensure_root_only_directory "${INSTALL_MIGRATION_ROOT}" true
ensure_root_only_directory "${INSTALL_MIGRATION_SERVICE_ROOT}" true
ensure_safe_root_directory "${BACKUP_CONFIG_DIR}" 0700 "${BACKUP_CONFIG_DIR}"
ensure_autostream_account


validate_secure_existing_file() {
  local path=$1
  local expected=$2
  local label=$3
  [[ -f ${path} && ! -L ${path} ]] || die "${label} must be a regular non-symlink file"
  [[ $(stat -c '%U:%G:%a' -- "${path}") == "${expected}" ]] || \
    die "${label} owner or mode is invalid"
}

validate_replaceable_regular_file() {
  local path=$1
  local label=$2
  local mode
  [[ -f ${path} && ! -L ${path} ]] || die "${label} must be a regular non-symlink file"
  [[ $(stat -c '%U:%G' -- "${path}") == "root:root" ]] || die "${label} must be owned by root:root"
  mode=$(stat -c '%a' -- "${path}")
  (( (8#${mode} & 07022) == 0 )) || \
    die "${label} must not have special bits or be writable by group or other"
}

validate_public_path() {
  local path=$1
  local expected_target=$2
  local label=$3
  local resolved expected_resolved
  if [[ ! -e ${path} && ! -L ${path} ]]; then
    return
  fi
  if [[ -L ${path} ]]; then
    [[ $(stat -c '%U:%G' -- "${path}") == "root:root" ]] || die "${label} symlink must be owned by root:root"
    if [[ $(readlink -- "${path}") == "${expected_target}" ]]; then
      return
    fi
    resolved=$(readlink -f -- "${path}" 2>/dev/null || true)
    expected_resolved=$(readlink -f -- "${expected_target}" 2>/dev/null || true)
    [[ -n ${resolved} && -n ${expected_resolved} && ${resolved} == "${expected_resolved}" ]] || \
      die "${label} is an unmanaged symlink"
    return
  fi
  validate_replaceable_regular_file "${path}" "${label}"
  [[ -x ${path} ]] || die "${label} legacy binary is not executable"
}

create_bound_stage_directory() {
  local output_path_variable=$1
  local output_identity_variable=$2
  local template=$3
  local expected_prefix=$4
  local expected_parent=$5
  local path="" identity="" creation_failed=false

  begin_installer_signal_transaction
  if ! path=$(mktemp -d "${template}"); then
    creation_failed=true
  elif [[ -z ${path} ||
    ${path} != "${expected_prefix}"* ||
    $(dirname -- "${path}") != "${expected_parent}" ||
    ! -d ${path} ||
    -L ${path} ||
    $(readlink -f -- "${path}") != "${path}" ||
    $(stat -c '%U:%G:%a' -- "${path}") != "root:root:700" ]]; then
    creation_failed=true
  elif ! identity=$(stat -c '%d:%i' -- "${path}"); then
    creation_failed=true
  else
    printf -v "${output_path_variable}" '%s' "${path}"
    printf -v "${output_identity_variable}" '%s' "${identity}"
  fi
  if [[ ${creation_failed} == true &&
    -n ${path} &&
    ${path} == "${expected_prefix}"* &&
    $(dirname -- "${path}") == "${expected_parent}" &&
    -d ${path} &&
    ! -L ${path} &&
    $(readlink -f -- "${path}") == "${path}" ]]; then
    rm -rf -- "${path}" || true
  fi
  finish_installer_signal_transaction
  [[ ${creation_failed} == false ]]
}

reserve_path() {
  local output_variable=$1
  local directory=$2
  local template=$3
  local reserved="" reservation_failed=false

  printf -v "${output_variable}" '%s' ""
  begin_installer_signal_transaction
  if ! reserved=$(mktemp "${directory}/${template}.XXXXXX"); then
    reservation_failed=true
  elif [[ -z ${reserved} ||
    ${reserved} != "${directory}/${template}."* ||
    $(dirname -- "${reserved}") != "${directory}" ||
    ! -f ${reserved} ||
    -L ${reserved} ]]; then
    reservation_failed=true
  else
    register_temporary_rollback_path "${reserved}"
    if ! rm -f -- "${reserved}"; then
      reservation_failed=true
    else
      printf -v "${output_variable}" '%s' "${reserved}"
    fi
  fi
  if [[ ${reservation_failed} == true &&
    -n ${reserved} &&
    ${reserved} == "${directory}/${template}."* &&
    $(dirname -- "${reserved}") == "${directory}" &&
    -f ${reserved} &&
    ! -L ${reserved} ]]; then
    rm -f -- "${reserved}" || true
  fi
  finish_installer_signal_transaction
  [[ ${reservation_failed} == false ]]
}

ensure_permanent_lock_directory() {
  local path=$1
  # updater target lock is permanent installer coordination state.
  if [[ -e ${path} || -L ${path} ]]; then
    [[ -d ${path} &&
      ! -L ${path} &&
      $(readlink -f -- "${path}") == "${path}" &&
      $(stat -c '%U:%G:%a' -- "${path}") == "root:root:700" ]] || \
      die "permanent updater lock directory is unsafe: ${path}"
  else
    install -d -o root -g root -m 0700 -- "${path}"
    [[ -d ${path} &&
      ! -L ${path} &&
      $(readlink -f -- "${path}") == "${path}" &&
      $(stat -c '%U:%G:%a' -- "${path}") == "root:root:700" ]] || \
      die "could not create the permanent updater lock directory"
    sync -f -- "$(dirname -- "${path}")" || \
      die "could not synchronize the permanent updater lock directory"
  fi
}

sync_existing_directories_best_effort() {
  local failed=false
  local directory
  for directory in "$@"; do
    if [[ -e ${directory} || -L ${directory} ]]; then
      if [[ ! -d ${directory} || -L ${directory} ]]; then
        failed=true
        continue
      fi
      sync -f -- "${directory}" || failed=true
    fi
  done
  [[ ${failed} == false ]]
}

sync_required_directories() {
  local directory
  for directory in "$@"; do
    [[ -d ${directory} && ! -L ${directory} ]] || return 1
    sync -f -- "${directory}" || return 1
  done
}

sync_common_installation_parents_best_effort() {
  sync_existing_directories_best_effort \
    / \
    /opt \
    /opt/autostream \
    "${MANAGED_ROOT}" \
    "${RELEASE_ROOT}" \
    /usr \
    /usr/local \
    /usr/local/bin \
    /usr/local/sbin \
    /etc \
    /etc/systemd \
    /etc/systemd/system \
    /etc/autostream \
    "${BACKUP_CONFIG_DIR}" \
    /var \
    /var/lib \
    /var/lib/autostream \
    "${STATE_DIR}" \
    /var/backups \
    /var/backups/autostream \
    "${INSTALL_MIGRATION_ROOT}" \
    "${INSTALL_MIGRATION_SERVICE_ROOT}" \
    "${BACKUP_DIR}" \
    /run \
    /run/autostream-updater
}

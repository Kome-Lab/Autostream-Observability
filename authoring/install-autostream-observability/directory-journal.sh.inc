
register_temporary_rollback_path() {
  local path=$1
  local recorded
  [[ -n ${path} && ${path} == /* ]] || die "temporary rollback path is empty or not absolute"
  for recorded in "${temporary_rollback_paths[@]}"; do
    [[ ${recorded} == "${path}" ]] && return 0
  done
  temporary_rollback_paths+=("${path}")
}

journal_directory_before_mutation() {
  local path=$1
  local retain_if_nonempty=${2-false}
  local snapshot_existed=false
  local snapshot_identity=""
  local snapshot_owner=""
  local snapshot_mode=""

  [[ ${transaction_journal_active} == true ]] || return 0
  [[ ${directory_journaled["${path}"]-false} != true ]] || return 0
  if [[ -e ${path} || -L ${path} ]]; then
    [[ -d ${path} && ! -L ${path} &&
      $(readlink -f -- "${path}") == "${path}" ]] || \
      die "directory path is unsafe before mutation: ${path}"
    snapshot_existed=true
    snapshot_identity=$(stat -c '%d:%i' -- "${path}") || \
      die "could not snapshot directory identity before mutation: ${path}"
    snapshot_owner=$(stat -c '%u:%g' -- "${path}") || \
      die "could not snapshot directory ownership before mutation: ${path}"
    snapshot_mode=$(stat -c '%a' -- "${path}") || \
      die "could not snapshot directory mode before mutation: ${path}"
  fi

  begin_installer_signal_transaction
  directory_journaled["${path}"]=true
  directory_retain_if_nonempty["${path}"]="${retain_if_nonempty}"
  directory_existed["${path}"]="${snapshot_existed}"
  directory_original_identity["${path}"]="${snapshot_identity}"
  directory_original_owner["${path}"]="${snapshot_owner}"
  directory_original_mode["${path}"]="${snapshot_mode}"
  directory_created_identity["${path}"]=""
  journaled_directory_paths+=("${path}")
  finish_installer_signal_transaction
}

record_created_directory_identity() {
  local path=$1
  local identity
  if [[ ${transaction_journal_active} == true &&
    ${directory_journaled["${path}"]-false} == true &&
    ${directory_existed["${path}"]} == false ]]; then
    identity=$(stat -c '%d:%i' -- "${path}") || return 1
    directory_created_identity["${path}"]="${identity}"
  fi
}

create_journaled_directory() {
  local path=$1
  local creation_failed=false

  begin_installer_signal_transaction
  if ! mkdir -- "${path}"; then
    creation_failed=true
  elif ! record_created_directory_identity "${path}"; then
    creation_failed=true
  fi
  finish_installer_signal_transaction
  [[ ${creation_failed} == false ]]
}

ensure_safe_root_directory() {
  local path=$1
  local mode=$2
  local label=$3
  local retain_if_nonempty=${4-false}
  local expected_mode=${mode#0}
  journal_directory_before_mutation "${path}" "${retain_if_nonempty}"
  if [[ ! -e ${path} && ! -L ${path} ]]; then
    create_journaled_directory "${path}" || \
      die "could not create or journal ${label}"
    chown root:root "${path}"
    chmod "${mode}" "${path}"
  fi
  validate_safe_root_directory "${path}" "${label}"
  if [[ ${directory_existed["${path}"]} == false ]]; then
    [[ $(stat -c '%U:%G:%a' -- "${path}") == "root:root:${expected_mode}" ]] || \
      die "${label} owner or mode is invalid after creation"
  fi
}

ensure_root_only_directory() {
  local path=$1
  local retain_if_nonempty=${2-false}
  journal_directory_before_mutation "${path}" "${retain_if_nonempty}"
  validate_root_only_directory_candidate "${path}"
  if [[ ! -e ${path} && ! -L ${path} ]]; then
    create_journaled_directory "${path}" || \
      die "could not create or journal ${path}"
  fi
  chown root:root "${path}"
  chmod 0700 "${path}"
  [[ $(stat -c '%U:%G:%a' -- "${path}") == "root:root:700" ]] || \
    die "${path} owner or mode is invalid"
  [[ $(readlink -f -- "${path}") == "${path}" ]] || \
    die "${path} must resolve to its exact canonical path"
}

validate_root_only_directory_candidate() {
  local path=$1
  local mode
  if [[ -e ${path} || -L ${path} ]]; then
    [[ -d ${path} && ! -L ${path} ]] || die "${path} must be a non-symlink directory"
    [[ $(stat -c '%U:%G' -- "${path}") == "root:root" ]] || \
      die "${path} must be owned by root:root"
    mode=$(stat -c '%a' -- "${path}")
    (( (8#${mode} & 07077) == 0 )) || \
      die "${path} must not have special bits or grant group or other permissions"
    [[ $(readlink -f -- "${path}") == "${path}" ]] || \
      die "${path} must resolve to its exact canonical path"
  fi
}

validate_exact_directory_candidate() {
  local path=$1
  local owner=$2
  local group=$3
  local mode=$4
  local label=$5
  local existing_mode
  local expected_mode=${mode#0}
  [[ ${expected_mode} =~ ^[0-7]{3,4}$ ]] || die "${label} requested mode is invalid"
  if [[ -e ${path} || -L ${path} ]]; then
    [[ -d ${path} && ! -L ${path} ]] || die "${label} must be a non-symlink directory"
    [[ $(stat -c '%U:%G' -- "${path}") == "${owner}:${group}" ]] || \
      die "${label} has unexpected ownership"
    existing_mode=$(stat -c '%a' -- "${path}")
    (( (8#${existing_mode} & 07022) == 0 )) || \
      die "${label} has special bits or is writable by group or other"
    [[ $(readlink -f -- "${path}") == "${path}" ]] || \
      die "${label} must resolve to its exact canonical path"
  fi
}

ensure_exact_directory() {
  local path=$1
  local owner=$2
  local group=$3
  local mode=$4
  local label=$5
  local journal=${6-true}
  local expected_mode=${mode#0}
  if [[ ${journal} == true ]]; then
    journal_directory_before_mutation "${path}"
  fi
  validate_exact_directory_candidate "${path}" "${owner}" "${group}" "${mode}" "${label}"
  if [[ ! -e ${path} && ! -L ${path} ]]; then
    create_journaled_directory "${path}" || \
      die "could not create or journal ${label}"
    if [[ ${journal} == true ]]; then
      [[ -n ${directory_created_identity["${path}"]-} ]] || \
        die "could not bind the created ${label} identity"
    fi
  fi
  chown "${owner}:${group}" "${path}"
  chmod "${mode}" "${path}"
  [[ -d ${path} && ! -L ${path} ]] || die "${label} was not created safely"
  [[ $(stat -c '%U:%G:%a' -- "${path}") == "${owner}:${group}:${expected_mode}" ]] || \
    die "${label} owner or mode is invalid"
  [[ $(readlink -f -- "${path}") == "${path}" ]] || \
    die "${label} must resolve to its exact canonical path"
}

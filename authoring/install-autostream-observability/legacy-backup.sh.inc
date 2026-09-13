
verify_legacy_backup_file() {
  local backup_path=$1
  local expected_digest=${2-}
  validate_replaceable_regular_file "${backup_path}" "retained legacy backup"
  if [[ -n ${expected_digest} &&
    $(sha256sum -- "${backup_path}" | awk 'NR == 1 { print $1 }') != "${expected_digest}" ]]; then
    die "retained legacy backup content conflicts with the live file: ${backup_path}"
  fi
  if [[ ${preexisting_legacy_backup_identity["${backup_path}"]+present} == present ]]; then
    [[ $(stat -c '%d:%i:%s:%Y:%Z:%f:%u:%g:%a' -- "${backup_path}") == \
      "${preexisting_legacy_backup_identity["${backup_path}"]}" ]] || \
      die "pre-existing legacy backup identity or metadata changed during installation: ${backup_path}"
    [[ $(sha256sum -- "${backup_path}" | awk 'NR == 1 { print $1 }') == \
      "${preexisting_legacy_backup_digest["${backup_path}"]}" ]] || \
      die "pre-existing legacy backup content changed during installation: ${backup_path}"
  fi
}

snapshot_legacy_backup_path() {
  local backup_path=$1
  if [[ -e ${backup_path} || -L ${backup_path} ]]; then
    verify_legacy_backup_file "${backup_path}"
    legacy_backup_existed_before["${backup_path}"]=true
    preexisting_legacy_backup_identity["${backup_path}"]="$(stat -c '%d:%i:%s:%Y:%Z:%f:%u:%g:%a' -- "${backup_path}")"
    preexisting_legacy_backup_digest["${backup_path}"]="$(sha256sum -- "${backup_path}" | awk 'NR == 1 { print $1 }')"
  else
    legacy_backup_existed_before["${backup_path}"]=false
  fi
}

retain_legacy_file() {
  local should_retain=$1
  local source=$2
  local destination=$3
  local label=$4
  local source_digest source_mode staged
  [[ ${should_retain} == true ]] || return 0
  validate_replaceable_regular_file "${source}" "${label}"
  source_digest=$(sha256sum -- "${source}" | awk 'NR == 1 { print $1 }') || \
    die "failed to hash ${label}"
  [[ ${source_digest} =~ ^[0-9a-f]{64}$ ]] || die "failed to hash ${label}"
  source_mode=$(stat -c '%a' -- "${source}") || die "failed to inspect ${label}"
  if [[ -e ${destination} || -L ${destination} ]]; then
    [[ ${legacy_backup_existed_before["${destination}"]-false} == true ]] || \
      die "legacy backup path appeared after preflight: ${destination}"
    validate_replaceable_regular_file "${destination}" "retained ${label}"
    [[ $(stat -c '%a' -- "${destination}") == "${source_mode}" ]] || \
      die "retained ${label} mode conflicts with the live file"
    [[ $(sha256sum -- "${destination}" | awk 'NR == 1 { print $1 }') == "${source_digest}" ]] || \
      die "retained ${label} content conflicts with the live file"
    return
  fi
  reserve_path staged "${INSTALL_BACKUP_DIR}" ".legacy.next" || \
    die "failed to reserve ${label} retention path"
  install -o root -g root -m "${source_mode}" -- "${source}" "${staged}"
  [[ $(sha256sum -- "${source}" | awk 'NR == 1 { print $1 }') == "${source_digest}" ]] || \
    die "${label} changed while it was retained"
  [[ $(sha256sum -- "${staged}" | awk 'NR == 1 { print $1 }') == "${source_digest}" ]] || \
    die "retained ${label} differs from its source"
  mv -T -- "${staged}" "${destination}"
  validate_replaceable_regular_file "${destination}" "retained ${label}"
  created_legacy_backup_identity["${destination}"]="$(stat -c '%d:%i:%s:%Y:%Z:%f:%u:%g:%a' -- "${destination}")"
  created_legacy_backup_digest["${destination}"]="$(sha256sum -- "${destination}" | awk 'NR == 1 { print $1 }')"
  sync -f -- "${INSTALL_BACKUP_DIR}" || die "failed to synchronize retained ${label}"
}

stage_symlink() {
  local output_variable=$1
  local target=$2
  local directory=$3
  local template=$4
  local staged="" staging_failed=false

  reserve_path staged "${directory}" "${template}" || return 1
  begin_installer_signal_transaction
  if ! ln -s -- "${target}" "${staged}"; then
    staging_failed=true
  elif [[ ! -L ${staged} || $(readlink -- "${staged}") != "${target}" ]]; then
    staging_failed=true
  else
    printf -v "${output_variable}" '%s' "${staged}"
  fi
  finish_installer_signal_transaction
  [[ ${staging_failed} == false ]]
}

backup_destination() {
  local output_variable=$1
  local destination=$2
  local directory=$3
  local template=$4
  local backup="" target="" backup_failed=false

  printf -v "${output_variable}" '%s' ""
  if [[ -e ${destination} || -L ${destination} ]]; then
    reserve_path backup "${directory}" "${template}" || return 1
    begin_installer_signal_transaction
    if [[ -L ${destination} ]]; then
      if ! target=$(readlink -- "${destination}"); then
        backup_failed=true
      elif ! ln -s -- "${target}" "${backup}"; then
        backup_failed=true
      elif [[ ! -L ${backup} || $(readlink -- "${backup}") != "${target}" ]]; then
        backup_failed=true
      fi
    elif [[ -f ${destination} ]]; then
      if ! ln -- "${destination}" "${backup}"; then
        backup_failed=true
      elif [[ ! -f ${backup} || -L ${backup} ||
        $(stat -c '%d:%i' -- "${backup}") != "$(stat -c '%d:%i' -- "${destination}")" ]]; then
        backup_failed=true
      fi
    else
      backup_failed=true
    fi
    if [[ ${backup_failed} == false ]]; then
      printf -v "${output_variable}" '%s' "${backup}"
    fi
    finish_installer_signal_transaction
  fi
  [[ ${backup_failed} == false ]]
}

restore_destination() {
  local destination=$1
  local backup=$2
  local failed=false
  rm -f -- "${destination}" || failed=true
  if [[ -n ${backup} && ( -e ${backup} || -L ${backup} ) ]]; then
    mv -T -- "${backup}" "${destination}" || failed=true
  fi
  [[ ${failed} == false ]]
}

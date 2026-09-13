
rollback_state_and_backup_directories() {
  local failed=false
  if [[ ${installation_complete} == false && ${state_dir_touched} == true ]]; then
    if [[ ${state_dir_existed} == true ]]; then
      if [[ -d ${STATE_DIR} && ! -L ${STATE_DIR} &&
        $(stat -c '%d:%i' -- "${STATE_DIR}") == "${state_dir_original_identity}" ]]; then
        chown -- "${state_dir_original_uid}:${state_dir_original_gid}" "${STATE_DIR}" || \
          failed=true
        chmod -- "${state_dir_original_mode}" "${STATE_DIR}" || failed=true
        [[ $(stat -c '%d:%i:%u:%g:%a' -- "${STATE_DIR}") == \
          "${state_dir_original_identity}:${state_dir_original_uid}:${state_dir_original_gid}:${state_dir_original_mode}" ]] || \
          failed=true
      else
        failed=true
      fi
    elif [[ -e ${STATE_DIR} || -L ${STATE_DIR} ]]; then
      if [[ -d ${STATE_DIR} && ! -L ${STATE_DIR} &&
        -n ${state_dir_created_identity} &&
        $(stat -c '%d:%i' -- "${STATE_DIR}") == "${state_dir_created_identity}" &&
        -z $(find "${STATE_DIR}" -mindepth 1 -print -quit) ]]; then
        rmdir -- "${STATE_DIR}" || failed=true
      else
        failed=true
      fi
      [[ ! -e ${STATE_DIR} && ! -L ${STATE_DIR} ]] || failed=true
    fi
  fi
  if [[ ${installation_complete} == false && ${backup_dir_touched} == true ]]; then
    if [[ ${backup_dir_existed} == true ]]; then
      if [[ -d ${BACKUP_DIR} && ! -L ${BACKUP_DIR} &&
        $(stat -c '%d:%i' -- "${BACKUP_DIR}") == "${backup_dir_original_identity}" ]]; then
        chown -- "${backup_dir_original_uid}:${backup_dir_original_gid}" "${BACKUP_DIR}" || \
          failed=true
        chmod -- "${backup_dir_original_mode}" "${BACKUP_DIR}" || failed=true
        [[ $(stat -c '%d:%i:%u:%g:%a' -- "${BACKUP_DIR}") == \
          "${backup_dir_original_identity}:${backup_dir_original_uid}:${backup_dir_original_gid}:${backup_dir_original_mode}" ]] || \
          failed=true
      else
        failed=true
      fi
    elif [[ -e ${BACKUP_DIR} || -L ${BACKUP_DIR} ]]; then
      if [[ -d ${BACKUP_DIR} && ! -L ${BACKUP_DIR} &&
        -n ${backup_dir_created_identity} &&
        $(stat -c '%d:%i' -- "${BACKUP_DIR}") == "${backup_dir_created_identity}" &&
        -z $(find "${BACKUP_DIR}" -mindepth 1 -print -quit) ]]; then
        rmdir -- "${BACKUP_DIR}" || failed=true
      else
        failed=true
      fi
      [[ ! -e ${BACKUP_DIR} && ! -L ${BACKUP_DIR} ]] || failed=true
    fi
  fi
  [[ ${failed} == false ]]
}

rollback_created_managed_release() {
  local failed=false
  local public_path
  [[ ${managed_release_created} == true ]] || return 0
  [[ -n ${RELEASE_DIR} ]] || return 1
  if [[ ! -e ${RELEASE_DIR} && ! -L ${RELEASE_DIR} ]]; then
    return 0
  fi
  [[ -d ${RELEASE_DIR} && ! -L ${RELEASE_DIR} &&
    $(readlink -f -- "${RELEASE_DIR}") == "${RELEASE_DIR}" &&
    $(stat -c '%d:%i' -- "${RELEASE_DIR}") == "${managed_release_created_identity}" ]] || \
    return 1
  if [[ -L ${CURRENT_LINK} && $(readlink -f -- "${CURRENT_LINK}") == "${RELEASE_DIR}" ]]; then
    return 1
  fi
  for public_path in "${PUBLIC_BINARY}" "${PUBLIC_ALIAS}"; do
    if [[ -L ${public_path} &&
      $(readlink -f -- "${public_path}") == "${RELEASE_DIR}/${RELEASE_BINARY}" ]]; then
      return 1
    fi
  done
  rm -rf -- "${RELEASE_DIR}" || failed=true
  [[ ! -e ${RELEASE_DIR} && ! -L ${RELEASE_DIR} ]] || failed=true
  if [[ -d ${RELEASE_ROOT} && ! -L ${RELEASE_ROOT} ]]; then
    sync -f -- "${RELEASE_ROOT}" || failed=true
  fi
  [[ ${failed} == false ]]
}

rollback_journaled_directories() {
  local index path current_owner current_mode failed=false
  for ((index=${#journaled_directory_paths[@]} - 1; index >= 0; index--)); do
    path="${journaled_directory_paths[index]}"
    if [[ ${directory_existed["${path}"]} == true ]]; then
      if [[ -d ${path} && ! -L ${path} &&
        $(readlink -f -- "${path}") == "${path}" &&
        $(stat -c '%d:%i' -- "${path}") == "${directory_original_identity["${path}"]}" ]]; then
        if ! current_owner=$(stat -c '%u:%g' -- "${path}"); then
          failed=true
        elif [[ ${current_owner} != "${directory_original_owner["${path}"]}" ]]; then
          chown -- "${directory_original_owner["${path}"]}" "${path}" || failed=true
        fi
        if ! current_mode=$(stat -c '%a' -- "${path}"); then
          failed=true
        elif [[ ${current_mode} != "${directory_original_mode["${path}"]}" ]]; then
          chmod -- "${directory_original_mode["${path}"]}" "${path}" || failed=true
        fi
        [[ $(stat -c '%d:%i:%u:%g:%a' -- "${path}") == \
          "${directory_original_identity["${path}"]}:${directory_original_owner["${path}"]}:${directory_original_mode["${path}"]}" ]] || \
          failed=true
      else
        failed=true
      fi
    elif [[ -e ${path} || -L ${path} ]]; then
      if [[ -d ${path} && ! -L ${path} &&
        $(readlink -f -- "${path}") == "${path}" &&
        -n ${directory_created_identity["${path}"]-} &&
        $(stat -c '%d:%i' -- "${path}") == "${directory_created_identity["${path}"]}" ]]; then
        if [[ -z $(find "${path}" -mindepth 1 -print -quit) ]]; then
          rmdir -- "${path}" || failed=true
          [[ ! -e ${path} && ! -L ${path} ]] || failed=true
        else
          current_mode=$(stat -c '%a' -- "${path}")
          if [[ ${directory_retain_if_nonempty["${path}"]} == true &&
            $(stat -c '%U:%G' -- "${path}") == "root:root" &&
            ${current_mode} =~ ^[0-7]+$ ]] &&
            (( (8#${current_mode} & 0022) == 0 )); then
            printf 'install-autostream-observability: retaining non-empty durable backup directory after rollback: %s\n' \
              "${path}" >&2
          else
            failed=true
          fi
        fi
      else
        failed=true
      fi
    fi
  done
  [[ ${failed} == false ]]
}

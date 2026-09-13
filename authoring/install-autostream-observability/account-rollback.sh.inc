
restore_created_autostream_user_login() {
  local expected_group_record=$1
  local renamed_user_record=$2
  local expected_group_digest=$3
  local expected_gshadow_digest=$4

  [[ -z $(getent passwd autostream 2>/dev/null || true) &&
    $(getent passwd "${AUTOSTREAM_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) == \
      "${renamed_user_record}" &&
    -z $(getent group "${AUTOSTREAM_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) ]] || \
    return 1
  usermod --login autostream "${AUTOSTREAM_USER_ROLLBACK_LOGIN}" || return 1
  [[ $(getent passwd autostream 2>/dev/null || true) == \
      "${created_autostream_user_record}" &&
    -z $(getent passwd "${AUTOSTREAM_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) &&
    $(getent group autostream 2>/dev/null || true) == "${expected_group_record}" &&
    -z $(getent group "${AUTOSTREAM_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) ]] || \
    return 1
  local_account_database_matches_digests \
    "${expected_group_digest}" "${expected_gshadow_digest}"
}

remove_created_autostream_user_preserving_group() {
  local delete_status=0 expected_group_gid expected_group_record
  local group_database_digest_before gshadow_database_digest_before
  local rename_status=0 renamed_user_record user_record_suffix

  [[ ${created_autostream_user} == true &&
    ${autostream_user_rollback_login_ready} == true &&
    ${created_autostream_user_record} =~ ^autostream(:[^:]*:[1-9][0-9]*:[1-9][0-9]*:[^:]*:/var/lib/autostream:/usr/sbin/nologin)$ ]] || \
    return 1
  user_record_suffix=${BASH_REMATCH[1]}
  [[ $(getent passwd autostream 2>/dev/null || true) == \
      "${created_autostream_user_record}" &&
    $(id -u autostream 2>/dev/null || true) == "${created_autostream_user_uid}" &&
    $(id -g autostream 2>/dev/null || true) == "${created_autostream_user_gid}" &&
    $(id -Gn autostream 2>/dev/null || true) == "autostream" ]] || return 1

  if [[ ${created_autostream_group} == true ]]; then
    expected_group_record=${created_autostream_group_record}
  else
    expected_group_record=${preexisting_autostream_group_record}
  fi
  [[ -n ${expected_group_record} &&
    $(getent group autostream 2>/dev/null || true) == "${expected_group_record}" ]] || \
    return 1
  expected_group_gid=$(printf '%s\n' "${expected_group_record}" |
    awk -F: 'NR == 1 && $1 == "autostream" { print $3 }')
  [[ ${expected_group_gid} =~ ^[1-9][0-9]*$ &&
    ${created_autostream_user_gid} == "${expected_group_gid}" &&
    -z $(getent passwd "${AUTOSTREAM_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) &&
    -z $(getent group "${AUTOSTREAM_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) ]] || \
    return 1

  group_database_digest_before=$(sha256sum -- /etc/group | awk 'NR == 1 { print $1 }') || \
    return 1
  gshadow_database_digest_before=$(sha256sum -- /etc/gshadow | awk 'NR == 1 { print $1 }') || \
    return 1
  [[ ${group_database_digest_before} =~ ^[[:xdigit:]]{64}$ &&
    ${gshadow_database_digest_before} =~ ^[[:xdigit:]]{64}$ ]] || return 1
  local_account_member_fields_are_clear || return 1
  local_account_database_matches_digests \
    "${group_database_digest_before}" "${gshadow_database_digest_before}" || return 1

  # With Ubuntu's USERGROUPS_ENAB setting, userdel may also delete an empty
  # group whose name matches the login. Rename only the invocation-created
  # login so the protected autostream group cannot be selected for deletion.
  renamed_user_record="${AUTOSTREAM_USER_ROLLBACK_LOGIN}${user_record_suffix}"
  if usermod --login "${AUTOSTREAM_USER_ROLLBACK_LOGIN}" autostream; then
    rename_status=0
  else
    rename_status=$?
  fi
  if [[ ${rename_status} -ne 0 ||
    -n $(getent passwd autostream 2>/dev/null || true) ||
    $(getent passwd "${AUTOSTREAM_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) != \
      "${renamed_user_record}" ||
    $(getent group autostream 2>/dev/null || true) != "${expected_group_record}" ||
    -n $(getent group "${AUTOSTREAM_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) ]] ||
    ! local_account_database_matches_digests \
      "${group_database_digest_before}" "${gshadow_database_digest_before}"; then
    restore_created_autostream_user_login \
      "${expected_group_record}" "${renamed_user_record}" \
      "${group_database_digest_before}" "${gshadow_database_digest_before}" || true
    return 1
  fi

  if userdel "${AUTOSTREAM_USER_ROLLBACK_LOGIN}"; then
    delete_status=0
  else
    delete_status=$?
  fi
  if [[ ${delete_status} -ne 0 ]]; then
    restore_created_autostream_user_login \
      "${expected_group_record}" "${renamed_user_record}" \
      "${group_database_digest_before}" "${gshadow_database_digest_before}" || true
    return 1
  fi
  [[ -z $(getent passwd autostream 2>/dev/null || true) &&
    -z $(getent passwd "${AUTOSTREAM_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) &&
    $(getent group autostream 2>/dev/null || true) == "${expected_group_record}" &&
    -z $(getent group "${AUTOSTREAM_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) ]] || \
    return 1
  local_account_database_matches_digests \
    "${group_database_digest_before}" "${gshadow_database_digest_before}" || return 1
  created_autostream_user=false
  created_autostream_user_uid=
  created_autostream_user_gid=
  created_autostream_user_record=
}

rollback_autostream_account() {
  local failed=false current_group
  if [[ ${created_autostream_user} == true ]]; then
    remove_created_autostream_user_preserving_group || failed=true
  fi
  if [[ ${created_autostream_group} == true &&
    ${created_autostream_user} == true ]]; then
    failed=true
  elif [[ ${created_autostream_group} == true ]]; then
    current_group=$(getent group autostream 2>/dev/null || true)
    if [[ -z ${current_group} ]]; then
      :
    elif [[ ${current_group} == "${created_autostream_group_record}" &&
      $(printf '%s\n' "${current_group}" | awk -F: 'NR == 1 { print $3 }') == \
        "${created_autostream_group_gid}" ]] &&
      ! getent passwd autostream >/dev/null 2>&1; then
      groupdel autostream || failed=true
      getent group autostream >/dev/null 2>&1 && failed=true
    else
      failed=true
    fi
  fi
  [[ ${failed} == false ]]
}

verify_bound_legacy_backups() {
  local path failed=false
  for path in "${!preexisting_legacy_backup_identity[@]}"; do
    [[ -f ${path} && ! -L ${path} &&
      $(stat -c '%d:%i:%s:%Y:%Z:%f:%u:%g:%a' -- "${path}") == \
        "${preexisting_legacy_backup_identity["${path}"]}" &&
      $(sha256sum -- "${path}" | awk 'NR == 1 { print $1 }') == \
        "${preexisting_legacy_backup_digest["${path}"]}" ]] || failed=true
  done
  for path in "${!created_legacy_backup_identity[@]}"; do
    [[ -f ${path} && ! -L ${path} &&
      $(stat -c '%d:%i:%s:%Y:%Z:%f:%u:%g:%a' -- "${path}") == \
        "${created_legacy_backup_identity["${path}"]}" &&
      $(sha256sum -- "${path}" | awk 'NR == 1 { print $1 }') == \
        "${created_legacy_backup_digest["${path}"]}" ]] || failed=true
  done
  [[ ${failed} == false ]]
}

cleanup_temporary_rollback_paths() {
  local index path failed=false
  for ((index=${#temporary_rollback_paths[@]} - 1; index >= 0; index--)); do
    path="${temporary_rollback_paths[index]}"
    if [[ -e ${path} || -L ${path} ]]; then
      rm -f -- "${path}" || failed=true
      [[ ! -e ${path} && ! -L ${path} ]] || failed=true
    fi
  done
  [[ ${failed} == false ]]
}

remove_transaction_stage_directory() {
  local path=$1
  local expected_identity=$2
  [[ -n ${path} ]] || return 0
  if [[ ! -e ${path} && ! -L ${path} ]]; then
    return 0
  fi
  [[ -n ${expected_identity} &&
    -d ${path} &&
    ! -L ${path} &&
    $(readlink -f -- "${path}") == "${path}" &&
    $(stat -c '%d:%i' -- "${path}") == "${expected_identity}" ]] || \
    return 1
  rm -rf -- "${path}" || return 1
  [[ ! -e ${path} && ! -L ${path} ]]
}

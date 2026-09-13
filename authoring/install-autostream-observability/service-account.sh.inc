
local_account_member_fields_are_clear() {
  [[ -f /etc/group && ! -L /etc/group && -r /etc/group &&
    -f /etc/gshadow && ! -L /etc/gshadow && -r /etc/gshadow ]] || return 1
  awk -F: \
    -v service_login="autostream" \
    -v rollback_login="${AUTOSTREAM_USER_ROLLBACK_LOGIN}" \
    '{
      count = split($4, members, ",")
      for (member_index = 1; member_index <= count; member_index++) {
        if (members[member_index] == service_login || members[member_index] == rollback_login) {
          exit 1
        }
      }
    }' /etc/group || return 1
  awk -F: \
    -v service_login="autostream" \
    -v rollback_login="${AUTOSTREAM_USER_ROLLBACK_LOGIN}" \
    '{
      admin_count = split($3, admins, ",")
      for (admin_index = 1; admin_index <= admin_count; admin_index++) {
        if (admins[admin_index] == service_login || admins[admin_index] == rollback_login) {
          exit 1
        }
      }
      member_count = split($4, members, ",")
      for (member_index = 1; member_index <= member_count; member_index++) {
        if (members[member_index] == service_login || members[member_index] == rollback_login) {
          exit 1
        }
      }
    }' /etc/gshadow
}

local_account_database_matches_digests() {
  local expected_group_digest=$1
  local expected_gshadow_digest=$2
  local group_digest gshadow_digest

  group_digest=$(sha256sum -- /etc/group | awk 'NR == 1 { print $1 }') || return 1
  gshadow_digest=$(sha256sum -- /etc/gshadow | awk 'NR == 1 { print $1 }') || return 1
  [[ ${group_digest} =~ ^[[:xdigit:]]{64}$ &&
    ${gshadow_digest} =~ ^[[:xdigit:]]{64}$ &&
    ${group_digest} == "${expected_group_digest}" &&
    ${gshadow_digest} == "${expected_gshadow_digest}" ]]
}

prepare_autostream_user_rollback_login() {
  [[ -z $(getent passwd "${AUTOSTREAM_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) &&
    -z $(getent group "${AUTOSTREAM_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) ]] || \
    return 1
  local_account_member_fields_are_clear || return 1
  autostream_user_rollback_login_ready=true
}

preflight_autostream_account() {
  local autostream_group_gid existing_uid existing_gid
  if getent group autostream >/dev/null 2>&1; then
    preexisting_autostream_group_record=$(getent group autostream) || \
      die "could not capture the pre-existing autostream service group"
    [[ -n ${preexisting_autostream_group_record} ]] || \
      die "could not capture the pre-existing autostream service group"
    autostream_group_gid=$(printf '%s\n' "${preexisting_autostream_group_record}" |
      awk -F: 'NR == 1 { print $3 }')
    [[ ${autostream_group_gid} =~ ^[0-9]+$ && ${autostream_group_gid} -ne 0 ]] || \
      die "autostream service group must have a non-root numeric GID"
  else
    if getent passwd autostream >/dev/null 2>&1 || id autostream >/dev/null 2>&1; then
      die "autostream service account exists without the autostream group"
    fi
    prepare_autostream_user_rollback_login || \
      die "could not reserve a safe service-account rollback login"
    return 0
  fi

  if getent passwd autostream >/dev/null 2>&1 || id autostream >/dev/null 2>&1; then
    existing_uid=$(id -u autostream)
    existing_gid=$(id -g autostream)
    [[ ${existing_uid} =~ ^[0-9]+$ && ${existing_uid} -ne 0 ]] || \
      die "autostream service account must have a non-root numeric UID"
    [[ ${existing_gid} == "${autostream_group_gid}" ]] || \
      die "autostream service account numeric primary GID does not match the autostream group"
    [[ $(id -gn autostream) == "autostream" ]] || \
      die "autostream service account must use the autostream primary group"
  else
    prepare_autostream_user_rollback_login || \
      die "could not reserve a safe service-account rollback login"
  fi
}

ensure_autostream_account() {
  local autostream_group_gid account_creation_failed=false
  if ! getent group autostream >/dev/null 2>&1; then
    begin_installer_signal_transaction
    if ! groupadd --system autostream; then
      account_creation_failed=true
    else
      created_autostream_group=true
      if ! created_autostream_group_record=$(getent group autostream); then
        account_creation_failed=true
      elif ! created_autostream_group_gid=$(printf '%s\n' "${created_autostream_group_record}" |
        awk -F: 'NR == 1 { print $3 }'); then
        account_creation_failed=true
      fi
    fi
    finish_installer_signal_transaction
    [[ ${account_creation_failed} == false ]] || \
      die "could not create and journal the autostream service group"
  fi
  autostream_group_gid=$(getent group autostream | awk -F: 'NR == 1 { print $3 }')
  [[ ${autostream_group_gid} =~ ^[0-9]+$ && ${autostream_group_gid} -ne 0 ]] || \
    die "autostream service group must have a non-root numeric GID"
  if [[ ${created_autostream_group} == true ]]; then
    [[ ${created_autostream_group_gid} == "${autostream_group_gid}" ]] || \
      die "created autostream service group identity changed during provisioning"
    [[ $(getent group autostream) == "${created_autostream_group_record}" ]] || \
      die "created autostream service group changed before user provisioning"
  else
    [[ -n ${preexisting_autostream_group_record} &&
      $(getent group autostream) == "${preexisting_autostream_group_record}" ]] || \
      die "pre-existing autostream service group changed before user provisioning"
  fi
  if ! id autostream >/dev/null 2>&1; then
    [[ ${autostream_user_rollback_login_ready} == true &&
      -z $(getent passwd "${AUTOSTREAM_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) &&
      -z $(getent group "${AUTOSTREAM_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) ]] || \
      die "service-account rollback login changed before user provisioning"
    local_account_member_fields_are_clear || \
      die "service-account names are referenced by local group membership state"
    account_creation_failed=false
    begin_installer_signal_transaction
    if ! useradd \
      --system \
      --gid "${autostream_group_gid}" \
      --home-dir /var/lib/autostream \
      --no-create-home \
      --shell /usr/sbin/nologin \
      autostream; then
      account_creation_failed=true
    else
      created_autostream_user=true
      if ! created_autostream_user_uid=$(id -u autostream); then
        account_creation_failed=true
      elif ! created_autostream_user_gid=$(id -g autostream); then
        account_creation_failed=true
      elif ! created_autostream_user_record=$(getent passwd autostream); then
        account_creation_failed=true
      fi
    fi
    finish_installer_signal_transaction
    [[ ${account_creation_failed} == false ]] || \
      die "could not create and journal the autostream service account"
  fi

  [[ $(id -u autostream) =~ ^[0-9]+$ && $(id -u autostream) -ne 0 ]] || \
    die "autostream service account must have a non-root numeric UID"
  [[ $(id -g autostream) == "${autostream_group_gid}" ]] || \
    die "autostream service account numeric primary GID does not match the autostream group"
  [[ $(id -gn autostream) == "autostream" ]] || \
    die "autostream service account must use the autostream primary group"
}

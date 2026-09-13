
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
preexisting_group_database_digest="$(sha256sum -- /etc/group | awk 'NR == 1 { print $1 }')"
preexisting_gshadow_database_digest="$(sha256sum -- /etc/gshadow | awk 'NR == 1 { print $1 }')"
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
[[ $(sha256sum -- /etc/group | awk 'NR == 1 { print $1 }') == \
    "${preexisting_group_database_digest}" &&
  $(sha256sum -- /etc/gshadow | awk 'NR == 1 { print $1 }') == \
    "${preexisting_gshadow_database_digest}" ]] || \
  die "useradd TERM transaction changed the pre-existing local group databases"
if getent passwd autostream-install-rollback >/dev/null 2>&1 ||
  getent group autostream-install-rollback >/dev/null 2>&1; then
  die "useradd TERM transaction retained the reserved rollback account name"
fi
assert_signal_setup_paths_rolled_back "useradd TERM transaction"
groupdel autostream


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

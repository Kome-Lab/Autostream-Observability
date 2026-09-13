
"${EXTRACTED_ROOT}/install-autostream-observability" > "${WORK_DIR}/migration.out"
replace_owned_runtime_unit_atomically "${UNIT_PATH}"
systemctl daemon-reload
assert_loaded_runtime_unit "${PUBLIC_BINARY}" "autostream" "successful migration"
[[ $(sha256sum "${RUNTIME_UNIT_PATH}" | awk 'NR == 1 { print $1 }') == \
  "$(sha256sum "${UNIT_PATH}" | awk 'NR == 1 { print $1 }')" ]] || \
  die "successful migration did not synchronize the managed runtime unit"
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
[[ $(sha256sum "${STATE_SENTINEL}" | awk 'NR == 1 { print $1 }') == \
  "${state_sentinel_before}" ]] || \
  die "successful migration changed existing state content"
state_metadata_before="$(stat -c '%u:%g:%a' -- "${STATE_DIR}")"
grep -F -- "sudo systemctl restart autostream-observability" \
  "${WORK_DIR}/migration.out" >/dev/null || \
  die "active migration did not print the explicit restart command"
[[ $(systemctl show --property MainPID --value "${UNIT}") == "${old_pid}" ]] || \
  die "successful migration replaced the running legacy process"
kill -0 "${old_pid}" || die "successful migration stopped the running legacy process"
systemctl is-enabled --quiet "${UNIT}" && die "successful migration unexpectedly enabled the service"

managed_release_dir="${MANAGED_ROOT}/releases/${VERSION}-${archive_sha256:0:12}"
printf '%s\n' "not declared by trusted checksums" > "${managed_release_dir}/unexpected.txt"
set +e
"${EXTRACTED_ROOT}/install-autostream-observability" \
  > "${WORK_DIR}/existing-release-extra-file.out" 2>&1
existing_release_extra_file_status=$?
set -e
[[ ${existing_release_extra_file_status} -ne 0 ]] || \
  die "existing release with an extra regular file unexpectedly succeeded"
grep -F -- "existing managed release checksum inventory is incomplete or unsafe" \
  "${WORK_DIR}/existing-release-extra-file.out" >/dev/null || \
  die "existing release extra file did not fail exact trusted checksum inventory validation"
[[ $(systemctl show --property MainPID --value "${UNIT}") == "${old_pid}" ]] || \
  die "existing release extra file validation replaced the running legacy process"
assert_state_preserved "existing release extra file validation"
rm -f -- "${managed_release_dir}/unexpected.txt"

ln -s -- /etc/passwd "${managed_release_dir}/unexpected-link"
set +e
"${EXTRACTED_ROOT}/install-autostream-observability" \
  > "${WORK_DIR}/existing-release-symlink.out" 2>&1
existing_release_symlink_status=$?
set -e
[[ ${existing_release_symlink_status} -ne 0 ]] || \
  die "existing release with a symlink unexpectedly succeeded"
grep -F -- "existing managed release contains a link or special entry" \
  "${WORK_DIR}/existing-release-symlink.out" >/dev/null || \
  die "existing release symlink did not report the expected failure"
assert_state_preserved "existing release symlink validation"
rm -f -- "${managed_release_dir}/unexpected-link"

mkfifo "${managed_release_dir}/unexpected-fifo"
set +e
"${EXTRACTED_ROOT}/install-autostream-observability" \
  > "${WORK_DIR}/existing-release-special.out" 2>&1
existing_release_special_status=$?
set -e
[[ ${existing_release_special_status} -ne 0 ]] || \
  die "existing release with a special entry unexpectedly succeeded"
grep -F -- "existing managed release contains a link or special entry" \
  "${WORK_DIR}/existing-release-special.out" >/dev/null || \
  die "existing release special entry did not report the expected failure"
assert_state_preserved "existing release special-entry validation"
rm -f -- "${managed_release_dir}/unexpected-fifo"

printf '%s\n' "permanent updater lock sentinel" > "${TARGET_LOCK}"
lock_identity_before_reinstall="$(stat -c '%d:%i:%u:%g:%a' -- "${TARGET_LOCK}")"
lock_digest_before_reinstall="$(sha256sum -- "${TARGET_LOCK}" | awk 'NR == 1 { print $1 }')"
"${EXTRACTED_ROOT}/install-autostream-observability" > "${WORK_DIR}/idempotent.out"
[[ $(stat -c '%d:%i:%u:%g:%a' -- "${TARGET_LOCK}") == "${lock_identity_before_reinstall}" ]] || \
  die "idempotent reinstall changed the permanent lock inode or metadata"
[[ $(sha256sum -- "${TARGET_LOCK}" | awk 'NR == 1 { print $1 }') == \
  "${lock_digest_before_reinstall}" ]] || \
  die "idempotent reinstall truncated or changed the permanent lock content"
[[ $(systemctl show --property MainPID --value "${UNIT}") == "${old_pid}" ]] || \
  die "idempotent reinstall replaced the running legacy process"
assert_loaded_runtime_unit "${PUBLIC_BINARY}" "autostream" "idempotent reinstall"
[[ $(sha256sum "${RUNTIME_UNIT_PATH}" | awk 'NR == 1 { print $1 }') == \
  "$(sha256sum "${UNIT_PATH}" | awk 'NR == 1 { print $1 }')" ]] || \
  die "idempotent reinstall changed the loaded runtime unit"
[[ $(sha256sum "${ENV_PATH}" | awk 'NR == 1 { print $1 }') == "${env_before}" ]] || \
  die "idempotent reinstall changed the existing environment"
[[ $(sha256sum "${MARIADB_DEFAULTS}" | awk 'NR == 1 { print $1 }') == "${db_before}" ]] || \
  die "idempotent reinstall changed the existing MariaDB defaults"
assert_state_preserved "idempotent reinstall"
systemctl is-enabled --quiet "${UNIT}" && die "idempotent reinstall unexpectedly enabled the service"

(
  exec 8<>"${TARGET_LOCK}"
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
[[ $(stat -c '%d:%i:%u:%g:%a' -- "${TARGET_LOCK}") == "${lock_identity_before_reinstall}" ]] || \
  die "lock contention changed the permanent lock inode or metadata"
[[ $(sha256sum -- "${TARGET_LOCK}" | awk 'NR == 1 { print $1 }') == \
  "${lock_digest_before_reinstall}" ]] || \
  die "lock contention truncated or changed the permanent lock content"
[[ $(systemctl show --property MainPID --value "${UNIT}") == "${old_pid}" ]] || \
  die "lock contention changed the running legacy process"
kill -0 "${old_pid}" || die "lock contention stopped the running legacy process"

printf '%s\n' "Observability installer integration scenarios passed."

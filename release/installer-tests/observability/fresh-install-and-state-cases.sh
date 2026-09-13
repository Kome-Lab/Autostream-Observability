
"${EXTRACTED_ROOT}/install-autostream-observability" > "${WORK_DIR}/fresh.out"
[[ $(stat -c '%d:%i' -- "${TARGET_LOCK}") == "${lock_identity_after_rollback}" ]] || \
  die "fresh install replaced the permanent updater lock inode"
[[ $(stat -c '%d:%i' -- "${SHARED_HOST_SETUP_LOCK}") == \
  "${shared_lock_identity_after_rollback}" ]] || \
  die "fresh install replaced the permanent shared host-setup lock inode"
[[ -L ${MANAGED_ROOT}/current ]] || die "fresh install did not create the managed current link"
[[ -L ${PUBLIC_BINARY} && -L ${PUBLIC_ALIAS} ]] || \
  die "fresh install did not install stable public links"
[[ -f ${ENV_PATH} && ! -L ${ENV_PATH} ]] || die "fresh install did not seed the environment"
[[ -f ${MARIADB_DEFAULTS} && ! -L ${MARIADB_DEFAULTS} ]] || \
  die "fresh install did not seed the MariaDB defaults"
[[ $(stat -c '%U:%G:%a' -- "${ENV_PATH}") == "root:root:640" ]] || \
  die "fresh environment ownership or mode is invalid"
[[ $(stat -c '%U:%G:%a' -- "${MARIADB_DEFAULTS}") == "root:root:600" ]] || \
  die "fresh MariaDB defaults ownership or mode is invalid"
[[ $(stat -c '%U:%G:%a' -- "${STATE_DIR}") == "autostream:autostream:750" ]] || \
  die "fresh state ownership or mode is invalid"
id autostream >/dev/null 2>&1 || die "fresh installer did not create the autostream account"
systemctl is-active --quiet "${UNIT}" && die "fresh installer unexpectedly started the service"
systemctl is-enabled --quiet "${UNIT}" && die "fresh installer unexpectedly enabled the service"
grep -F -- "sudo systemctl enable --now autostream-observability" \
  "${WORK_DIR}/fresh.out" >/dev/null || \
  die "fresh install did not print the explicit start command"

rm -f -- \
  "${PUBLIC_BINARY}" \
  "${PUBLIC_ALIAS}" \
  "${ENV_PATH}" \
  "${UNIT_PATH}" \
  "${BACKUP_EXECUTABLE}" \
  "${MARIADB_DEFAULTS}" \
  "${SHARED_HOST_SETUP_LOCK}" \
  "${TARGET_LOCK}"
rm -rf -- \
  "${STATE_DIR}" \
  "${MANAGED_ROOT}" \
  "${DATABASE_BACKUP_DIR}" \
  "${INSTALL_BACKUP_ROOT}"
systemctl daemon-reload
rmdir \
  /var/backups/autostream/install-migrations \
  /var/backups/autostream \
  /var/lib/autostream \
  /opt/autostream \
  /etc/autostream \
  /etc/autostream-local-executor \
  /run/autostream-updater >/dev/null 2>&1 || \
  die "fresh-install reset left an unexpected directory"
userdel autostream
if getent group autostream >/dev/null 2>&1; then
  groupdel autostream
fi
[[ ! -e ${MANAGED_ROOT} && ! -L ${MANAGED_ROOT} ]] || \
  die "fresh-install reset retained the managed root"
if id autostream >/dev/null 2>&1 || getent group autostream >/dev/null 2>&1; then
  die "fresh-install reset retained the autostream account"
fi

install -d -o root -g root -m 0750 /etc/autostream
printf '%s\n' "invalid preflight mode before account creation" > "${ENV_PATH}"
chmod 0600 "${ENV_PATH}"
set +e
"${EXTRACTED_ROOT}/install-autostream-observability" \
  > "${WORK_DIR}/fresh-late-preflight-failure.out" 2>&1
fresh_late_preflight_status=$?
set -e
[[ ${fresh_late_preflight_status} -ne 0 ]] || \
  die "fresh late preflight failure unexpectedly succeeded"
grep -F -- "${ENV_PATH} owner or mode is invalid" \
  "${WORK_DIR}/fresh-late-preflight-failure.out" >/dev/null || \
  die "fresh late preflight failure did not reach existing environment validation"
if id autostream >/dev/null 2>&1 || getent group autostream >/dev/null 2>&1; then
  die "fresh late preflight failure created the autostream account"
fi
for unexpected_path in \
  /opt/autostream \
  "${MANAGED_ROOT}" \
  /var/lib/autostream \
  "${STATE_DIR}" \
  /var/backups/autostream \
  "${DATABASE_BACKUP_DIR}" \
  "${INSTALL_BACKUP_ROOT}" \
  /etc/autostream-local-executor \
  "${MARIADB_DEFAULTS}" \
  "${SHARED_HOST_SETUP_LOCK}" \
  "${TARGET_LOCK}" \
  /run/autostream-updater; do
  [[ ! -e ${unexpected_path} && ! -L ${unexpected_path} ]] || \
    die "fresh late preflight failure created ${unexpected_path}"
done
rm -f -- "${ENV_PATH}"

groupadd --system autostream
useradd --system --gid autostream --home-dir /var/lib/autostream \
  --no-create-home --shell /usr/sbin/nologin autostream
install -d -o root -g root -m 0755 /etc/autostream /var/lib/autostream
install -d -o autostream -g autostream -m 0700 "${STATE_DIR}"
printf '%s\n' "preserve state exactly across a later preflight failure" > "${STATE_SENTINEL}"
chown autostream:autostream "${STATE_SENTINEL}"
chmod 0600 "${STATE_SENTINEL}"
state_identity_before="$(stat -c '%d:%i' -- "${STATE_DIR}")"
state_metadata_before="$(stat -c '%u:%g:%a' -- "${STATE_DIR}")"
state_sentinel_before="$(sha256sum "${STATE_SENTINEL}" | awk 'NR == 1 { print $1 }')"
printf '%s\n' "invalid preflight mode" > "${ENV_PATH}"
chmod 0600 "${ENV_PATH}"

set +e
"${EXTRACTED_ROOT}/install-autostream-observability" \
  > "${WORK_DIR}/state-preflight-failure.out" 2>&1
state_preflight_status=$?
set -e
[[ ${state_preflight_status} -ne 0 ]] || \
  die "late preflight failure with existing state unexpectedly succeeded"
grep -F -- "${ENV_PATH} owner or mode is invalid" \
  "${WORK_DIR}/state-preflight-failure.out" >/dev/null || \
  die "late preflight failure did not reach existing environment validation"
assert_state_preserved "late preflight failure"

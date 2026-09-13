
MANAGED_STAGE_DIR=
create_bound_stage_directory \
  MANAGED_STAGE_DIR \
  managed_stage_dir_identity \
  "${MANAGED_ROOT}/.install.XXXXXX" \
  "${MANAGED_ROOT}/.install." \
  "${MANAGED_ROOT}" || \
  die "failed to create installer staging directory"
[[ -n ${MANAGED_STAGE_DIR} &&
  ${MANAGED_STAGE_DIR} == "${MANAGED_ROOT}/.install."* &&
  -d ${MANAGED_STAGE_DIR} &&
  ! -L ${MANAGED_STAGE_DIR} ]] || \
  die "installer staging directory is invalid"
readonly MANAGED_STAGE_DIR
chmod 0755 "${MANAGED_STAGE_DIR}"
readonly EXTRACT_DIR="${MANAGED_STAGE_DIR}/release"
install -d -o root -g root -m 0755 "${EXTRACT_DIR}"

if [[ ${state_dir_existed} == false || ${state_dir_original_mode} != "750" ]]; then
  state_dir_touched=true
  ensure_exact_directory "${STATE_DIR}" autostream autostream 0750 "${STATE_DIR}"
  if [[ ${state_dir_existed} == false ]]; then
    state_dir_created_identity=$(stat -c '%d:%i' -- "${STATE_DIR}")
  fi
fi
if [[ ${backup_dir_existed} == false || ${backup_dir_original_mode} != "700" ]]; then
  backup_dir_touched=true
  ensure_exact_directory "${BACKUP_DIR}" root root 0700 "${BACKUP_DIR}"
  if [[ ${backup_dir_existed} == false ]]; then
    backup_dir_created_identity=$(stat -c '%d:%i' -- "${BACKUP_DIR}")
  fi
fi

ensure_root_only_directory "${INSTALL_BACKUP_DIR}" true
retain_legacy_file \
  "${legacy_binary_regular}" "${PUBLIC_BINARY}" "${LEGACY_BINARY_BACKUP}" "legacy binary"
retain_legacy_file \
  "${legacy_alias_regular}" "${PUBLIC_ALIAS}" "${LEGACY_ALIAS_BACKUP}" "legacy alias"
retain_legacy_file \
  "${legacy_unit_regular}" "${UNIT_DEST}" "${LEGACY_UNIT_BACKUP}" "legacy systemd unit"
retain_legacy_file \
  "${legacy_backup_exec_regular}" "${BACKUP_DEST}" "${LEGACY_BACKUP_EXEC_BACKUP}" \
  "legacy backup executable"

tar \
  --extract \
  --gzip \
  --file "${STAGED_ARCHIVE}" \
  --directory "${EXTRACT_DIR}" \
  --strip-components=1 \
  --no-same-owner \
  --no-same-permissions \
  --delay-directory-restore

if find "${EXTRACT_DIR}" -type l -print -quit | grep -q .; then
  die "extracted release contains a symlink"
fi
for required in \
  "${RELEASE_BINARY}" \
  "bin/observability" \
  "${BACKUP_SOURCE_REL}" \
  ".env.example" \
  "systemd/autostream-observability.service.example" \
  "README.install.md" \
  "${ARTIFACT_MANIFEST_REL}" \
  "checksums.txt" \
  "install-autostream-observability"; do
  [[ -f ${EXTRACT_DIR}/${required} && ! -L ${EXTRACT_DIR}/${required} ]] || \
    die "release archive is missing ${required}"
done
[[ ! -e ${EXTRACT_DIR}/.artifact-sha256 && ! -L ${EXTRACT_DIR}/.artifact-sha256 ]] || \
  die "release archive must not provide .artifact-sha256"
[[ ! -e ${EXTRACT_DIR}/.version && ! -L ${EXTRACT_DIR}/.version ]] || \
  die "release archive must not provide .version"
validate_checksum_inventory \
  "${EXTRACT_DIR}" \
  "${MANAGED_STAGE_DIR}/candidate-checksums" || \
  die "managed release candidate checksum inventory is incomplete or unsafe"
(
  cd -- "${EXTRACT_DIR}"
  sha256sum --check --strict checksums.txt
) || die "managed release candidate content verification failed"
cmp -s \
  "${PREFLIGHT_EXTRACT_DIR}/checksums.txt" \
  "${EXTRACT_DIR}/checksums.txt" || \
  die "managed release candidate checksums differ from the preflight release"
cmp -s \
  "${PREFLIGHT_EXTRACT_DIR}/${ARTIFACT_MANIFEST_REL}" \
  "${EXTRACT_DIR}/${ARTIFACT_MANIFEST_REL}" || \
  die "managed release candidate manifest differs from the preflight release"
validate_artifact_manifest "${EXTRACT_DIR}/${ARTIFACT_MANIFEST_REL}" || \
  die "managed release candidate artifact manifest is invalid"

chown -R root:root "${EXTRACT_DIR}"
find "${EXTRACT_DIR}" -type d -exec chmod 0755 {} +
find "${EXTRACT_DIR}" -type f -exec chmod 0644 {} +
chmod 0755 \
  "${EXTRACT_DIR}/${RELEASE_BINARY}" \
  "${EXTRACT_DIR}/bin/observability" \
  "${EXTRACT_DIR}/${BACKUP_SOURCE_REL}" \
  "${EXTRACT_DIR}/install-autostream-observability"

version_output=$(runuser -u autostream -- "${EXTRACT_DIR}/${RELEASE_BINARY}" --version) || \
  die "managed release candidate binary identity probe failed"
[[ ${version_output} == "${EXPECTED_BINARY_IDENTITY}" ]] || \
  die "managed release candidate binary identity does not match the artifact manifest"

printf '%s\n' "${ARCHIVE_DIGEST}" >"${EXTRACT_DIR}/.artifact-sha256"
printf '%s\n' "${VERSION}" >"${EXTRACT_DIR}/.version"
chown root:root "${EXTRACT_DIR}/.artifact-sha256" "${EXTRACT_DIR}/.version"
chmod 0444 "${EXTRACT_DIR}/.artifact-sha256" "${EXTRACT_DIR}/.version"

readonly RELEASE_DIR="${RELEASE_ROOT}/${VERSION}-${ARCHIVE_DIGEST:0:12}"
if [[ -e ${RELEASE_DIR} || -L ${RELEASE_DIR} ]]; then
  validate_release_tree \
    "${RELEASE_DIR}" \
    "${EXTRACT_DIR}/checksums.txt" \
    "${MANAGED_STAGE_DIR}/existing-release-checksums"
else
  begin_installer_signal_transaction
  mv -T -- "${EXTRACT_DIR}" "${RELEASE_DIR}"
  managed_release_created=true
  managed_release_created_identity=$(stat -c '%d:%i' -- "${RELEASE_DIR}")
  finish_installer_signal_transaction
  validate_release_tree \
    "${RELEASE_DIR}" \
    "${RELEASE_DIR}/checksums.txt" \
    "${MANAGED_STAGE_DIR}/new-release-checksums"
fi
managed_version_output=$(runuser -u autostream -- "${RELEASE_DIR}/${RELEASE_BINARY}" --version) || \
  die "managed release binary identity probe failed"
[[ ${managed_version_output} == "${EXPECTED_BINARY_IDENTITY}" ]] || \
  die "managed release binary identity does not match the artifact manifest"

stage_symlink \
  binary_stage \
  "${CURRENT_LINK}/${RELEASE_BINARY}" \
  /usr/local/bin \
  ".autostream-observability.next" || \
  die "failed to stage the public binary link"
stage_symlink alias_stage "${PUBLIC_BINARY}" /usr/local/bin ".observability.next" || \
  die "failed to stage the public alias link"
reserve_path unit_stage /etc/systemd/system ".autostream-observability.service.next" || \
  die "failed to reserve the systemd unit staging path"
install \
  -o root -g root -m 0644 \
  "${RELEASE_DIR}/systemd/autostream-observability.service.example" \
  "${unit_stage}"
grep -Fqx 'ExecStart=/usr/local/bin/autostream-observability' "${unit_stage}" || \
  die "release systemd unit does not use the stable public binary path"

reserve_path backup_exec_stage /usr/local/sbin ".autostream-backup-observability.next" || \
  die "failed to reserve the backup executable staging path"
install -o root -g root -m 0700 "${RELEASE_DIR}/${BACKUP_SOURCE_REL}" "${backup_exec_stage}"

if [[ ${env_existed} == false ]]; then
  reserve_path env_stage /etc/autostream ".observability.env.next" || \
    die "failed to reserve the environment staging path"
  install -o root -g root -m 0640 "${RELEASE_DIR}/.env.example" "${env_stage}"
fi
if [[ ${backup_config_existed} == false ]]; then
  reserve_path \
    backup_config_stage \
    "${BACKUP_CONFIG_DIR}" \
    ".mariadb-backup.cnf.next" || \
    die "failed to reserve the MariaDB backup config staging path"
  install -o root -g root -m 0600 /dev/null "${backup_config_stage}"
fi

if [[ -L ${CURRENT_LINK} ]]; then
  current_original_exists=true
  current_original_target=$(readlink -- "${CURRENT_LINK}")
fi
stage_symlink current_stage "${RELEASE_DIR}" "${MANAGED_ROOT}" ".current.next" || \
  die "failed to stage the current release link"

commit_started=true
backup_destination \
  binary_backup \
  "${PUBLIC_BINARY}" \
  /usr/local/bin \
  ".autostream-observability.backup" || \
  die "failed to snapshot the existing public binary"
binary_quiesced=true
backup_destination alias_backup "${PUBLIC_ALIAS}" /usr/local/bin ".observability.backup" || \
  die "failed to snapshot the existing public alias"
alias_quiesced=true
backup_destination \
  unit_backup \
  "${UNIT_DEST}" \
  /etc/systemd/system \
  ".autostream-observability.service.backup" || \
  die "failed to snapshot the existing systemd unit"
unit_quiesced=true
backup_destination \
  backup_exec_backup \
  "${BACKUP_DEST}" \
  /usr/local/sbin \
  ".autostream-backup-observability.backup" || \
  die "failed to snapshot the existing backup executable"
backup_exec_quiesced=true

begin_installer_signal_transaction
mv -Tf -- "${current_stage}" "${CURRENT_LINK}"
current_stage=
current_switched=true

mv -Tf -- "${binary_stage}" "${PUBLIC_BINARY}"
binary_stage=
binary_activated=true
mv -Tf -- "${alias_stage}" "${PUBLIC_ALIAS}"
alias_stage=
alias_activated=true
mv -Tf -- "${backup_exec_stage}" "${BACKUP_DEST}"
backup_exec_stage=
backup_exec_activated=true
mv -Tf -- "${unit_stage}" "${UNIT_DEST}"
unit_stage=
unit_activated=true
if [[ ${env_existed} == false ]]; then
  mv -T -- "${env_stage}" "${ENV_DEST}"
  env_stage=
  env_created=true
  env_created_identity=$(stat -c '%d:%i:%s:%Y:%Z:%f:%u:%g:%a' -- "${ENV_DEST}")
  env_created_digest=$(sha256sum -- "${ENV_DEST}" | awk 'NR == 1 { print $1 }')
fi
if [[ ${backup_config_existed} == false ]]; then
  mv -T -- "${backup_config_stage}" "${BACKUP_CONFIG_DEST}"
  backup_config_stage=
  backup_config_created=true
  backup_config_created_identity=$(stat -c '%d:%i:%s:%Y:%Z:%f:%u:%g:%a' -- "${BACKUP_CONFIG_DEST}")
  backup_config_created_digest=$(sha256sum -- "${BACKUP_CONFIG_DEST}" | awk 'NR == 1 { print $1 }')
fi
finish_installer_signal_transaction

systemctl daemon-reload

[[ -L ${CURRENT_LINK} && $(readlink -f -- "${CURRENT_LINK}") == "${RELEASE_DIR}" ]] || \
  die "current release link verification failed"
[[ -L ${PUBLIC_BINARY} &&
  $(readlink -- "${PUBLIC_BINARY}") == "${CURRENT_LINK}/${RELEASE_BINARY}" ]] || \
  die "public binary link verification failed"
[[ $(readlink -f -- "${PUBLIC_BINARY}") == "${RELEASE_DIR}/${RELEASE_BINARY}" ]] || \
  die "public binary does not resolve to the selected release"
[[ -L ${PUBLIC_ALIAS} && $(readlink -- "${PUBLIC_ALIAS}") == "${PUBLIC_BINARY}" ]] || \
  die "public alias link verification failed"
[[ -f ${BACKUP_DEST} && ! -L ${BACKUP_DEST} &&
  $(stat -c '%U:%G:%a' -- "${BACKUP_DEST}") == "root:root:700" ]] || \
  die "backup executable verification failed"
[[ -f ${UNIT_DEST} && ! -L ${UNIT_DEST} &&
  $(stat -c '%U:%G:%a' -- "${UNIT_DEST}") == "root:root:644" ]] || \
  die "systemd unit verification failed"
validate_secure_existing_file "${ENV_DEST}" "root:root:640" "${ENV_DEST}"
validate_secure_existing_file "${BACKUP_CONFIG_DEST}" "root:root:600" "${BACKUP_CONFIG_DEST}"
if [[ ${env_existed} == true ]]; then
  [[ $(sha256sum -- "${ENV_DEST}" | awk 'NR == 1 { print $1 }') == "${env_sha_before}" ]] || \
    die "existing environment file changed during installation"
fi
if [[ ${backup_config_existed} == true ]]; then
  [[ $(sha256sum -- "${BACKUP_CONFIG_DEST}" | awk 'NR == 1 { print $1 }') == "${backup_config_sha_before}" ]] || \
    die "existing MariaDB backup config changed during installation"
fi

if [[ ${legacy_binary_regular} == true ]]; then
  validate_replaceable_regular_file "${LEGACY_BINARY_BACKUP}" "retained legacy binary"
fi
if [[ ${legacy_alias_regular} == true ]]; then
  validate_replaceable_regular_file "${LEGACY_ALIAS_BACKUP}" "retained legacy alias"
fi
if [[ ${legacy_unit_regular} == true ]]; then
  validate_replaceable_regular_file "${LEGACY_UNIT_BACKUP}" "retained legacy systemd unit"
fi
if [[ ${legacy_backup_exec_regular} == true ]]; then
  validate_replaceable_regular_file \
    "${LEGACY_BACKUP_EXEC_BACKUP}" "retained legacy backup executable"
fi

sync_required_directories \
  / \
  /opt \
  /opt/autostream \
  "${MANAGED_ROOT}" \
  "${RELEASE_ROOT}" \
  "${RELEASE_DIR}" \
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
  "${INSTALL_BACKUP_DIR}" \
  "${BACKUP_DIR}" \
  /run \
  /run/autostream-updater || \
  die "failed to synchronize installed filesystem state"
installation_complete=true
rm -f -- "${binary_backup}" "${alias_backup}" "${unit_backup}" "${backup_exec_backup}"
binary_backup=
alias_backup=
unit_backup=
backup_exec_backup=

printf 'Installed AutoStream Observability %s for %s.\n' "${VERSION}" "${ARCH}"
printf 'Preserved updater rollback state under %s (installer-owned).\n' "${MANAGED_ROOT}"
if [[ ${legacy_install_detected} == true ]]; then
  printf 'Retained direct-install files under %s.\n' "${INSTALL_BACKUP_DIR}"
fi
printf 'Review %s and %s, then configure the node.\n' "${ENV_DEST}" "${BACKUP_CONFIG_DEST}"
if [[ ${service_was_active} == true ]]; then
  printf 'Then run: sudo systemctl restart autostream-observability\n'
else
  printf 'Then run: sudo systemctl enable --now autostream-observability\n'
fi

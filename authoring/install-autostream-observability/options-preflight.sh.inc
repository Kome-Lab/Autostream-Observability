#!/bin/bash
set -euo pipefail

umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C

readonly SERVICE_NAME="observability"
readonly ARTIFACT_PREFIX="autostream-observability"
readonly MANAGED_ROOT="/opt/autostream/observability"
readonly RELEASE_ROOT="${MANAGED_ROOT}/releases"
readonly CURRENT_LINK="${MANAGED_ROOT}/current"
readonly RELEASE_BINARY="bin/autostream-observability"
readonly PUBLIC_BINARY="/usr/local/bin/autostream-observability"
readonly PUBLIC_ALIAS="/usr/local/bin/observability"
readonly ENV_DEST="/etc/autostream/observability.env"
readonly UNIT_DEST="/etc/systemd/system/autostream-observability.service"
readonly UNIT_NAME="autostream-observability.service"
readonly STATE_DIR="/var/lib/autostream/observability"
readonly INSTALL_MIGRATION_ROOT="/var/backups/autostream/install-migrations"
readonly INSTALL_MIGRATION_SERVICE_ROOT="${INSTALL_MIGRATION_ROOT}/observability"
readonly BACKUP_SOURCE_REL="backup/autostream-backup-observability"
readonly BACKUP_DEST="/usr/local/sbin/autostream-backup-observability"
readonly BACKUP_DIR="/var/backups/autostream/observability"
readonly BACKUP_CONFIG_DIR="/etc/autostream-local-executor"
readonly BACKUP_CONFIG_DEST="${BACKUP_CONFIG_DIR}/mariadb-backup.cnf"
readonly ARTIFACT_MANIFEST_REL="artifact-manifest.json"
readonly AUTOSTREAM_USER_ROLLBACK_LOGIN="autostream-install-rollback"

STAGE_DIR=
stage_dir_identity=
MANAGED_STAGE_DIR=
managed_stage_dir_identity=
EXTRACT_DIR=
RELEASE_DIR=
INSTALL_BACKUP_DIR=
binary_stage=
alias_stage=
unit_stage=
backup_exec_stage=
env_stage=
backup_config_stage=
current_stage=
binary_backup=
alias_backup=
unit_backup=
backup_exec_backup=
binary_quiesced=false
alias_quiesced=false
unit_quiesced=false
backup_exec_quiesced=false
current_original_exists=false
current_original_target=
current_switched=false
binary_activated=false
alias_activated=false
unit_activated=false
backup_exec_activated=false
env_created=false
env_created_identity=
env_created_digest=
backup_config_created=false
backup_config_created_identity=
backup_config_created_digest=
state_dir_existed=false
state_dir_original_uid=
state_dir_original_gid=
state_dir_original_mode=
state_dir_original_identity=
state_dir_created_identity=
state_dir_touched=false
backup_dir_existed=false
backup_dir_original_uid=
backup_dir_original_gid=
backup_dir_original_mode=
backup_dir_original_identity=
backup_dir_created_identity=
backup_dir_touched=false
commit_started=false
installation_complete=false
transaction_journal_active=false
managed_release_created=false
managed_release_created_identity=
created_autostream_group=false
created_autostream_group_gid=
created_autostream_group_record=
preexisting_autostream_group_record=
created_autostream_user=false
created_autostream_user_uid=
created_autostream_user_gid=
created_autostream_user_record=
autostream_user_rollback_login_ready=false
lock_create_stage=
shared_lock_create_stage=
preserve_stage_directories=false
cleanup_in_progress=false
signal_transaction_active=false
deferred_termination_status=0
declare -a temporary_rollback_paths=()
declare -a journaled_directory_paths=()
declare -A directory_journaled=()
declare -A directory_existed=()
declare -A directory_original_identity=()
declare -A directory_original_owner=()
declare -A directory_original_mode=()
declare -A directory_created_identity=()
declare -A directory_retain_if_nonempty=()
declare -A legacy_backup_existed_before=()
declare -A preexisting_legacy_backup_identity=()
declare -A preexisting_legacy_backup_digest=()
declare -A created_legacy_backup_identity=()
declare -A created_legacy_backup_digest=()

die() {
  printf 'install-autostream-observability: %s\n' "$*" >&2
  exit 1
}

handle_installer_signal() {
  local requested_status=$1
  if [[ ${signal_transaction_active} == true ]]; then
    deferred_termination_status=${requested_status}
    return 0
  fi
  exit "${requested_status}"
}

restore_installer_signal_traps() {
  if [[ ${cleanup_in_progress} == true ]]; then
    trap '' HUP INT TERM
    return
  fi
  trap 'handle_installer_signal 129' HUP
  trap 'handle_installer_signal 130' INT
  trap 'handle_installer_signal 143' TERM
}

begin_installer_signal_transaction() {
  [[ ${signal_transaction_active} == false ]] || \
    die "nested installer signal transaction is not allowed"
  signal_transaction_active=true
}

finish_installer_signal_transaction() {
  local requested_status
  signal_transaction_active=false
  requested_status=${deferred_termination_status}
  deferred_termination_status=0
  if (( requested_status != 0 )); then
    exit "${requested_status}"
  fi
}

if (( $# != 0 )); then
  die "this installer takes no arguments; run it from the extracted release directory"
fi

for command in \
  awk basename chmod chown cmp dirname find flock getent grep groupadd groupdel head id install jq \
  ln mkdir mktemp mv pwd readlink rm rmdir runuser sha256sum sort stat sync systemctl tar uname uniq \
  useradd userdel usermod wc; do
  command -v "${command}" >/dev/null 2>&1 || die "required command ${command} is unavailable"
done

[[ ${EUID} -eq 0 ]] || die "must run as root"
[[ -f /usr/bin/mariadb-dump &&
  ! -L /usr/bin/mariadb-dump &&
  -x /usr/bin/mariadb-dump ]] || \
  die "/usr/bin/mariadb-dump must be a regular non-symlink executable"

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) || \
  die "could not resolve the installer directory"
[[ -n ${SCRIPT_DIR} && ${SCRIPT_DIR} == /* && -d ${SCRIPT_DIR} && ! -L ${SCRIPT_DIR} ]] || \
  die "installer directory is missing or unsafe"
readonly SCRIPT_DIR
ARCHIVE_ROOT_NAME=$(basename -- "${SCRIPT_DIR}") || \
  die "could not resolve the release directory name"
[[ -n ${ARCHIVE_ROOT_NAME} && ${ARCHIVE_ROOT_NAME} != */* ]] || \
  die "release directory name is empty or unsafe"
readonly ARCHIVE_ROOT_NAME
if [[ ! ${ARCHIVE_ROOT_NAME} =~ ^autostream-observability_(v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?)_linux_(amd64|arm64)$ ]]; then
  die "release directory name must look like autostream-observability_v1.2.3_linux_amd64"
fi
readonly VERSION="${BASH_REMATCH[1]}"
readonly ARCH="${BASH_REMATCH[3]}"
SOURCE_DIR=$(dirname -- "${SCRIPT_DIR}") || \
  die "could not resolve the release parent directory"
[[ -n ${SOURCE_DIR} && ${SOURCE_DIR} == /* && -d ${SOURCE_DIR} && ! -L ${SOURCE_DIR} ]] || \
  die "release parent directory is missing or unsafe"
readonly SOURCE_DIR
readonly ASSET_NAME="${ARCHIVE_ROOT_NAME}.tar.gz"
readonly ARCHIVE_SOURCE="${SOURCE_DIR}/${ASSET_NAME}"

case "$(uname -m)" in
  x86_64)
    readonly HOST_ARCH="amd64"
    ;;
  aarch64|arm64)
    readonly HOST_ARCH="arm64"
    ;;
  *)
    die "unsupported host architecture $(uname -m)"
    ;;
esac
[[ ${ARCH} == "${HOST_ARCH}" ]] || die "archive architecture ${ARCH} does not match host architecture ${HOST_ARCH}"

source_identity() {
  stat -c '%d:%i:%s:%Y:%f' -- "$1"
}

validate_source_file() {
  local path=$1
  local label=$2
  [[ -f ${path} && ! -L ${path} ]] || die "${label} must be a regular non-symlink file: ${path}"
}

validate_safe_root_directory() {
  local path=$1
  local label=$2
  local mode
  [[ -d ${path} && ! -L ${path} ]] || die "${label} must be a non-symlink directory: ${path}"
  [[ $(stat -c '%U:%G' -- "${path}") == "root:root" ]] || die "${label} must be owned by root:root"
  mode=$(stat -c '%a' -- "${path}")
  (( (8#${mode} & 07022) == 0 )) || \
    die "${label} must not have special bits or be writable by group or other"
  [[ $(readlink -f -- "${path}") == "${path}" ]] || \
    die "${label} must resolve to its exact canonical path"
}

validate_safe_root_directory_candidate() {
  local path=$1
  local label=$2
  if [[ -e ${path} || -L ${path} ]]; then
    validate_safe_root_directory "${path}" "${label}"
  fi
}

validate_root_sticky_tmp_directory() {
  local path=$1
  local label=$2
  [[ -d ${path} && ! -L ${path} ]] || die "${label} must be a non-symlink directory"
  [[ $(stat -c '%U:%G:%a' -- "${path}") == "root:root:1777" ]] || \
    die "${label} must be owned by root:root with mode 1777"
  [[ $(readlink -f -- "${path}") == "${path}" ]] || \
    die "${label} must resolve to its exact canonical path"
}

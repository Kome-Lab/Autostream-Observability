#!/bin/bash
set -euo pipefail

umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C

die() {
  printf 'observability installer integration test: %s\n' "$*" >&2
  exit 1
}

[[ ${EUID} -eq 0 ]] || die "must run as root"
[[ $(uname -m) == "x86_64" ]] || die "this integration fixture requires an amd64 Linux runner"

if [[ ${AUTOSTREAM_OBSERVABILITY_INSTALLER_TEST_MOUNT_NS:-} != "1" ]]; then
  exec unshare --mount --propagation private bash -c '
    set -euo pipefail
    mount -t tmpfs -o nodev,nosuid,mode=0755,uid=0,gid=0 \
      autostream-observability-installer-test-scratch /mnt
    install -d -o root -g root -m 0755 \
      /mnt/usr-lower \
      /mnt/etc-lower \
      /mnt/var-lower \
      /mnt/run-lower
    mount --rbind /usr /mnt/usr-lower
    mount --make-rprivate /mnt/usr-lower
    mount --rbind /etc /mnt/etc-lower
    mount --make-rprivate /mnt/etc-lower
    mount --rbind /var /mnt/var-lower
    mount --make-rprivate /mnt/var-lower
    mount --rbind /run /mnt/run-lower
    mount --make-rprivate /mnt/run-lower
    install -d -o root -g root -m 0755 \
      /mnt/usr-upper \
      /mnt/usr-upper/local \
      /mnt/etc-upper \
      /mnt/etc-upper/systemd \
      /mnt/etc-upper/systemd/system \
      /mnt/var-upper \
      /mnt/var-upper/lib \
      /mnt/var-upper/backups \
      /mnt/run-upper \
      /mnt/run-upper/systemd
    install -d -o root -g root -m 1777 /mnt/var-upper/tmp
    install -d -o root -g root -m 0700 \
      /mnt/usr-work \
      /mnt/etc-work \
      /mnt/var-work \
      /mnt/run-work
    mount -t overlay -o nodev,nosuid,lowerdir=/mnt/usr-lower,upperdir=/mnt/usr-upper,workdir=/mnt/usr-work \
      autostream-observability-installer-test-usr-overlay /usr
    mount -t overlay -o nodev,nosuid,lowerdir=/mnt/etc-lower,upperdir=/mnt/etc-upper,workdir=/mnt/etc-work \
      autostream-observability-installer-test-etc-overlay /etc
    mount -t overlay -o nodev,nosuid,lowerdir=/mnt/var-lower,upperdir=/mnt/var-upper,workdir=/mnt/var-work \
      autostream-observability-installer-test-var-overlay /var
    mount -t overlay -o nodev,nosuid,lowerdir=/mnt/run-lower,upperdir=/mnt/run-upper,workdir=/mnt/run-work \
      autostream-observability-installer-test-run-overlay /run
    mount --rbind /mnt/run-lower/systemd /run/systemd
    mount --make-rprivate /run/systemd
    systemd_identity="$(stat -c "%d:%i" -- /mnt/run-lower/systemd)"
    [[ ${systemd_identity} =~ ^[0-9]+:[0-9]+$ &&
      $(stat -c "%d:%i" -- /run/systemd) == "${systemd_identity}" ]]
    mount -t tmpfs -o nodev,nosuid,mode=0755,uid=0,gid=0 \
      autostream-observability-installer-test-bin /usr/local/bin
    mount -t tmpfs -o nodev,nosuid,mode=0755,uid=0,gid=0 \
      autostream-observability-installer-test-sbin /usr/local/sbin
    mount -t tmpfs -o nodev,nosuid,mode=0755,uid=0,gid=0 \
      autostream-observability-installer-test-opt /opt
    mount -t tmpfs -o ro,nodev,nosuid,noexec,mode=0555,uid=0,gid=0 \
      autostream-observability-installer-test-sealed /mnt
    exec env \
      AUTOSTREAM_OBSERVABILITY_INSTALLER_TEST_MOUNT_NS=1 \
      AUTOSTREAM_OBSERVABILITY_INSTALLER_TEST_SYSTEMD_IDENTITY="${systemd_identity}" \
      bash "$1"
  ' autostream-observability-installer-test-mount "$0"
fi
grep -Eq ' /mnt .* - tmpfs autostream-observability-installer-test-sealed ' \
  /proc/self/mountinfo || die "sealed /mnt mount is missing"
awk '$5 == "/mnt" &&
  $6 ~ /(^|,)ro(,|$)/ &&
  $6 ~ /(^|,)nodev(,|$)/ &&
  $6 ~ /(^|,)nosuid(,|$)/ &&
  $6 ~ /(^|,)noexec(,|$)/ { found = 1 }
  END { exit !found }' /proc/self/mountinfo || \
  die "sealed /mnt mount options are unsafe"
[[ $(stat -c '%U:%G:%a' -- /mnt) == "root:root:555" ]] || \
  die "sealed /mnt ownership or mode is unsafe"
if touch /mnt/.autostream-observability-write-probe 2>/dev/null; then
  rm -f -- /mnt/.autostream-observability-write-probe
  die "sealed /mnt unexpectedly accepted a write"
fi
grep -Eq ' /usr .* - overlay autostream-observability-installer-test-usr-overlay ' \
  /proc/self/mountinfo || die "isolated /usr overlay mount is missing"
grep -Eq ' /etc .* - overlay autostream-observability-installer-test-etc-overlay ' \
  /proc/self/mountinfo || die "isolated /etc overlay mount is missing"
grep -Eq ' /var .* - overlay autostream-observability-installer-test-var-overlay ' \
  /proc/self/mountinfo || die "isolated /var overlay mount is missing"
grep -Eq ' /run .* - overlay autostream-observability-installer-test-run-overlay ' \
  /proc/self/mountinfo || die "isolated /run overlay mount is missing"
grep -Eq ' /run/systemd ' /proc/self/mountinfo || \
  die "host-backed /run/systemd mount is missing"
readonly EXPECTED_SYSTEMD_IDENTITY="${AUTOSTREAM_OBSERVABILITY_INSTALLER_TEST_SYSTEMD_IDENTITY:-}"
[[ ${EXPECTED_SYSTEMD_IDENTITY} =~ ^[0-9]+:[0-9]+$ &&
  $(stat -c '%d:%i' -- /run/systemd) == "${EXPECTED_SYSTEMD_IDENTITY}" ]] || \
  die "host-backed /run/systemd mount identity is invalid"
grep -Eq ' /usr/local/bin .* - tmpfs autostream-observability-installer-test-bin ' \
  /proc/self/mountinfo || die "isolated /usr/local/bin mount is missing"
grep -Eq ' /usr/local/sbin .* - tmpfs autostream-observability-installer-test-sbin ' \
  /proc/self/mountinfo || die "isolated /usr/local/sbin mount is missing"
grep -Eq ' /opt .* - tmpfs autostream-observability-installer-test-opt ' \
  /proc/self/mountinfo || die "isolated /opt mount is missing"
[[ $(stat -c '%U:%G:%a' -- /usr) == "root:root:755" ]] || \
  die "could not create an isolated safe /usr fixture"
[[ $(stat -c '%U:%G:%a' -- /etc) == "root:root:755" ]] || \
  die "could not create an isolated safe /etc fixture"
[[ $(stat -c '%U:%G:%a' -- /etc/systemd) == "root:root:755" ]] || \
  die "could not create an isolated safe /etc/systemd fixture"
[[ $(stat -c '%U:%G:%a' -- /etc/systemd/system) == "root:root:755" ]] || \
  die "could not create an isolated safe /etc/systemd/system fixture"
[[ $(stat -c '%U:%G:%a' -- /var) == "root:root:755" ]] || \
  die "could not create an isolated safe /var fixture"
[[ $(stat -c '%U:%G:%a' -- /var/lib) == "root:root:755" ]] || \
  die "could not create an isolated safe /var/lib fixture"
[[ $(stat -c '%U:%G:%a' -- /var/backups) == "root:root:755" ]] || \
  die "could not create an isolated safe /var/backups fixture"
[[ $(stat -c '%U:%G:%a' -- /var/tmp) == "root:root:1777" ]] || \
  die "could not create an isolated safe /var/tmp fixture"
[[ $(stat -c '%U:%G:%a' -- /run) == "root:root:755" ]] || \
  die "could not create an isolated safe /run fixture"
[[ $(stat -c '%U:%G:%a' -- /usr/local) == "root:root:755" ]] || \
  die "could not create an isolated safe /usr/local fixture"
[[ $(stat -c '%U:%G:%a' -- /usr/local/bin) == "root:root:755" ]] || \
  die "could not create an isolated safe /usr/local/bin fixture"
[[ $(stat -c '%U:%G:%a' -- /usr/local/sbin) == "root:root:755" ]] || \
  die "could not create an isolated safe /usr/local/sbin fixture"
[[ $(stat -c '%U:%G:%a' -- /opt) == "root:root:755" ]] || \
  die "could not create an isolated safe /opt fixture"

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly INSTALLER_SOURCE="${SCRIPT_DIR}/install-autostream-observability"

# Modules share this shell and preserve the original scenario order.
source "${SCRIPT_DIR}/installer-tests/observability/fixture-ownership-and-runtime.sh"
source "${SCRIPT_DIR}/installer-tests/observability/archive-fixture-and-validation.sh"
source "${SCRIPT_DIR}/installer-tests/observability/account-and-staging-rollback-cases.sh"
source "${SCRIPT_DIR}/installer-tests/observability/fresh-install-and-state-cases.sh"
source "${SCRIPT_DIR}/installer-tests/observability/legacy-rollback-cases.sh"
source "${SCRIPT_DIR}/installer-tests/observability/migration-and-reinstall-cases.sh"

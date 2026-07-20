#!/bin/bash
set -euo pipefail
umask 077

if (( $# != 4 )); then
  printf 'usage: %s SCRIPT BACKUP_DIR DEFAULT_DATABASE CUSTOM_DATABASE\n' "${0##*/}" >&2
  exit 2
fi

readonly SOURCE_SCRIPT="$1"
readonly BACKUP_DIR="$2"
readonly DEFAULT_DATABASE="$3"
readonly CUSTOM_DATABASE="$4"
readonly ARG_LOG=/tmp/autostream-mariadb-dump.argv
readonly INSTALLED_SCRIPT="/usr/local/sbin/$(basename "$SOURCE_SCRIPT" .example)"

[[ -f "$SOURCE_SCRIPT" ]] || { printf 'missing backup script: %s\n' "$SOURCE_SCRIPT" >&2; exit 1; }
for database in "$DEFAULT_DATABASE" "$CUSTOM_DATABASE"; do
  [[ "$database" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ ]] || {
    printf 'invalid smoke-test database: %s\n' "$database" >&2
    exit 1
  }
done

mkdir -p /etc/autostream "$BACKUP_DIR" /usr/local/sbin
install -m 0700 "$SOURCE_SCRIPT" "$INSTALLED_SCRIPT"
printf '[client]\nuser=smoke\npassword=not-used\n' > /etc/autostream/mariadb-backup.cnf
chmod 0600 /etc/autostream/mariadb-backup.cnf
chmod 0700 "$BACKUP_DIR"
[[ "$(stat -c '%u:%g:%a' "$INSTALLED_SCRIPT")" == "0:0:700" ]]
[[ "$(stat -c '%u:%g:%a' /etc/autostream/mariadb-backup.cnf)" == "0:0:600" ]]
[[ "$(stat -c '%u:%g:%a' "$BACKUP_DIR")" == "0:0:700" ]]

cat > /usr/bin/mariadb-dump <<'DUMP'
#!/bin/bash
set -euo pipefail
printf '%s\0' "$@" > /tmp/autostream-mariadb-dump.argv
printf '%s\n' '-- AutoStream backup smoke test'
DUMP
chmod 0755 /usr/bin/mariadb-dump

assert_dump() {
  local expected="$1"
  shift
  local output content partials
  local -a argv=() expected_argv=(
    "--defaults-extra-file=/etc/autostream/mariadb-backup.cnf"
    "--single-transaction"
    "--quick"
    "--skip-lock-tables"
    "--triggers"
    "--hex-blob"
    "--databases"
    "$expected"
  )

  rm -f "$ARG_LOG"
  output="$(/bin/bash "$INSTALLED_SCRIPT" "$@")"
  [[ "$output" != *$'\n'* ]] || { printf 'backup script wrote multiple stdout lines\n' >&2; return 1; }
  [[ "$output" == "$BACKUP_DIR/${expected}-"*.sql ]] || {
    printf 'unexpected backup path for %s: %s\n' "$expected" "$output" >&2
    return 1
  }
  [[ -f "$output" && ! -L "$output" && -s "$output" ]] || {
    printf 'backup is not a non-empty regular file: %s\n' "$output" >&2
    return 1
  }
  [[ "$(stat -c '%u:%g:%a' "$output")" == "0:0:600" ]] || {
    printf 'unsafe backup owner or mode: %s\n' "$(stat -c '%u:%g:%a' "$output")" >&2
    return 1
  }
  content="$(<"$output")"
  [[ "$content" == "-- AutoStream backup smoke test" ]] || {
    printf 'unexpected backup content\n' >&2
    return 1
  }
  [[ -s "$ARG_LOG" ]] || { printf 'mariadb-dump argv was not captured\n' >&2; return 1; }
  mapfile -d '' -t argv < "$ARG_LOG"
  [[ "${#argv[@]}" == "${#expected_argv[@]}" ]] || {
    printf 'mariadb-dump argv count mismatch: got %s want %s\n' "${#argv[@]}" "${#expected_argv[@]}" >&2
    return 1
  }
  for index in "${!expected_argv[@]}"; do
    if [[ "${argv[$index]}" != "${expected_argv[$index]}" ]]; then
      printf 'mariadb-dump argv[%s] mismatch: got %s want %s\n' \
        "$index" "${argv[$index]}" "${expected_argv[$index]}" >&2
      return 1
    fi
  done
  partials="$(find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.part' -print -quit)"
  [[ -z "$partials" ]] || {
    printf 'partial backup was not removed: %s\n' "$partials" >&2
    return 1
  }
  LAST_BACKUP="$output"
}

LAST_BACKUP=
assert_dump "$DEFAULT_DATABASE"
first_backup="$LAST_BACKUP"
assert_dump "$CUSTOM_DATABASE" "$CUSTOM_DATABASE"
second_backup="$LAST_BACKUP"
[[ "$first_backup" != "$second_backup" ]]
[[ "$(find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.sql' | wc -l)" == 2 ]]
printf 'root backup smoke passed for %s and %s\n' "$DEFAULT_DATABASE" "$CUSTOM_DATABASE"

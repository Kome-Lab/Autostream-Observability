#!/usr/bin/env bash
set -euo pipefail

: "${AUTOSTREAM_MARIADB_CI_CONTAINER:?disposable CI service container required}"
: "${AUTOSTREAM_MARIADB_CI_ROOT_PASSWORD:?disposable CI root password required}"
: "${RUNNER_TEMP:?}"
expected=(
  TestMariaDBNotificationChannelV2ResumeAfterDDL
  TestMariaDBNotificationChannelV2ResumeBeforeDDL
  TestMariaDBNotificationChannelV2ResumeCurrentCheckpoint
  TestMariaDBNotificationChannelV2ResumeRejectsBackupMismatch
  TestMariaDBNotificationChannelV2ResumeRejectsMissingAuthority
  TestMariaDBNotificationChannelV2ResumeRejectsReplacementMismatch
  TestMariaDBNotificationChannelV2ResumeRejectsRetainedDataDrift
)
mapfile -t discovered < <(go test ./internal/database -list '^TestMariaDBNotificationChannelV2Resume' | grep '^TestMariaDBNotificationChannelV2Resume' | sort)
diff -u <(printf '%s\n' "${expected[@]}" | sort) <(printf '%s\n' "${discovered[@]}")
mkdir -p "${RUNNER_TEMP}/notification-v2-resume"
index=0
for test_name in "${expected[@]}"; do
  index=$((index + 1))
  database="notification_v2_resume_${index}"
  docker exec -e MYSQL_PWD="${AUTOSTREAM_MARIADB_CI_ROOT_PASSWORD}" "${AUTOSTREAM_MARIADB_CI_CONTAINER}" \
    mariadb -uroot -e "CREATE DATABASE ${database}; GRANT ALL ON ${database}.* TO 'autostream'@'%';"
  result="${RUNNER_TEMP}/notification-v2-resume/${test_name}.json"
  AUTOSTREAM_OBSERVABILITY_TEST_DATABASE_URL="autostream:autostream_password@tcp(127.0.0.1:3306)/${database}?parseTime=true" \
    go test -p 1 ./internal/database -run "^${test_name}$" -count=1 -timeout=2m -json | tee "${result}"
  jq -s -e --arg name "${test_name}" '
    ([.[] | select(.Action=="run" and .Test==$name)] | length)==1 and
    ([.[] | select(.Action=="pass" and .Test==$name)] | length)==1 and
    ([.[] | select(.Action=="skip" or .Action=="fail")] | length)==0 and
    ([.[] | select(.Action=="pass" and ((.Test // "")==""))] | length)==1
  ' "${result}" >/dev/null
done

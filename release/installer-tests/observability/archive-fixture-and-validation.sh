
install -d -o root -g root -m 0755 \
  "${ARTIFACTS_DIR}" \
  "${EXTRACTED_ROOT}/bin" \
  "${EXTRACTED_ROOT}/backup" \
  "${EXTRACTED_ROOT}/systemd"
install -o root -g root -m 0755 "${INSTALLER_SOURCE}" \
  "${EXTRACTED_ROOT}/install-autostream-observability"

cat > "${EXTRACTED_ROOT}/bin/autostream-observability" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "--version" ]; then
  printf '%s\n' 'autostream-observability v9.9.9'
  printf '%s\n' 'commit: 0123456789abcdef0123456789abcdef01234567'
  printf '%s\n' 'build_date: 2026-07-31T00:00:00Z'
  exit 0
fi
exit 99
EOF
chmod 0755 "${EXTRACTED_ROOT}/bin/autostream-observability"
cp "${EXTRACTED_ROOT}/bin/autostream-observability" \
  "${EXTRACTED_ROOT}/bin/observability"
chmod 0755 "${EXTRACTED_ROOT}/bin/observability"

cat > "${EXTRACTED_ROOT}/backup/autostream-backup-observability" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 0755 "${EXTRACTED_ROOT}/backup/autostream-backup-observability"

cat > "${EXTRACTED_ROOT}/systemd/autostream-observability.service.example" <<'EOF'
[Unit]
Description=AutoStream Observability integration fixture

[Service]
Type=simple
User=autostream
Group=autostream
EnvironmentFile=-/etc/autostream/observability.env
LoadCredential=node-listener.json:/opt/autostream/local-executor/ports/observability.json
ExecStart=/usr/local/bin/autostream-observability

[Install]
WantedBy=multi-user.target
EOF
printf '%s\n' 'AUTOSTREAM_NODE_CONFIG=/etc/autostream-observability/config.yml' \
  > "${EXTRACTED_ROOT}/.env.example"
printf '%s\n' 'integration fixture' > "${EXTRACTED_ROOT}/README.install.md"
jq -n \
  --arg version "${VERSION}" \
  --arg commit "${FIXTURE_COMMIT}" \
  --arg build_date "${FIXTURE_BUILD_DATE}" \
  --arg name "${ARTIFACT_ID}.tar.gz" \
  --arg root "${ARTIFACT_ID}" \
  '{
    schema_version: 1,
    component: "observability",
    source_version: $version,
    commit: $commit,
    build_date: $build_date,
    platform: {
      os: "linux",
      arch: "amd64"
    },
    archive: {
      name: $name,
      root: $root
    },
    compatibility: {
      minimum_agent_version: "v1.0.0",
      minimum_panel_version: null,
      rollback_compatible: true,
      database_schema: "backward_compatible"
    }
  }' > "${EXTRACTED_ROOT}/artifact-manifest.json"

(
  cd -- "${EXTRACTED_ROOT}"
  find . -type f ! -path './checksums.txt' -print0 |
    sort -z |
    xargs -0 sha256sum > checksums.txt
)
tar -C "${ARTIFACTS_DIR}" -czf "${ARCHIVE}" "${ARTIFACT_ID}"
archive_sha256="$(sha256sum "${ARCHIVE}" | awk 'NR == 1 { print $1 }')"
for external_metadata in \
  "${ARCHIVE}.sha256" \
  "${ARTIFACTS_DIR}/release-manifest.json" \
  "${ARTIFACTS_DIR}/release-manifest.json.sha256"; do
  [[ ! -e ${external_metadata} && ! -L ${external_metadata} ]] || \
    die "archive-only fixture unexpectedly created ${external_metadata}"
done

install -d -o root -g root -m 0755 "${BAD_ARTIFACTS_DIR}"
cp -a -- "${EXTRACTED_ROOT}" "${BAD_EXTRACTED_ROOT}"
tar \
  --transform='s#bin/observability#bin//observability#' \
  -C "${BAD_ARTIFACTS_DIR}" \
  -czf "${BAD_ARCHIVE}" \
  "${ARTIFACT_ID}"

set +e
"${BAD_EXTRACTED_ROOT}/install-autostream-observability" \
  > "${WORK_DIR}/noncanonical-archive.out" 2>&1
noncanonical_archive_status=$?
set -e
[[ ${noncanonical_archive_status} -ne 0 ]] || \
  die "noncanonical archive path unexpectedly succeeded"
grep -F -- "release archive contains a noncanonical path" \
  "${WORK_DIR}/noncanonical-archive.out" >/dev/null || \
  die "noncanonical archive path did not report the expected failure"
[[ ! -e ${MANAGED_ROOT} && ! -L ${MANAGED_ROOT} ]] || \
  die "noncanonical archive path mutated the managed root"
if id autostream >/dev/null 2>&1 || getent group autostream >/dev/null 2>&1; then
  die "noncanonical archive path created the autostream account"
fi

printf '%s\n' "not declared by checksums.txt" \
  > "${BAD_EXTRACTED_ROOT}/unlisted.txt"
tar -C "${BAD_ARTIFACTS_DIR}" -czf "${BAD_ARCHIVE}" "${ARTIFACT_ID}"

set +e
"${BAD_EXTRACTED_ROOT}/install-autostream-observability" \
  > "${WORK_DIR}/bad-checksum-inventory.out" 2>&1
bad_inventory_status=$?
set -e
[[ ${bad_inventory_status} -ne 0 ]] || \
  die "incomplete embedded checksum inventory unexpectedly succeeded"
grep -F -- "release archive checksum inventory is incomplete or unsafe" \
  "${WORK_DIR}/bad-checksum-inventory.out" >/dev/null || \
  die "incomplete embedded checksum inventory did not report the expected failure"
[[ ! -e ${MANAGED_ROOT} && ! -L ${MANAGED_ROOT} ]] || \
  die "incomplete embedded checksum inventory mutated the managed root"
if id autostream >/dev/null 2>&1 || getent group autostream >/dev/null 2>&1; then
  die "incomplete embedded checksum inventory created the autostream account"
fi
rm -f -- "${BAD_EXTRACTED_ROOT}/unlisted.txt"

jq '.component = "worker"' \
  "${BAD_EXTRACTED_ROOT}/artifact-manifest.json" \
  > "${BAD_EXTRACTED_ROOT}/artifact-manifest.json.next"
mv -T \
  "${BAD_EXTRACTED_ROOT}/artifact-manifest.json.next" \
  "${BAD_EXTRACTED_ROOT}/artifact-manifest.json"
(
  cd -- "${BAD_EXTRACTED_ROOT}"
  find . -type f ! -path './checksums.txt' -print0 |
    sort -z |
    xargs -0 sha256sum > checksums.txt
)
tar -C "${BAD_ARTIFACTS_DIR}" -czf "${BAD_ARCHIVE}" "${ARTIFACT_ID}"

set +e
"${BAD_EXTRACTED_ROOT}/install-autostream-observability" \
  > "${WORK_DIR}/bad-manifest.out" 2>&1
bad_manifest_status=$?
set -e
[[ ${bad_manifest_status} -ne 0 ]] || \
  die "mismatched embedded artifact manifest unexpectedly succeeded"
grep -F -- "release artifact manifest does not bind the expected Observability archive" \
  "${WORK_DIR}/bad-manifest.out" >/dev/null || \
  die "mismatched embedded artifact manifest did not report the expected failure"
[[ ! -e ${MANAGED_ROOT} && ! -L ${MANAGED_ROOT} ]] || \
  die "mismatched embedded artifact manifest mutated the managed root"
[[ ! -e ${TARGET_LOCK} && ! -L ${TARGET_LOCK} ]] || \
  die "mismatched embedded artifact manifest created the updater lock"
[[ ! -e ${SHARED_HOST_SETUP_LOCK} && ! -L ${SHARED_HOST_SETUP_LOCK} ]] || \
  die "mismatched embedded artifact manifest created the shared host-setup lock"
if id autostream >/dev/null 2>&1 || getent group autostream >/dev/null 2>&1; then
  die "mismatched embedded artifact manifest created the autostream account"
fi

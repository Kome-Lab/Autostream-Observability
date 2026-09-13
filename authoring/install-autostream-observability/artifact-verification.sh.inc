
copy_bound_source() {
  local source=$1
  local destination=$2
  local label=$3
  local before_identity before_sha
  validate_source_file "${source}" "${label}"
  before_identity=$(source_identity "${source}")
  before_sha=$(sha256sum -- "${source}" | awk 'NR == 1 { print $1 }')
  install -o root -g root -m 0600 -- "${source}" "${destination}"
  validate_source_file "${source}" "${label}"
  [[ $(source_identity "${source}") == "${before_identity}" ]] || die "${label} changed while it was copied"
  [[ $(sha256sum -- "${source}" | awk 'NR == 1 { print $1 }') == "${before_sha}" ]] || \
    die "${label} content changed while it was copied"
  [[ $(sha256sum -- "${destination}" | awk 'NR == 1 { print $1 }') == "${before_sha}" ]] || \
    die "staged ${label} does not match its source"
}

validate_archive_layout() {
  local archive=$1
  local names=$2
  local verbose=$3
  local canonical_names="${names}.canonical"
  local duplicate_paths entry

  tar -tzf "${archive}" >"${names}"
  tar -tvzf "${archive}" >"${verbose}"
  [[ -s ${names} ]] || die "release archive is empty"
  : >"${canonical_names}"

  while IFS= read -r entry; do
    [[ -n ${entry} ]] || die "release archive contains a blank path"
    [[ ${entry} =~ ^[A-Za-z0-9._/-]+$ ]] || die "release archive contains an unsafe path: ${entry}"
    [[ ${entry} != /* ]] || die "release archive contains an absolute path"
    [[ ! ${entry} =~ (^|/)\.\.(/|$) ]] || die "release archive contains a parent traversal"
    [[ ${entry} != *"//"* &&
      ${entry} != *"/./"* &&
      ${entry} != */. ]] || \
      die "release archive contains a noncanonical path: ${entry}"
    case "${entry}" in
      "${ARCHIVE_ROOT_NAME}"|"${ARCHIVE_ROOT_NAME}/"|"${ARCHIVE_ROOT_NAME}/"*)
        ;;
      *)
        die "release archive must contain exactly the ${ARCHIVE_ROOT_NAME} root"
        ;;
    esac
    printf '%s\n' "${entry%/}" >>"${canonical_names}"
  done <"${names}"

  duplicate_paths=$(sort "${canonical_names}" | uniq -d)
  if [[ -n ${duplicate_paths} ]]; then
    die "release archive contains duplicate paths"
  fi
  if awk 'substr($1, 1, 1) != "-" && substr($1, 1, 1) != "d" { found=1 } END { exit found ? 0 : 1 }' "${verbose}"; then
    die "release archive contains a link or special file"
  fi
}

validate_checksum_inventory() {
  local release_dir=$1
  local scratch_prefix=$2
  local managed_markers=${3:-false}
  local checksums="${release_dir}/checksums.txt"
  local declared="${scratch_prefix}.declared"
  local declared_sorted="${scratch_prefix}.declared.sorted"
  local duplicates="${scratch_prefix}.duplicates"
  local actual="${scratch_prefix}.actual"
  local checksum_pattern='^[0-9a-f]{64}  (\./[A-Za-z0-9._/-]+)$'
  local line path

  : >"${declared}"
  while IFS= read -r line; do
    [[ ${line} =~ ${checksum_pattern} ]] || return 1
    path=${BASH_REMATCH[1]}
    [[ ${path} != "./checksums.txt" &&
      ${path} != *"//"* &&
      ${path} != *"/./"* &&
      ${path} != *"/../"* ]] || return 1
    printf '%s\n' "${path}" >>"${declared}"
  done <"${checksums}"
  [[ -s ${declared} ]] || return 1

  LC_ALL=C sort "${declared}" >"${declared_sorted}"
  uniq -d "${declared_sorted}" >"${duplicates}"
  [[ ! -s ${duplicates} ]] || return 1
  case "${managed_markers}" in
    false)
      (
        cd -- "${release_dir}"
        find . -type f ! -path './checksums.txt' -print | LC_ALL=C sort
      ) >"${actual}" || return 1
      ;;
    true)
      (
        cd -- "${release_dir}"
        find . -type f \
          ! -path './checksums.txt' \
          ! -path './.artifact-sha256' \
          ! -path './.version' \
          -print | LC_ALL=C sort
      ) >"${actual}" || return 1
      ;;
    *)
      return 1
      ;;
  esac
  cmp -s -- "${declared_sorted}" "${actual}"
}

validate_artifact_manifest() {
  local manifest=$1
  jq -e \
    --arg version "${VERSION}" \
    --arg service "${SERVICE_NAME}" \
    --arg arch "${ARCH}" \
    --arg asset "${ASSET_NAME}" \
    --arg root "${ARCHIVE_ROOT_NAME}" \
    '((keys | sort) ==
       ["archive", "build_date", "commit", "compatibility", "component", "platform",
        "schema_version", "source_version"]) and
     (.schema_version == 1) and
     (.component == $service) and
     (.source_version == $version) and
     (.commit | type == "string" and test("^[0-9a-f]{40}$")) and
     (.build_date | type == "string" and
       test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")) and
     (.platform | type == "object") and
     ((.platform | keys | sort) == ["arch", "os"]) and
     (.platform.os == "linux") and
     (.platform.arch == $arch) and
     (.archive | type == "object") and
     ((.archive | keys | sort) == ["name", "root"]) and
     (.archive.name == $asset) and
     (.archive.root == $root) and
     (.compatibility | type == "object") and
     ((.compatibility | keys | sort) ==
       ["database_schema", "minimum_agent_version", "minimum_panel_version",
        "rollback_compatible"]) and
     (.compatibility.minimum_agent_version == "v1.0.0") and
     (.compatibility.minimum_panel_version == null) and
     (.compatibility.rollback_compatible == true) and
     (.compatibility.database_schema == "backward_compatible")' \
    "${manifest}" >/dev/null
}

expected_binary_identity() {
  local manifest=$1
  local commit build_date
  commit=$(jq -r '.commit' "${manifest}") || return 1
  build_date=$(jq -r '.build_date' "${manifest}") || return 1
  printf 'autostream-observability %s\ncommit: %s\nbuild_date: %s' \
    "${VERSION}" "${commit}" "${build_date}"
}

validate_marker() {
  local path=$1
  local expected=$2
  local label=$3
  [[ -f ${path} && ! -L ${path} ]] || die "${label} marker is missing or unsafe"
  [[ $(stat -c '%U:%G:%a' -- "${path}") == "root:root:444" ]] || \
    die "${label} marker owner or mode is invalid"
  [[ $(<"${path}") == "${expected}" ]] || die "${label} marker does not match the verified release"
}

validate_release_tree() {
  local release_dir=$1
  local trusted_checksums=$2
  local scratch_prefix=$3
  [[ -d ${release_dir} && ! -L ${release_dir} ]] || die "managed release is missing or unsafe"
  [[ $(stat -c '%U:%G:%a' -- "${release_dir}") == "root:root:755" ]] || \
    die "managed release root owner or mode is invalid"
  if find "${release_dir}" -mindepth 1 \
    \( -type l -o \( ! -type d ! -type f \) \) \
    -print -quit | grep -q .; then
    die "existing managed release contains a link or special entry"
  fi
  [[ -f ${release_dir}/checksums.txt && ! -L ${release_dir}/checksums.txt ]] || \
    die "managed release checksums are missing or unsafe"
  cmp -s -- "${trusted_checksums}" "${release_dir}/checksums.txt" || \
    die "existing managed release checksums do not match the verified archive"
  validate_checksum_inventory "${release_dir}" "${scratch_prefix}" true || \
    die "existing managed release checksum inventory is incomplete or unsafe"
  (
    cd -- "${release_dir}"
    sha256sum --check --strict checksums.txt
  ) || die "managed release content verification failed"
  validate_marker "${release_dir}/.artifact-sha256" "${ARCHIVE_DIGEST}" "artifact digest"
  validate_marker "${release_dir}/.version" "${VERSION}" "version"
  [[ -x ${release_dir}/${RELEASE_BINARY} && -f ${release_dir}/${RELEASE_BINARY} &&
    ! -L ${release_dir}/${RELEASE_BINARY} ]] || die "managed release binary is missing or unsafe"
}

validate_current_release() {
  if [[ ! -e ${CURRENT_LINK} && ! -L ${CURRENT_LINK} ]]; then
    return
  fi
  [[ -L ${CURRENT_LINK} ]] || die "${CURRENT_LINK} must be an updater-managed symlink"
  local resolved marker_digest marker_version
  resolved=$(readlink -f -- "${CURRENT_LINK}") || die "${CURRENT_LINK} is dangling"
  case "${resolved}" in
    "${RELEASE_ROOT}/"*)
      ;;
    *)
      die "${CURRENT_LINK} points outside ${RELEASE_ROOT}"
      ;;
  esac
  [[ -d ${resolved} && ! -L ${resolved} ]] || die "current managed release is missing or unsafe"
  [[ -f ${resolved}/.artifact-sha256 && ! -L ${resolved}/.artifact-sha256 ]] || \
    die "current managed release digest marker is invalid"
  [[ -f ${resolved}/.version && ! -L ${resolved}/.version ]] || \
    die "current managed release version marker is invalid"
  marker_digest=$(<"${resolved}/.artifact-sha256")
  marker_version=$(<"${resolved}/.version")
  [[ ${marker_digest} =~ ^[0-9a-f]{64}$ ]] || die "current managed release digest marker is invalid"
  [[ ${marker_version} =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || \
    die "current managed release version marker is invalid"
  [[ $(stat -c '%U:%G:%a' -- "${resolved}/.artifact-sha256") == "root:root:444" ]] || \
    die "current digest marker owner or mode is invalid"
  [[ $(stat -c '%U:%G:%a' -- "${resolved}/.version") == "root:root:444" ]] || \
    die "current version marker owner or mode is invalid"
  [[ -f ${resolved}/checksums.txt && ! -L ${resolved}/checksums.txt ]] || \
    die "current managed release checksums are invalid"
  (
    cd -- "${resolved}"
    sha256sum --check --strict checksums.txt
  ) >/dev/null || die "current managed release content is corrupt"
}

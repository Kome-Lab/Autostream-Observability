
cleanup() {
  local status=$?
  local cleanup_failed=false
  local setup_rollback_safe=true
  local restore_link
  set +e
  cleanup_in_progress=true
  signal_transaction_active=false
  deferred_termination_status=0
  trap - EXIT
  trap '' HUP INT TERM
  if [[ ${installation_complete} == false && ${commit_started} == true ]]; then
    [[ ${unit_quiesced} != true ]] ||
      restore_destination "${UNIT_DEST}" "${unit_backup}" || {
        cleanup_failed=true
        setup_rollback_safe=false
      }
    [[ ${backup_exec_quiesced} != true ]] ||
      restore_destination "${BACKUP_DEST}" "${backup_exec_backup}" || {
        cleanup_failed=true
        setup_rollback_safe=false
      }
    [[ ${alias_quiesced} != true ]] ||
      restore_destination "${PUBLIC_ALIAS}" "${alias_backup}" || {
        cleanup_failed=true
        setup_rollback_safe=false
      }
    [[ ${binary_quiesced} != true ]] ||
      restore_destination "${PUBLIC_BINARY}" "${binary_backup}" || {
        cleanup_failed=true
        setup_rollback_safe=false
      }
    if [[ ${env_created} == true ]]; then
      if [[ -f ${ENV_DEST} && ! -L ${ENV_DEST} &&
        $(stat -c '%d:%i:%s:%Y:%Z:%f:%u:%g:%a' -- "${ENV_DEST}") == "${env_created_identity}" &&
        $(sha256sum -- "${ENV_DEST}" | awk 'NR == 1 { print $1 }') == "${env_created_digest}" ]]; then
        rm -f -- "${ENV_DEST}" || {
          cleanup_failed=true
          setup_rollback_safe=false
        }
      else
        cleanup_failed=true
        setup_rollback_safe=false
      fi
    fi
    if [[ ${backup_config_created} == true ]]; then
      if [[ -f ${BACKUP_CONFIG_DEST} && ! -L ${BACKUP_CONFIG_DEST} &&
        $(stat -c '%d:%i:%s:%Y:%Z:%f:%u:%g:%a' -- "${BACKUP_CONFIG_DEST}") == \
          "${backup_config_created_identity}" &&
        $(sha256sum -- "${BACKUP_CONFIG_DEST}" | awk 'NR == 1 { print $1 }') == \
          "${backup_config_created_digest}" ]]; then
        rm -f -- "${BACKUP_CONFIG_DEST}" || {
          cleanup_failed=true
          setup_rollback_safe=false
        }
      else
        cleanup_failed=true
        setup_rollback_safe=false
      fi
    fi
    if [[ ${current_switched} == true ]]; then
      if [[ ${current_original_exists} == true ]]; then
        reserve_path restore_link "${MANAGED_ROOT}" ".current.restore" || {
          cleanup_failed=true
          setup_rollback_safe=false
        }
        if [[ -n ${restore_link} ]]; then
          ln -s -- "${current_original_target}" "${restore_link}" || {
            cleanup_failed=true
            setup_rollback_safe=false
          }
          [[ ! -L ${restore_link} ]] ||
            mv -Tf -- "${restore_link}" "${CURRENT_LINK}" || {
              cleanup_failed=true
              setup_rollback_safe=false
            }
        fi
        [[ -L ${CURRENT_LINK} &&
          $(readlink -- "${CURRENT_LINK}") == "${current_original_target}" ]] || \
          {
            cleanup_failed=true
            setup_rollback_safe=false
          }
      else
        rm -f -- "${CURRENT_LINK}" || {
          cleanup_failed=true
          setup_rollback_safe=false
        }
        [[ ! -e ${CURRENT_LINK} && ! -L ${CURRENT_LINK} ]] || {
          cleanup_failed=true
          setup_rollback_safe=false
        }
      fi
    fi
    systemctl daemon-reload >/dev/null 2>&1 || {
      cleanup_failed=true
      setup_rollback_safe=false
    }
  fi
  if [[ ${installation_complete} == false ]]; then
    remove_transaction_stage_directory \
      "${MANAGED_STAGE_DIR}" "${managed_stage_dir_identity}" || {
      cleanup_failed=true
      setup_rollback_safe=false
    }
    rollback_state_and_backup_directories || {
      cleanup_failed=true
      setup_rollback_safe=false
    }
    rollback_created_managed_release || {
      cleanup_failed=true
      setup_rollback_safe=false
    }
    rollback_journaled_directories || {
      cleanup_failed=true
      setup_rollback_safe=false
    }
    if [[ ${setup_rollback_safe} == true ]]; then
      rollback_autostream_account || cleanup_failed=true
    else
      printf 'install-autostream-observability: retaining the service account because setup rollback was incomplete\n' >&2
    fi
    verify_bound_legacy_backups || cleanup_failed=true
  fi
  cleanup_temporary_rollback_paths || cleanup_failed=true
  if [[ -n ${lock_create_stage} && ( -e ${lock_create_stage} || -L ${lock_create_stage} ) ]]; then
    rm -f -- "${lock_create_stage}" || cleanup_failed=true
  fi
  if [[ -n ${shared_lock_create_stage} &&
    ( -e ${shared_lock_create_stage} || -L ${shared_lock_create_stage} ) ]]; then
    rm -f -- "${shared_lock_create_stage}" || cleanup_failed=true
  fi
  if [[ ${installation_complete} == true ]]; then
    remove_transaction_stage_directory \
      "${MANAGED_STAGE_DIR}" "${managed_stage_dir_identity}" || cleanup_failed=true
  fi
  if [[ ${preserve_stage_directories} == false ]]; then
    remove_transaction_stage_directory "${STAGE_DIR}" "${stage_dir_identity}" || cleanup_failed=true
  fi
  if [[ ${transaction_journal_active} == true ]]; then
    sync_common_installation_parents_best_effort || cleanup_failed=true
  fi
  if [[ ${cleanup_failed} == true ]]; then
    printf 'install-autostream-observability: cleanup or rollback was incomplete; inspect %s, %s, and retained backups before retrying\n' \
      "${STAGE_DIR:-unset}" "${MANAGED_STAGE_DIR:-unset}" >&2
    (( status != 0 )) || status=1
  fi
  exit "${status}"
}

validate_source_file "${ARCHIVE_SOURCE}" "release archive"
validate_root_sticky_tmp_directory /var/tmp "/var/tmp"

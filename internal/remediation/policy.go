package remediation

import (
	"os"
	"strings"
	"time"

	"github.com/example/autostream-observability/internal/store"
)

const (
	ModeDisabled       = "disabled"
	ModeSuggestOnly    = "suggest_only"
	ModeSafeAuto       = "safe_auto"
	ModeManualApproval = "manual_approval"
)

func ModeFromEnv() string {
	return NormalizeMode(os.Getenv("REMEDIATION_MODE"))
}

func NormalizeMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case ModeDisabled:
		return ModeDisabled
	case ModeSafeAuto:
		return ModeSafeAuto
	case ModeManualApproval:
		return ModeManualApproval
	default:
		return ModeSuggestOnly
	}
}

func BuildActions(incident store.Incident, mode string) []store.RemediationAction {
	mode = NormalizeMode(mode)
	actions := make([]store.RemediationAction, 0, len(incident.Report.SafeAutoCandidates)+len(incident.Report.ApprovalRequired))
	seen := map[string]bool{}
	for _, action := range incident.Report.SafeAutoCandidates {
		action = strings.TrimSpace(action)
		if action == "" || IsDangerous(action) || seen[action] {
			continue
		}
		seen[action] = true
		actions = append(actions, store.RemediationAction{
			IncidentID: incident.ID,
			Action:     action,
			Mode:       mode,
			Status:     initialStatus(mode, false),
			SafeAuto:   IsSafeAuto(action),
		})
	}
	for _, action := range incident.Report.ApprovalRequired {
		action = strings.TrimSpace(action)
		if action == "" || IsDangerous(action) || seen[action] {
			continue
		}
		seen[action] = true
		actions = append(actions, store.RemediationAction{
			IncidentID:       incident.ID,
			Action:           action,
			Mode:             mode,
			Status:           initialStatus(mode, true),
			SafeAuto:         false,
			RequiresApproval: true,
		})
	}
	return actions
}

func Approve(action store.RemediationAction) store.RemediationAction {
	if action.Status == "pending_approval" {
		action.Status = "approved"
	}
	return action
}

func Execute(action store.RemediationAction) store.RemediationAction {
	now := time.Now().UTC()
	if IsTerminalStatus(action.Status) {
		if strings.TrimSpace(action.Result) == "" {
			action.Result = "remediation action is already terminal"
		}
		return action
	}
	if NormalizeMode(action.Mode) == ModeDisabled || action.Status == "disabled" {
		action.Status = "blocked"
		action.Result = "remediation is disabled"
		return action
	}
	if NormalizeMode(action.Mode) == ModeSuggestOnly {
		action.Status = "blocked"
		action.Result = "remediation mode is suggest_only"
		return action
	}
	if NormalizeMode(action.Mode) == ModeManualApproval && action.Status != "approved" {
		action.Status = "blocked"
		action.Result = "manual approval is required"
		return action
	}
	if IsDangerous(action.Action) {
		action.Status = "blocked"
		action.Result = "dangerous action is never auto-executed"
		return action
	}
	if action.RequiresApproval && action.Status != "approved" {
		action.Status = "blocked"
		action.Result = "manual approval is required"
		return action
	}
	if !action.SafeAuto && !action.RequiresApproval {
		action.Status = "blocked"
		action.Result = "action is not marked safe"
		return action
	}
	action.Status = "executed"
	action.Result = "recorded_noop"
	action.ExecutedAt = &now
	return action
}

func IsTerminalStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "executed", "blocked":
		return true
	default:
		return false
	}
}

func IsSafeAuto(action string) bool {
	switch action {
	case "retry_gdrive_upload", "refresh_service_status", "rerun_diagnostics", "clear_stale_warning", "retry_package_remux":
		return true
	default:
		return false
	}
}

func IsDangerous(action string) bool {
	switch action {
	case "delete_archives", "rotate_credentials", "change_roles", "stop_live_stream", "recreate_youtube_broadcast", "revoke_service_tokens":
		return true
	default:
		return false
	}
}

func initialStatus(mode string, requiresApproval bool) string {
	if mode == ModeDisabled {
		return "disabled"
	}
	if requiresApproval || mode == ModeManualApproval {
		return "pending_approval"
	}
	return "suggested"
}

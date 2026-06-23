package remediation

import (
	"testing"

	"github.com/example/autostream-observability/internal/diagnostics"
	"github.com/example/autostream-observability/internal/store"
)

func TestBuildActionsFromIncidentReport(t *testing.T) {
	incident := store.Incident{
		ID: "inc-01",
		Report: diagnostics.Report{
			SafeAutoCandidates: []string{"retry_gdrive_upload", "retry_gdrive_upload", "stop_live_stream"},
			ApprovalRequired:   []string{"restart_encoder_recorder", "retry_gdrive_upload"},
		},
	}
	actions := BuildActions(incident, ModeSuggestOnly)
	if len(actions) != 2 {
		t.Fatalf("expected dangerous and duplicate actions filtered out, got %#v", actions)
	}
	if actions[0].Action != "retry_gdrive_upload" || !actions[0].SafeAuto || actions[0].Status != "suggested" {
		t.Fatalf("unexpected safe action: %#v", actions[0])
	}
	if actions[1].Action != "restart_encoder_recorder" || !actions[1].RequiresApproval || actions[1].Status != "pending_approval" {
		t.Fatalf("unexpected manual action: %#v", actions[1])
	}
}

func TestBuildActionsForArchiveRemediationReports(t *testing.T) {
	slow := store.Incident{
		ID:     "inc-remux-slow",
		Report: diagnostics.JapaneseReport("archive_remux_slow", []string{"signal_name=recorder.remux_duration_ms"}),
	}
	actions := BuildActions(slow, ModeSuggestOnly)
	if !hasAction(actions, "refresh_service_status") || !hasAction(actions, "rerun_diagnostics") {
		t.Fatalf("expected safe diagnostic actions for slow remux: %#v", actions)
	}
	if hasAction(actions, "retry_package_remux") {
		t.Fatalf("slow completed remux should not automatically suggest retry: %#v", actions)
	}

	failed := store.Incident{
		ID:     "inc-package-failed",
		Report: diagnostics.JapaneseReport("archive_package_failed", []string{"signal_name=archive.package_status"}),
	}
	actions = BuildActions(failed, ModeSuggestOnly)
	if !hasAction(actions, "retry_package_remux") || !hasAction(actions, "rerun_diagnostics") {
		t.Fatalf("expected package retry actions for package failure: %#v", actions)
	}
}

func TestExecuteBlocksDangerousAction(t *testing.T) {
	action := Execute(store.RemediationAction{Action: "delete_archives", SafeAuto: true})
	if action.Status != "blocked" {
		t.Fatalf("dangerous action must be blocked: %#v", action)
	}
}

func TestExecuteRequiresApproval(t *testing.T) {
	action := Execute(store.RemediationAction{Action: "restart_encoder_recorder", Mode: ModeManualApproval, RequiresApproval: true, Status: "pending_approval"})
	if action.Status != "blocked" {
		t.Fatalf("manual action without approval must be blocked: %#v", action)
	}
	action = Approve(store.RemediationAction{Action: "restart_encoder_recorder", Mode: ModeManualApproval, RequiresApproval: true, Status: "pending_approval"})
	action = Execute(action)
	if action.Status != "executed" {
		t.Fatalf("approved manual action should execute as recorded noop: %#v", action)
	}
}

func TestExecuteManualApprovalBlocksUnapprovedSafeAuto(t *testing.T) {
	action := Execute(store.RemediationAction{Action: "retry_package_remux", Mode: ModeManualApproval, SafeAuto: true, Status: "pending_approval"})
	if action.Status != "blocked" || action.Result != "manual approval is required" {
		t.Fatalf("manual approval mode must block unapproved safe-auto action: %#v", action)
	}
	action = Approve(store.RemediationAction{Action: "retry_package_remux", Mode: ModeManualApproval, SafeAuto: true, Status: "pending_approval"})
	action = Execute(action)
	if action.Status != "executed" {
		t.Fatalf("approved safe-auto action should execute in manual approval mode: %#v", action)
	}
}

func TestExecuteDoesNotReexecuteTerminalActions(t *testing.T) {
	executedAt := store.RemediationAction{Action: "retry_package_remux", Mode: ModeSafeAuto, SafeAuto: true, Status: "executed", Result: "control_panel_dispatch_executed"}
	got := Execute(executedAt)
	if got.Status != "executed" || got.Result != "control_panel_dispatch_executed" || got.ExecutedAt != executedAt.ExecutedAt {
		t.Fatalf("executed action must remain unchanged: %#v", got)
	}

	blocked := Execute(store.RemediationAction{Action: "retry_package_remux", Mode: ModeSafeAuto, SafeAuto: true, Status: "blocked"})
	if blocked.Status != "blocked" || blocked.Result != "remediation action is already terminal" {
		t.Fatalf("blocked action should remain terminal without execution: %#v", blocked)
	}
}

func hasAction(actions []store.RemediationAction, want string) bool {
	for _, action := range actions {
		if action.Action == want {
			return true
		}
	}
	return false
}

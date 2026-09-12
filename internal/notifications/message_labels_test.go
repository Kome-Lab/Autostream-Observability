package notifications

import (
	"strings"
	"testing"

	"github.com/example/autostream-observability/internal/store"
)

func TestNotificationTitlesAlwaysHaveSafeFallbacks(t *testing.T) {
	for _, eventType := range []string{"incident.opened", "incident.updated", "incident.resolved", "diagnostic.created", "remediation.pending_approval", "remediation.executed", "admin.audit", "unknown.event"} {
		t.Run(eventType, func(t *testing.T) {
			title := notificationTitle(eventType, store.Incident{})
			if strings.TrimSpace(title) == "" {
				t.Fatalf("notification title is empty for event %q", eventType)
			}
		})
	}
	unknownRule := notificationTitle("incident.opened", store.Incident{Rule: "new_rule_from_future"})
	if !strings.Contains(unknownRule, "new_rule_from_future") {
		t.Fatalf("unknown incident rule was dropped from title: %q", unknownRule)
	}
}

func TestKnownIncidentRulesHaveReadableTitles(t *testing.T) {
	for _, rule := range []string{
		"heartbeat_timeout", "encoder_process_exited", "recorder_not_writing", "disk_low",
		"archive_package_failed", "archive_remux_slow", "gdrive_upload_failed", "gdrive_upload_retry_high",
		"high_packet_loss", "rtmps_reconnect_loop", "encoder_low_fps", "encoder_bitrate_low",
		"encoder_dropped_frames_high", "audio_silence", "audio_clipping", "discord_audio_not_receiving",
		"discord_audio_forward_inactive", "discord_audio_forward_failed", "discord_audio_forward_recovered",
		"discord_audio_forward_stale", "discord_reconnect_loop", "discord_voice_disconnected",
		"media_input_timeout", "worker_event_send_failed", "stream_start_timeout", "stream_stop_timeout",
		"unexpected_stopped",
	} {
		t.Run(rule, func(t *testing.T) {
			title := notificationTitle("incident.opened", store.Incident{Rule: rule})
			if strings.TrimSpace(title) == "" || strings.HasSuffix(title, ": "+rule) {
				t.Fatalf("known incident rule has no readable title: %q", title)
			}
		})
	}
}

func TestNotificationActionLabelsCoverControlPanelAuditVocabulary(t *testing.T) {
	actions := []string{
		"api_tokens.create",
		"app.settings.test_email",
		"archive.artifact.share.create",
		"auth.change_password",
		"auth.avatar.update",
		"auth.avatar.delete",
		"auth.oauth.provision_user",
		"auth.passkey.login.start",
		"auth.passkey.login.finish",
		"integrations.drive_destination.update",
		"integrations.oauth_account.connect",
		"integrations.oauth_provider.update",
		"mfa.recovery_codes.regenerate",
		"passkeys.registration.start",
		"passkeys.registration.finish",
		"security.settings.update",
		"services.runtime_config.preview",
		"system_updates.create",
		"system_updates.request",
		"system_updates.cancel",
		"system_updates.claim",
		"system_updates.authorize",
		"system_updates.report",
		"system_updates.succeeded",
		"system_updates.rolled_back",
		"system_updates.failed",
		"streams.discord_youtube_notify",
		"streams.retry_upload",
		"streams.worker_event_test",
		"streams.youtube_relay_static_recovery.resolve",
		"users.email_welcome",
		"users.force_password_change",
		"users.oauth_link.delete",
		"workers.unassign",
		"youtube.relay_static_cleanup",
	}
	for _, action := range actions {
		if label := NotificationActionLabel(action); label == action || label == "" {
			t.Fatalf("control-panel audit action %q has no readable label", action)
		}
	}
}

func TestNotificationTitlesUseJapaneseLabelsForDiagnosticsAndStreamRecoveryActions(t *testing.T) {
	for action, want := range map[string]string{
		"diagnostics.run":    "診断を再実行",
		"streams.force_stop": "配信を強制停止",
		"streams.rearm":      "配信枠を待機状態に戻す",
	} {
		t.Run(action, func(t *testing.T) {
			if got := notificationTitle("admin.audit", store.Incident{Rule: action}); got != want {
				t.Fatalf("notification title = %q, want %q", got, want)
			}
		})
	}
}

func TestRelayStaticAuditActionsUseJapaneseNotificationLabels(t *testing.T) {
	for action, want := range map[string]string{
		"youtube.relay_static_cleanup":                  "YouTube固定リレーの後始末を実行",
		"streams.youtube_relay_static_recovery.resolve": "固定リレー配信の復旧を解決済みに変更",
	} {
		t.Run(action, func(t *testing.T) {
			if got := NotificationActionLabel(action); got != want {
				t.Fatalf("notification action label = %q, want %q", got, want)
			}
			if got := notificationTitle("admin.audit", store.Incident{Rule: action}); got != want {
				t.Fatalf("notification title = %q, want %q", got, want)
			}
		})
	}
}

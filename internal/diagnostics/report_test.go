package diagnostics

import (
	"reflect"
	"strings"
	"testing"
)

func TestAssignmentScopedCredentialDiagnosticsV2(t *testing.T) {
	for _, tc := range []struct {
		rule     string
		approval []string
	}{
		{"discord_audio_forward_inactive", []string{"restart_discord_bot"}},
		{"discord_audio_forward_failed", []string{"restart_discord_bot", "restart_encoder_recorder"}},
		{"worker_event_send_failed", []string{"restart_worker", "restart_encoder_recorder"}},
	} {
		t.Run(tc.rule, func(t *testing.T) {
			evidence := []string{"forward_failures_total=1"}
			got := JapaneseReport(tc.rule, evidence)
			guidance := got.LikelyCause + "\n" + strings.Join(got.RecommendedActions, "\n")
			for _, old := range []string{"ENCODER_AUDIO_TOKEN", "SERVICE_CONTROL_TOKEN_SHA256", "ENCODER_RECORDER_URL", "ENCODER_RECORDER_TOKEN"} {
				if strings.Contains(guidance, old) {
					t.Fatalf("retired configuration guidance: %s", old)
				}
			}
			for _, required := range []string{"Control Panel", "assignment", "Encoder", "job/run/generation", "credential", "準備", "期限", "値を表示・コピーしない"} {
				if !strings.Contains(guidance, required) {
					t.Fatalf("missing assignment-scoped guidance: %s", required)
				}
			}
			for _, unsafe := range []string{"認証を解除", "token を表示", "hash を表示", "grant を書き換", "journal を書き換"} {
				if strings.Contains(guidance, unsafe) {
					t.Fatalf("unsafe credential guidance: %s", unsafe)
				}
			}
			if got.Confidence != 0.78 || !reflect.DeepEqual(got.Evidence, evidence) || !reflect.DeepEqual(got.SafeAutoCandidates, []string{"refresh_service_status", "rerun_diagnostics"}) || !reflect.DeepEqual(got.ApprovalRequired, tc.approval) {
				t.Fatal("diagnostic evidence or action authority changed")
			}
		})
	}
}

func TestDiscordAudioDiagnosticsMentionAudioStatus(t *testing.T) {
	report := JapaneseReport("discord_audio_not_receiving", []string{"discord.audio_receiving=0"})
	if !containsAction(report.RecommendedActions, "/streams/{id}/audio-status") {
		t.Fatalf("expected audio-status action, got %#v", report.RecommendedActions)
	}
}

func TestMediaInputTimeoutDiagnosticsMentionLastPacketAge(t *testing.T) {
	report := JapaneseReport("media_input_timeout", []string{"media.input_timeout_sec=5"})
	if !containsAction(report.RecommendedActions, "last_packet_age_sec") {
		t.Fatalf("expected last_packet_age_sec action, got %#v", report.RecommendedActions)
	}
}

func TestWorkerEventDiagnosticsMentionControlPanelSidecar(t *testing.T) {
	report := JapaneseReport("worker_event_send_failed", []string{"worker.event_send_failures_total=1"})
	if !containsAction(report.RecommendedActions, "Worker event sidecar") {
		t.Fatalf("expected Worker event sidecar action, got %#v", report.RecommendedActions)
	}
}

func TestDiscordForwardRecoveredDiagnosticsMentionForwardedTotal(t *testing.T) {
	report := JapaneseReport("discord_audio_forward_recovered", []string{"discord.audio_forward_errors_total=1"})
	if report.Confidence >= JapaneseReport("discord_audio_forward_failed", nil).Confidence {
		t.Fatalf("recovered diagnostic should be lower confidence than active failure: %#v", report)
	}
	if !containsAction(report.RecommendedActions, "discord.audio_forwarded_total") {
		t.Fatalf("expected forwarded total action, got %#v", report.RecommendedActions)
	}
	if !containsAction(report.SafeAutoCandidates, "clear_stale_warning") {
		t.Fatalf("expected clear stale warning candidate, got %#v", report.SafeAutoCandidates)
	}
}

func TestDiscordForwardStaleDiagnosticsMentionAudioStatus(t *testing.T) {
	report := JapaneseReport("discord_audio_forward_stale", []string{"discord.audio_last_forward_age_sec=5"})
	if !containsAction(report.RecommendedActions, "/streams/{id}/audio-status") {
		t.Fatalf("expected audio-status action, got %#v", report.RecommendedActions)
	}
}

func TestDiscordConnectionDiagnosticsMentionConnectionMetrics(t *testing.T) {
	reconnect := JapaneseReport("discord_reconnect_loop", []string{"discord.reconnect_count=3"})
	if !containsAction(reconnect.RecommendedActions, "discord.reconnect_count") {
		t.Fatalf("expected reconnect metric action, got %#v", reconnect.RecommendedActions)
	}
	voice := JapaneseReport("discord_voice_disconnected", []string{"discord.voice_disconnect_count=1"})
	if voice.Confidence <= reconnect.Confidence {
		t.Fatalf("voice disconnect should be higher confidence than reconnect loop: reconnect=%#v voice=%#v", reconnect, voice)
	}
	if !containsAction(voice.RecommendedActions, "/streams/{id}/audio-status") {
		t.Fatalf("expected audio-status action, got %#v", voice.RecommendedActions)
	}
}

func TestKnownDetectionRulesHaveSpecificDiagnostics(t *testing.T) {
	fallback := JapaneseReport("unknown_rule", nil)
	for _, rule := range knownRules() {
		t.Run(rule, func(t *testing.T) {
			report := JapaneseReport(rule, []string{rule + "=1"})
			if report.Summary == fallback.Summary {
				t.Fatalf("rule uses generic fallback report: %s", rule)
			}
			if len(report.RecommendedActions) == 0 || len(report.Evidence) == 0 {
				t.Fatalf("rule should include actions and evidence: %#v", report)
			}
		})
	}
}

func TestKnownDiagnosticsDoNotContainMojibake(t *testing.T) {
	rules := append(knownRules(), "unknown_rule")
	for _, rule := range rules {
		t.Run(rule, func(t *testing.T) {
			report := JapaneseReport(rule, []string{rule + "=1"})
			joined := strings.Join(append([]string{
				report.Summary,
				report.LikelyCause,
				report.Impact,
			}, append(append(report.RecommendedActions, report.SafeAutoCandidates...), report.ApprovalRequired...)...), "\n")
			assertNoMojibake(t, joined)
		})
	}
}

func TestArchiveUploadDiagnosticsKeepServiceAccountGuidance(t *testing.T) {
	report := JapaneseReport("gdrive_upload_failed", []string{"failure_phase=upload"})
	if !containsAction(report.RecommendedActions, "Service Account") {
		t.Fatalf("expected Service Account guidance, got %#v", report.RecommendedActions)
	}
	if !containsAction(report.SafeAutoCandidates, "retry_gdrive_upload") {
		t.Fatalf("expected retry candidate, got %#v", report.SafeAutoCandidates)
	}
}

func TestEncoderQualityDiagnosticsMentionProfileAndHostLoad(t *testing.T) {
	report := JapaneseReport("encoder_low_fps", []string{"encoder.output_fps=30"})
	if !containsAction(report.RecommendedActions, "CPU/GPU") {
		t.Fatalf("expected host load action, got %#v", report.RecommendedActions)
	}
	if !containsAction(report.RecommendedActions, "encoder profile") {
		t.Fatalf("expected encoder profile action, got %#v", report.RecommendedActions)
	}
}

func knownRules() []string {
	return []string{
		"heartbeat_timeout",
		"encoder_process_exited",
		"recorder_not_writing",
		"archive_package_failed",
		"archive_remux_slow",
		"gdrive_upload_failed",
		"gdrive_upload_retry_high",
		"high_packet_loss",
		"rtmps_reconnect_loop",
		"audio_silence",
		"audio_clipping",
		"discord_audio_not_receiving",
		"discord_audio_forward_inactive",
		"discord_audio_forward_failed",
		"discord_audio_forward_recovered",
		"discord_audio_forward_stale",
		"discord_reconnect_loop",
		"discord_voice_disconnected",
		"media_input_timeout",
		"encoder_low_fps",
		"encoder_bitrate_low",
		"encoder_dropped_frames_high",
		"worker_event_send_failed",
		"disk_low",
		"stream_start_timeout",
		"stream_stop_timeout",
		"unexpected_stopped",
	}
}

func containsAction(actions []string, needle string) bool {
	for _, action := range actions {
		if strings.Contains(action, needle) {
			return true
		}
	}
	return false
}

func assertNoMojibake(t *testing.T, body string) {
	t.Helper()
	fragments := []string{"\u7e3a", "\u7e67", "\u8700", "\u9021", "\u8b5b", "\u9a5f", "\u9afb", "\u87a2", "\u9706", "\u9a3e", "\u8b41", "\u879f", "\u86ef", "\u9b2e", "\u9aeb", "\u9015"}
	for _, fragment := range fragments {
		if strings.Contains(body, fragment) {
			t.Fatalf("mojibake-like fragment %q found in %q", fragment, body)
		}
	}
}

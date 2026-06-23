package detection

import (
	"strings"
	"testing"
)

func TestEvaluateHeartbeatTimeout(t *testing.T) {
	incidents := Evaluate(Signal{Name: "heartbeat.age_sec", Value: 31})
	if len(incidents) != 1 || incidents[0].Rule != "heartbeat_timeout" {
		t.Fatalf("unexpected incidents: %#v", incidents)
	}
}

func TestDangerousActionsNotDetectedAsAuto(t *testing.T) {
	incidents := Evaluate(Signal{Name: "roles.changed", Value: 1})
	if len(incidents) != 0 {
		t.Fatalf("role changes must not create auto remediation incident: %#v", incidents)
	}
}

func TestEvaluateEncoderProcessExitedEvent(t *testing.T) {
	incidents := Evaluate(Signal{Type: "error", Name: "encoder.process.exited"})
	if len(incidents) != 1 || incidents[0].Rule != "encoder_process_exited" || incidents[0].Severity != "critical" {
		t.Fatalf("unexpected incidents: %#v", incidents)
	}
}

func TestRequiredDetectionRules(t *testing.T) {
	cases := []struct {
		name string
		in   Signal
		rule string
	}{
		{name: "packet loss", in: Signal{Name: "srt.packet_loss_percent", Value: 7}, rule: "high_packet_loss"},
		{name: "rtmps reconnect", in: Signal{Name: "encoder.rtmp_reconnect_count", Value: 3, StreamLive: true}, rule: "rtmps_reconnect_loop"},
		{name: "encoder low fps", in: Signal{Name: "encoder.output_fps", Value: 30, StreamLive: true}, rule: "encoder_low_fps"},
		{name: "encoder low bitrate", in: Signal{Name: "encoder.output_bitrate_kbps", Value: 2500, StreamLive: true}, rule: "encoder_bitrate_low"},
		{name: "encoder dropped frames", in: Signal{Name: "encoder.dropped_frames_total", Value: 30, StreamLive: true}, rule: "encoder_dropped_frames_high"},
		{name: "audio silence", in: Signal{Name: "encoder.audio_silence_sec", Value: 5, StreamLive: true}, rule: "audio_silence"},
		{name: "audio clipping", in: Signal{Name: "encoder.audio_clipping_total", Value: 10, StreamLive: true}, rule: "audio_clipping"},
		{name: "discord audio not receiving", in: Signal{Name: "discord.audio_receiving", Value: 0, StreamLive: true}, rule: "discord_audio_not_receiving"},
		{name: "discord audio forward inactive", in: Signal{Name: "discord.audio_forward_active", Value: 0, StreamLive: true}, rule: "discord_audio_forward_inactive"},
		{name: "discord audio forward failed", in: Signal{Name: "discord.audio_forward_errors_total", Value: 1, StreamLive: true}, rule: "discord_audio_forward_failed"},
		{name: "discord reconnect loop", in: Signal{Name: "discord.reconnect_count", Value: 3, StreamLive: true}, rule: "discord_reconnect_loop"},
		{name: "discord voice disconnected", in: Signal{Name: "discord.voice_disconnect_count", Value: 1, StreamLive: true}, rule: "discord_voice_disconnected"},
		{name: "media input timeout", in: Signal{Name: "media.input_timeout_sec", Value: 5, StreamLive: true}, rule: "media_input_timeout"},
		{name: "worker event send failure", in: Signal{Name: "worker.event_send_failures_total", Value: 1}, rule: "worker_event_send_failed"},
		{name: "discord worker event publish failure", in: Signal{Name: "discord.worker_event_publish_failures_total", Value: 1}, rule: "worker_event_send_failed"},
		{name: "archive package failed", in: Signal{Name: "archive.package_status", Value: 0}, rule: "archive_package_failed"},
		{name: "archive package failed event", in: Signal{Name: "archive.package.failed", Attributes: map[string]any{"failure_phase": "remux"}}, rule: "archive_package_failed"},
		{name: "archive remux slow", in: Signal{Name: "recorder.remux_duration_ms", Value: 300001}, rule: "archive_remux_slow"},
		{name: "gdrive upload failed", in: Signal{Name: "gdrive.upload_status", Value: 0}, rule: "gdrive_upload_failed"},
		{name: "gdrive upload failed package event", in: Signal{Name: "archive.package.failed", Attributes: map[string]any{"failure_phase": "upload"}}, rule: "gdrive_upload_failed"},
		{name: "gdrive retry high", in: Signal{Name: "gdrive.upload_retry_count", Value: 3}, rule: "gdrive_upload_retry_high"},
		{name: "disk low", in: Signal{Name: "host.disk_free_bytes", Value: 1024}, rule: "disk_low"},
		{name: "start timeout", in: Signal{Name: "stream.start_duration_ms", Value: 130000}, rule: "stream_start_timeout"},
		{name: "stop timeout", in: Signal{Name: "stream.stop_duration_ms", Value: 130000}, rule: "stream_stop_timeout"},
		{name: "unexpected stopped", in: Signal{Name: "stream.status", Status: "failed", StreamLive: true}, rule: "unexpected_stopped"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			incidents := Evaluate(tc.in)
			if len(incidents) != 1 || incidents[0].Rule != tc.rule {
				t.Fatalf("unexpected incidents: %#v", incidents)
			}
		})
	}
}

func TestDiscordAudioForwardErrorsRecoveredWhenRecentForwardSucceeded(t *testing.T) {
	incidents := Evaluate(Signal{
		Name:       "discord.audio_forward_errors_total",
		Value:      1,
		StreamLive: true,
		Attributes: map[string]any{
			"discord.audio_forwarded_total":      20,
			"discord.audio_last_forward_age_sec": 1,
		},
	})
	if len(incidents) != 1 || incidents[0].Rule != "discord_audio_forward_recovered" || incidents[0].Severity != "info" {
		t.Fatalf("unexpected incidents: %#v", incidents)
	}
}

func TestDiscordAudioForwardErrorsEscalateWhenForwardIsStale(t *testing.T) {
	incidents := Evaluate(Signal{
		Name:       "discord.audio_forward_errors_total",
		Value:      1,
		StreamLive: true,
		Attributes: map[string]any{
			"discord.audio_forwarded_total":      20,
			"discord.audio_last_forward_age_sec": 8,
		},
	})
	if len(incidents) != 1 || incidents[0].Rule != "discord_audio_forward_failed" || incidents[0].Severity != "error" {
		t.Fatalf("unexpected incidents: %#v", incidents)
	}
}

func TestDiscordAudioForwardStaleRule(t *testing.T) {
	incidents := Evaluate(Signal{Name: "discord.audio_last_forward_age_sec", Value: 5, StreamLive: true})
	if len(incidents) != 1 || incidents[0].Rule != "discord_audio_forward_stale" {
		t.Fatalf("unexpected incidents: %#v", incidents)
	}
}

func TestEvaluateUsesEnvironmentThresholdOverrides(t *testing.T) {
	t.Setenv("OBSERVABILITY_THRESHOLD_PACKET_LOSS_PERCENT", "9")
	if incidents := Evaluate(Signal{Name: "srt.packet_loss_percent", Value: 7}); len(incidents) != 0 {
		t.Fatalf("packet loss threshold override was ignored: %#v", incidents)
	}
	if incidents := Evaluate(Signal{Name: "srt.packet_loss_percent", Value: 9}); len(incidents) != 1 || incidents[0].Rule != "high_packet_loss" {
		t.Fatalf("packet loss threshold override did not trigger: %#v", incidents)
	}

	t.Setenv("OBSERVABILITY_THRESHOLD_MEDIA_INPUT_TIMEOUT_SEC", "12")
	if incidents := Evaluate(Signal{Name: "media.input_timeout_sec", Value: 5, StreamLive: true}); len(incidents) != 0 {
		t.Fatalf("media timeout threshold override was ignored: %#v", incidents)
	}
	if incidents := Evaluate(Signal{Name: "media.input_timeout_sec", Value: 12, StreamLive: true}); len(incidents) != 1 || incidents[0].Rule != "media_input_timeout" {
		t.Fatalf("media timeout threshold override did not trigger: %#v", incidents)
	}

	t.Setenv("OBSERVABILITY_THRESHOLD_RTMPS_RECONNECT_COUNT", "7")
	if incidents := Evaluate(Signal{Name: "encoder.rtmp_reconnect_count", Value: 6, StreamLive: true}); len(incidents) != 0 {
		t.Fatalf("RTMPS reconnect threshold override was ignored: %#v", incidents)
	}
	if incidents := Evaluate(Signal{Name: "encoder.rtmp_reconnect_count", Value: 7, StreamLive: true}); len(incidents) != 1 || incidents[0].Rule != "rtmps_reconnect_loop" {
		t.Fatalf("RTMPS reconnect threshold override did not trigger: %#v", incidents)
	}

	t.Setenv("OBSERVABILITY_THRESHOLD_GDRIVE_UPLOAD_RETRY_COUNT", "6")
	if incidents := Evaluate(Signal{Name: "gdrive.upload_retry_count", Value: 5}); len(incidents) != 0 {
		t.Fatalf("Google Drive retry threshold override was ignored: %#v", incidents)
	}
	if incidents := Evaluate(Signal{Name: "gdrive.upload_retry_count", Value: 6}); len(incidents) != 1 || incidents[0].Rule != "gdrive_upload_retry_high" {
		t.Fatalf("Google Drive retry threshold override did not trigger: %#v", incidents)
	}
}

func TestInvalidThresholdOverridesFallBackToSafeDefaults(t *testing.T) {
	for _, value := range []string{"0", "-1", "not-a-number"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("OBSERVABILITY_THRESHOLD_RTMPS_RECONNECT_COUNT", value)
			incidents := Evaluate(Signal{Name: "encoder.rtmp_reconnect_count", Value: 3, StreamLive: true})
			if len(incidents) != 1 || incidents[0].Rule != "rtmps_reconnect_loop" {
				t.Fatalf("invalid threshold should use the default: %#v", incidents)
			}
		})
	}
}

func TestDiscordAudioForwardThresholdOverrides(t *testing.T) {
	t.Setenv("OBSERVABILITY_THRESHOLD_DISCORD_AUDIO_FORWARD_STALE_SEC", "12")
	t.Setenv("OBSERVABILITY_THRESHOLD_DISCORD_AUDIO_FORWARD_ERRORS_TOTAL", "5")
	t.Setenv("OBSERVABILITY_THRESHOLD_DISCORD_RECONNECT_COUNT", "8")
	t.Setenv("OBSERVABILITY_THRESHOLD_DISCORD_VOICE_DISCONNECT_COUNT", "2")

	incidents := Evaluate(Signal{
		Name:       "discord.audio_forward_errors_total",
		Value:      3,
		StreamLive: true,
	})
	if len(incidents) != 1 || incidents[0].Rule != "discord_audio_forward_failed" || incidents[0].Severity != "warning" {
		t.Fatalf("discord threshold override was ignored: %#v", incidents)
	}
	if incidents := Evaluate(Signal{Name: "discord.reconnect_count", Value: 7, StreamLive: true}); len(incidents) != 0 {
		t.Fatalf("discord reconnect threshold override was ignored: %#v", incidents)
	}
	if incidents := Evaluate(Signal{Name: "discord.reconnect_count", Value: 8, StreamLive: true}); len(incidents) != 1 || incidents[0].Rule != "discord_reconnect_loop" {
		t.Fatalf("discord reconnect threshold override did not trigger: %#v", incidents)
	}
	if incidents := Evaluate(Signal{Name: "discord.voice_disconnect_count", Value: 1, StreamLive: true}); len(incidents) != 0 {
		t.Fatalf("discord voice disconnect threshold override was ignored: %#v", incidents)
	}
	if incidents := Evaluate(Signal{Name: "discord.voice_disconnect_count", Value: 2, StreamLive: true}); len(incidents) != 1 || incidents[0].Rule != "discord_voice_disconnected" {
		t.Fatalf("discord voice disconnect threshold override did not trigger: %#v", incidents)
	}
}

func TestIncidentSummariesDoNotContainMojibake(t *testing.T) {
	cases := []Signal{
		{Name: "heartbeat.age_sec", Value: 31},
		{Name: "encoder.process_alive", Value: 0, StreamLive: true},
		{Name: "recorder.write_bitrate_kbps", Value: 0, StreamLive: true},
		{Name: "host.disk_free_bytes", Value: 1024},
		{Name: "archive.package_status", Value: 0},
		{Name: "gdrive.upload_status", Value: 0},
		{Name: "srt.packet_loss_percent", Value: 7},
		{Name: "encoder.rtmp_reconnect_count", Value: 3, StreamLive: true},
		{Name: "encoder.output_fps", Value: 30, StreamLive: true},
		{Name: "encoder.audio_silence_sec", Value: 5, StreamLive: true},
		{Name: "discord.audio_receiving", Value: 0, StreamLive: true},
		{Name: "discord.audio_forward_active", Value: 0, StreamLive: true},
		{Name: "discord.audio_forward_errors_total", Value: 1, StreamLive: true},
		{Name: "discord.audio_last_forward_age_sec", Value: 5, StreamLive: true},
		{Name: "discord.reconnect_count", Value: 3, StreamLive: true},
		{Name: "discord.voice_disconnect_count", Value: 1, StreamLive: true},
		{Name: "media.input_timeout_sec", Value: 5, StreamLive: true},
		{Name: "worker.event_send_failures_total", Value: 1},
		{Name: "stream.start_duration_ms", Value: 130000},
		{Name: "stream.status", Status: "failed", StreamLive: true},
	}
	for _, tc := range cases {
		for _, incident := range Evaluate(tc) {
			assertNoSummaryMojibake(t, incident.SummaryJA)
		}
	}
}

func assertNoSummaryMojibake(t *testing.T, body string) {
	t.Helper()
	fragments := []string{"\u7e3a", "\u7e67", "\u8700", "\u9021", "\u8b5b", "\u9a5f", "\u9afb", "\u87a2", "\u9706", "\u9a3e", "\u8b41", "\u879f", "\u86ef", "\u9b2e", "\u9aeb", "\u9015"}
	for _, fragment := range fragments {
		if strings.Contains(body, fragment) {
			t.Fatalf("mojibake-like fragment %q found in %q", fragment, body)
		}
	}
}

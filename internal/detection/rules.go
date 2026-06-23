package detection

import (
	"os"
	"strconv"
	"strings"
)

type Signal struct {
	Type       string
	Name       string
	Value      float64
	StreamID   string
	StreamLive bool
	Status     string
	Attributes map[string]any
}

type Incident struct {
	Rule      string
	Severity  string
	SummaryJA string
}

type thresholds struct {
	HeartbeatAgeSec             float64
	DiskFreeBytes               float64
	RemuxSlowMS                 float64
	GDriveUploadRetryCount      float64
	PacketLossPercent           float64
	RTMPSReconnectCount         float64
	EncoderLowFPS               float64
	EncoderLowBitrateKbps       float64
	EncoderDroppedFramesTotal   float64
	AudioSilenceSec             float64
	AudioClippingTotal          float64
	DiscordAudioForwardStaleSec float64
	DiscordAudioForwardErrors   float64
	DiscordReconnectCount       float64
	DiscordVoiceDisconnectCount float64
	MediaInputTimeoutSec        float64
	StreamStartTimeoutMS        float64
	StreamStopTimeoutMS         float64
}

func Evaluate(s Signal) []Incident {
	cfg := thresholdsFromEnv()
	var out []Incident
	if s.Name == "heartbeat.age_sec" && s.Value > cfg.HeartbeatAgeSec {
		out = append(out, Incident{Rule: "heartbeat_timeout", Severity: "error", SummaryJA: "サービスの heartbeat が遅延しています。"})
	}
	if s.Name == "encoder.process_alive" && s.StreamLive && s.Value == 0 {
		out = append(out, Incident{Rule: "encoder_process_exited", Severity: "critical", SummaryJA: "配信中に Encoder process が停止しました。"})
	}
	if s.Name == "encoder.process.exited" && s.Type == "error" {
		out = append(out, Incident{Rule: "encoder_process_exited", Severity: "critical", SummaryJA: "Encoder process が異常終了しました。"})
	}
	if s.Name == "recorder.write_bitrate_kbps" && s.StreamLive && s.Value <= 0 {
		out = append(out, Incident{Rule: "recorder_not_writing", Severity: "critical", SummaryJA: "録画ファイルへの書き込みが停止しています。"})
	}
	if s.Name == "recorder.file_size_bytes" && s.StreamLive && s.Value <= 0 {
		out = append(out, Incident{Rule: "recorder_not_writing", Severity: "critical", SummaryJA: "録画ファイルサイズが増えていません。"})
	}
	if (s.Name == "recorder.disk_free_bytes" || s.Name == "host.disk_free_bytes") && s.Value > 0 && s.Value < cfg.DiskFreeBytes {
		out = append(out, Incident{Rule: "disk_low", Severity: "error", SummaryJA: "録画先または host のディスク空き容量が不足しています。"})
	}
	if s.Name == "archive.package_status" && s.Value == 0 {
		out = append(out, Incident{Rule: "archive_package_failed", Severity: "error", SummaryJA: "アーカイブの package 処理に失敗しました。"})
	}
	if s.Name == "recorder.remux_duration_ms" && s.Value > cfg.RemuxSlowMS {
		out = append(out, Incident{Rule: "archive_remux_slow", Severity: "warning", SummaryJA: "アーカイブの remux 処理に時間がかかっています。"})
	}
	if s.Name == "gdrive.upload_status" && s.Value == 0 {
		out = append(out, Incident{Rule: "gdrive_upload_failed", Severity: "error", SummaryJA: "Google Drive への archive upload に失敗しました。"})
	}
	if s.Name == "gdrive.upload_retry_count" && s.Value >= cfg.GDriveUploadRetryCount {
		out = append(out, Incident{Rule: "gdrive_upload_retry_high", Severity: "warning", SummaryJA: "Google Drive upload の retry 回数が増えています。"})
	}
	if s.Name == "archive.package.failed" || s.Name == "archive.upload.failed" {
		if s.Attributes["failure_phase"] == "upload" || s.Name == "archive.upload.failed" {
			out = append(out, Incident{Rule: "gdrive_upload_failed", Severity: "error", SummaryJA: "Google Drive への archive upload に失敗しました。"})
		} else {
			out = append(out, Incident{Rule: "archive_package_failed", Severity: "error", SummaryJA: "アーカイブの package 処理に失敗しました。"})
		}
	}
	if (s.Name == "srt.packet_loss_percent" || s.Name == "rtp.packet_loss_percent") && s.Value >= cfg.PacketLossPercent {
		out = append(out, Incident{Rule: "high_packet_loss", Severity: "warning", SummaryJA: "メディア伝送の packet loss が高くなっています。"})
	}
	if (s.Name == "rtmp.reconnect_count" || s.Name == "encoder.rtmp_reconnect_count") && s.StreamLive && s.Value >= cfg.RTMPSReconnectCount {
		out = append(out, Incident{Rule: "rtmps_reconnect_loop", Severity: "error", SummaryJA: "RTMPS の再接続が繰り返されています。"})
	}
	if s.Name == "encoder.output_fps" && s.StreamLive && s.Value > 0 && s.Value < cfg.EncoderLowFPS {
		out = append(out, Incident{Rule: "encoder_low_fps", Severity: "warning", SummaryJA: "Encoder の出力 FPS が低下しています。"})
	}
	if s.Name == "encoder.output_bitrate_kbps" && s.StreamLive && s.Value > 0 && s.Value < cfg.EncoderLowBitrateKbps {
		out = append(out, Incident{Rule: "encoder_bitrate_low", Severity: "warning", SummaryJA: "Encoder の出力 bitrate が低下しています。"})
	}
	if s.Name == "encoder.dropped_frames_total" && s.StreamLive && s.Value >= cfg.EncoderDroppedFramesTotal {
		out = append(out, Incident{Rule: "encoder_dropped_frames_high", Severity: "warning", SummaryJA: "Encoder の dropped frames が増えています。"})
	}
	if s.Name == "encoder.audio_silence_sec" && s.StreamLive && s.Value >= cfg.AudioSilenceSec {
		out = append(out, Incident{Rule: "audio_silence", Severity: "warning", SummaryJA: "配信音声の無音状態が続いています。"})
	}
	if s.Name == "encoder.audio_clipping_total" && s.StreamLive && s.Value >= cfg.AudioClippingTotal {
		out = append(out, Incident{Rule: "audio_clipping", Severity: "warning", SummaryJA: "配信音声の clipping が増えています。"})
	}
	if s.Name == "discord.audio_receiving" && s.StreamLive && s.Value == 0 {
		out = append(out, Incident{Rule: "discord_audio_not_receiving", Severity: "warning", SummaryJA: "Discord Bot が音声 packet を受信できていません。"})
	}
	if s.Name == "discord.audio_forward_active" && s.StreamLive && s.Value == 0 {
		out = append(out, Incident{Rule: "discord_audio_forward_inactive", Severity: "warning", SummaryJA: "Discord 音声 packet の Encoder/Recorder 転送が有効になっていません。"})
	}
	if s.Name == "discord.audio_forward_errors_total" && s.StreamLive && s.Value > 0 {
		out = append(out, evaluateDiscordAudioForwardErrors(s, cfg)...)
	}
	if s.Name == "discord.audio_last_forward_age_sec" && s.StreamLive && s.Value >= cfg.DiscordAudioForwardStaleSec {
		out = append(out, Incident{Rule: "discord_audio_forward_stale", Severity: "warning", SummaryJA: "Discord 音声 packet の Encoder/Recorder 転送が停滞しています。"})
	}
	if s.Name == "discord.reconnect_count" && s.StreamLive && s.Value >= cfg.DiscordReconnectCount {
		out = append(out, Incident{Rule: "discord_reconnect_loop", Severity: "warning", SummaryJA: "Discord Gateway の再接続が繰り返されています。"})
	}
	if s.Name == "discord.voice_disconnect_count" && s.StreamLive && s.Value >= cfg.DiscordVoiceDisconnectCount {
		out = append(out, Incident{Rule: "discord_voice_disconnected", Severity: "error", SummaryJA: "Discord Bot が配信中の voice channel から切断されました。"})
	}
	if s.Name == "media.input_timeout_sec" && s.StreamLive && s.Value >= cfg.MediaInputTimeoutSec {
		out = append(out, Incident{Rule: "media_input_timeout", Severity: "error", SummaryJA: "メディア入力がタイムアウトしています。"})
	}
	if s.Name == "worker.event_send_failures_total" && s.Value > 0 {
		out = append(out, Incident{Rule: "worker_event_send_failed", Severity: "warning", SummaryJA: "Worker から Encoder/Recorder への event 送信に失敗しています。"})
	}
	if s.Name == "discord.worker_event_publish_failures_total" && s.Value > 0 {
		out = append(out, Incident{Rule: "worker_event_send_failed", Severity: "warning", SummaryJA: "Discord Bot から Worker への participant / active-speaker event 送信に失敗しています。"})
	}
	if s.Name == "stream.start_duration_ms" && s.Value > cfg.StreamStartTimeoutMS {
		out = append(out, Incident{Rule: "stream_start_timeout", Severity: "error", SummaryJA: "配信開始処理がタイムアウトしています。"})
	}
	if s.Name == "stream.stop_duration_ms" && s.Value > cfg.StreamStopTimeoutMS {
		out = append(out, Incident{Rule: "stream_stop_timeout", Severity: "error", SummaryJA: "配信停止処理がタイムアウトしています。"})
	}
	if s.Name == "stream.status" && s.StreamLive && (s.Status == "stopped" || s.Status == "failed") {
		out = append(out, Incident{Rule: "unexpected_stopped", Severity: "critical", SummaryJA: "配信中の stream が予期せず停止しました。"})
	}
	return out
}

func evaluateDiscordAudioForwardErrors(s Signal, cfg thresholds) []Incident {
	lastForwardAge, hasLastForwardAge := attrFloat(s.Attributes, "discord.audio_last_forward_age_sec")
	forwardedTotal, hasForwardedTotal := attrFloat(s.Attributes, "discord.audio_forwarded_total")
	if hasLastForwardAge && hasForwardedTotal && forwardedTotal > 0 && lastForwardAge <= cfg.DiscordAudioForwardStaleSec {
		return []Incident{{Rule: "discord_audio_forward_recovered", Severity: "info", SummaryJA: "Discord 音声 packet の転送で一時的な失敗がありましたが、直近の転送は成功しています。"}}
	}
	severity := "warning"
	if s.Value >= cfg.DiscordAudioForwardErrors || (hasLastForwardAge && lastForwardAge >= cfg.DiscordAudioForwardStaleSec) {
		severity = "error"
	}
	return []Incident{{Rule: "discord_audio_forward_failed", Severity: severity, SummaryJA: "Discord 音声 packet の Encoder/Recorder 転送に失敗しています。"}}
}

func thresholdsFromEnv() thresholds {
	return thresholds{
		HeartbeatAgeSec:             envFloat("OBSERVABILITY_THRESHOLD_HEARTBEAT_AGE_SEC", 30),
		DiskFreeBytes:               envFloat("OBSERVABILITY_THRESHOLD_DISK_FREE_BYTES", 10*1024*1024*1024),
		RemuxSlowMS:                 envFloat("OBSERVABILITY_THRESHOLD_REMUX_SLOW_MS", 300000),
		GDriveUploadRetryCount:      envFloat("OBSERVABILITY_THRESHOLD_GDRIVE_UPLOAD_RETRY_COUNT", 3),
		PacketLossPercent:           envFloat("OBSERVABILITY_THRESHOLD_PACKET_LOSS_PERCENT", 5),
		RTMPSReconnectCount:         envFloat("OBSERVABILITY_THRESHOLD_RTMPS_RECONNECT_COUNT", 3),
		EncoderLowFPS:               envFloat("OBSERVABILITY_THRESHOLD_ENCODER_LOW_FPS", 45),
		EncoderLowBitrateKbps:       envFloat("OBSERVABILITY_THRESHOLD_ENCODER_LOW_BITRATE_KBPS", 3000),
		EncoderDroppedFramesTotal:   envFloat("OBSERVABILITY_THRESHOLD_ENCODER_DROPPED_FRAMES_TOTAL", 30),
		AudioSilenceSec:             envFloat("OBSERVABILITY_THRESHOLD_AUDIO_SILENCE_SEC", 5),
		AudioClippingTotal:          envFloat("OBSERVABILITY_THRESHOLD_AUDIO_CLIPPING_TOTAL", 10),
		DiscordAudioForwardStaleSec: envFloat("OBSERVABILITY_THRESHOLD_DISCORD_AUDIO_FORWARD_STALE_SEC", 5),
		DiscordAudioForwardErrors:   envFloat("OBSERVABILITY_THRESHOLD_DISCORD_AUDIO_FORWARD_ERRORS_TOTAL", 3),
		DiscordReconnectCount:       envFloat("OBSERVABILITY_THRESHOLD_DISCORD_RECONNECT_COUNT", 3),
		DiscordVoiceDisconnectCount: envFloat("OBSERVABILITY_THRESHOLD_DISCORD_VOICE_DISCONNECT_COUNT", 1),
		MediaInputTimeoutSec:        envFloat("OBSERVABILITY_THRESHOLD_MEDIA_INPUT_TIMEOUT_SEC", 5),
		StreamStartTimeoutMS:        envFloat("OBSERVABILITY_THRESHOLD_STREAM_START_TIMEOUT_MS", 120000),
		StreamStopTimeoutMS:         envFloat("OBSERVABILITY_THRESHOLD_STREAM_STOP_TIMEOUT_MS", 120000),
	}
}

func envFloat(key string, fallback float64) float64 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func attrFloat(attrs map[string]any, key string) (float64, bool) {
	if attrs == nil {
		return 0, false
	}
	switch value := attrs[key].(type) {
	case float64:
		return value, true
	case float32:
		return float64(value), true
	case int:
		return float64(value), true
	case int64:
		return float64(value), true
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

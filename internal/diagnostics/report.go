package diagnostics

type Report struct {
	Summary            string   `json:"summary"`
	LikelyCause        string   `json:"likely_cause"`
	Confidence         float64  `json:"confidence"`
	Evidence           []string `json:"evidence"`
	Impact             string   `json:"impact"`
	RecommendedActions []string `json:"recommended_actions"`
	SafeAutoCandidates []string `json:"safe_auto_remediation_candidates"`
	ApprovalRequired   []string `json:"actions_requiring_approval"`
}

func JapaneseReport(rule string, evidence []string) Report {
	switch rule {
	case "heartbeat_timeout":
		return report(
			"サービスの heartbeat が遅延しています。",
			"対象サービスの停止、ネットワーク遮断、Control Panel URL の誤り、または service token の不一致が考えられます。",
			0.80,
			evidence,
			"状態監視と制御指示が遅延し、運用判断に必要な情報が不足します。",
			[]string{"対象サービスの稼働状態を確認する", "Control Panel URL と service token を確認する", "firewall と reverse proxy を確認する"},
			[]string{"refresh_service_status", "rerun_diagnostics"},
			[]string{"restart_service"},
		)
	case "encoder_process_exited":
		return report(
			"Encoder process が停止しました。",
			"FFmpeg の異常終了、入力 stream の断絶、RTMPS 接続失敗、または host resource 不足が考えられます。",
			0.85,
			evidence,
			"YouTube 配信と録画が停止している可能性があります。",
			[]string{"Encoder/Recorder の logs.jsonl を確認する", "入力 URL と YouTube RTMPS 状態を確認する", "CPU/GPU、メモリ、ディスク容量を確認する"},
			[]string{"refresh_service_status", "rerun_diagnostics"},
			[]string{"restart_encoder_recorder", "restart_youtube_rtmps_output"},
		)
	case "recorder_not_writing":
		return report(
			"録画ファイルへの書き込みが止まっている可能性があります。",
			"FFmpeg 出力停止、ディスク容量不足、ファイル権限不足、または入力断絶が考えられます。",
			0.80,
			evidence,
			"最終アーカイブが欠損または不完全になる可能性があります。",
			[]string{"archive directory の空き容量と権限を確認する", "final.mkv の更新時刻とサイズを確認する", "FFmpeg process の状態を確認する"},
			[]string{"refresh_service_status", "rerun_diagnostics"},
			[]string{"restart_encoder_recorder"},
		)
	case "archive_package_failed":
		return report(
			"アーカイブの package 処理に失敗しました。",
			"final.mkv の欠落または破損、remux 失敗、sidecar copy 失敗、archive directory の権限不足、ディスク容量不足が考えられます。",
			0.82,
			evidence,
			"final.mp4 が作成されず、Google Drive upload へ進めない可能性があります。",
			[]string{"failure_phase と error_class を確認する", "tmp/{stream_id}/final.mkv が存在するか確認する", "remux の FFmpeg log を確認する", "archive directory の権限と空き容量を確認する"},
			[]string{"retry_package_remux", "rerun_diagnostics"},
			[]string{"restart_encoder_recorder"},
		)
	case "archive_remux_slow":
		return report(
			"アーカイブの remux 処理に時間がかかっています。",
			"final.mkv が大きい、disk I/O が低下している、host resource が不足している、または source file の読み取りが遅い可能性があります。",
			0.66,
			evidence,
			"配信停止後の final.mp4 確定と Google Drive upload 開始が遅れます。",
			[]string{"recorder.remux_duration_ms と file size を確認する", "archive directory の disk I/O と空き容量を確認する", "remux 実行時の FFmpeg log を確認する"},
			[]string{"refresh_service_status", "rerun_diagnostics"},
			[]string{},
		)
	case "gdrive_upload_failed":
		return report(
			"Google Drive への archive upload に失敗しました。",
			"Service Account の権限、Drive folder 共有、API quota、network 障害、または metadata upload の失敗が考えられます。",
			0.75,
			evidence,
			"ローカルには成果物が残っていても、Drive 上の共有アーカイブが未完成の可能性があります。",
			[]string{"failure_phase が upload か確認する", "Service Account に Drive folder が共有されているか確認する", "GOOGLE_DRIVE_FOLDER_ID と credentials path を確認する", "retry-upload を実行する"},
			[]string{"retry_gdrive_upload", "rerun_diagnostics"},
			[]string{},
		)
	case "gdrive_upload_retry_high":
		return report(
			"Google Drive upload の retry 回数が増えています。",
			"Google Drive API の一時障害、quota 制限、network 不安定、または大容量 upload の中断が考えられます。",
			0.68,
			evidence,
			"upload 完了が遅延し、アーカイブ共有が遅れる可能性があります。",
			[]string{"upload logs の retry 理由を確認する", "Google API quota と network を確認する", "完了していなければ retry-upload を実行する"},
			[]string{"retry_gdrive_upload", "rerun_diagnostics"},
			[]string{},
		)
	case "high_packet_loss":
		return report(
			"メディア伝送の packet loss が高い状態です。",
			"送信元 network、VPN、SRT/RTP 経路、または受信 host 負荷が考えられます。",
			0.70,
			evidence,
			"映像や音声の欠落、freeze、瞬断が発生する可能性があります。",
			[]string{"送信元と受信側の network 品質を確認する", "SRT/RTP 統計と host 負荷を確認する"},
			[]string{"refresh_service_status", "rerun_diagnostics"},
			[]string{},
		)
	case "rtmps_reconnect_loop":
		return report(
			"RTMPS の再接続が繰り返されています。",
			"YouTube RTMPS endpoint、stream key、上り回線、または FFmpeg 出力設定の問題が考えられます。",
			0.78,
			evidence,
			"YouTube 側の配信が不安定になり、視聴者に中断が見える可能性があります。",
			[]string{"YouTube stream key と RTMPS URL を確認する", "上り帯域と encoder bitrate を確認する", "encoder.rtmp_reconnect_count の増加間隔を確認する", "YouTube Studio の stream health を確認する"},
			[]string{"refresh_service_status", "rerun_diagnostics"},
			[]string{"restart_youtube_rtmps_output"},
		)
	case "audio_silence":
		return report(
			"配信音声の無音状態が続いています。",
			"Discord voice audio 受信停止、入力 mute、音声 routing、または encoder audio mapping の問題が考えられます。",
			0.72,
			evidence,
			"ライブ配信とアーカイブに音声欠落が残る可能性があります。",
			[]string{"Discord Bot の voice 接続を確認する", "Encoder の audio level と input mapping を確認する", "discord.audio_receiving と encoder.audio_silence_sec を同時に確認する"},
			[]string{"refresh_service_status", "rerun_diagnostics"},
			[]string{"reconnect_discord_voice", "restart_discord_bot"},
		)
	case "audio_clipping":
		return report(
			"配信音声の clipping が増えています。",
			"入力音量が高すぎる、複数音声の合成で headroom が不足している、または encoder 前段の gain 設定が過大な可能性があります。",
			0.70,
			evidence,
			"視聴者側で音割れが発生し、アーカイブにも歪みが残る可能性があります。",
			[]string{"Discord Bot と Encoder の audio level を確認する", "入力 gain を下げる", "音声 mix の headroom を確認する"},
			[]string{"refresh_service_status", "rerun_diagnostics"},
			[]string{"restart_encoder_recorder"},
		)
	case "discord_audio_not_receiving":
		return report(
			"Discord Bot が音声 packet を受信できていません。",
			"Bot が voice channel に参加できていない、Discord 側権限が不足している、または VC に話者がいない可能性があります。",
			0.76,
			evidence,
			"配信音声が無音になり、caption/STT の入力も欠落する可能性があります。",
			[]string{"Discord Bot の status と voice 接続を確認する", "Discord 側の Connect / Speak 権限を確認する", "Encoder/Recorder の /streams/{id}/audio-status で packets_total と rtp_forwarded を確認する"},
			[]string{"refresh_service_status", "rerun_diagnostics"},
			[]string{"reconnect_discord_voice", "restart_discord_bot"},
		)
	case "discord_audio_forward_inactive":
		return report(
			"Discord 音声 packet の Encoder/Recorder 転送が有効になっていません。",
			"Discord Bot の ENCODER_AUDIO_TOKEN 未設定、Control Panel からの encoder_audio_url 未伝播、Encoder/Recorder public_url 未設定、または stream assignment 不足が考えられます。",
			0.78,
			evidence,
			"Bot が voice channel に参加していても Encoder/Recorder に音声が届かず、配信とアーカイブが無音になる可能性があります。",
			[]string{"Discord Bot の audio_forward_enabled と audio_forward_active を確認する", "ENCODER_AUDIO_TOKEN を設定する", "Control Panel の stream assignment と Encoder/Recorder public_url を確認する"},
			[]string{"refresh_service_status", "rerun_diagnostics"},
			[]string{"restart_discord_bot"},
		)
	case "discord_audio_forward_failed":
		return report(
			"Discord 音声 packet の Encoder/Recorder 転送に失敗しています。",
			"Encoder/Recorder の public URL、service token、network 到達性、または stream assignment の不一致が考えられます。",
			0.78,
			evidence,
			"Bot は音声を受けていても Encoder/Recorder に届かず、配信音声が無音になる可能性があります。",
			[]string{"discord.audio_forward_errors_total と discord.audio_last_forward_age_sec を確認する", "ENCODER_AUDIO_TOKEN と SERVICE_CONTROL_TOKEN_SHA256 を確認する", "Encoder/Recorder の /streams/{id}/audio/opus に到達できるか確認する", "retry 後も discord.audio_forwarded_total が増えない場合は Encoder/Recorder と Bot の再起動を検討する"},
			[]string{"refresh_service_status", "rerun_diagnostics"},
			[]string{"restart_discord_bot", "restart_encoder_recorder"},
		)
	case "discord_audio_forward_recovered":
		return report(
			"Discord 音声 packet の転送で一時的な失敗がありましたが、直近の転送は成功しています。",
			"Encoder/Recorder の一時的な混雑、network 瞬断、または retry で回復可能な transient failure が考えられます。",
			0.62,
			evidence,
			"現在は音声転送が回復していますが、失敗が繰り返されると音切れや無音につながる可能性があります。",
			[]string{"discord.audio_forward_errors_total の増加傾向を確認する", "discord.audio_forwarded_total が継続して増えているか確認する", "同じ incident が繰り返される場合は network と Encoder/Recorder 負荷を確認する"},
			[]string{"refresh_service_status", "rerun_diagnostics", "clear_stale_warning"},
			[]string{},
		)
	case "discord_audio_forward_stale":
		return report(
			"Discord 音声 packet の Encoder/Recorder 転送が停滞しています。",
			"Discord Bot は起動しているが Encoder/Recorder への forward が進んでいない、または retry 中に失敗が続いている可能性があります。",
			0.74,
			evidence,
			"音声 packet が Encoder/Recorder に届かず、配信音声とアーカイブ音声が欠落する可能性があります。",
			[]string{"discord.audio_last_forward_age_sec と discord.audio_forwarded_total を確認する", "Encoder/Recorder の /streams/{id}/audio-status を確認する", "Bot から Encoder/Recorder public URL への到達性を確認する"},
			[]string{"refresh_service_status", "rerun_diagnostics"},
			[]string{"restart_discord_bot", "restart_encoder_recorder"},
		)
	case "discord_reconnect_loop":
		return report(
			"Discord Gateway の再接続が繰り返されています。",
			"Bot から Discord Gateway への network が不安定、Discord 側 rate limit / gateway close、または Bot host の一時停止が考えられます。",
			0.70,
			evidence,
			"VC 参加、participant tracking、active speaker、音声 forward が一時的に途切れる可能性があります。",
			[]string{"discord.reconnect_count の増加傾向を確認する", "Bot host の network と DNS を確認する", "Discord Bot の gateway log と service heartbeat を確認する"},
			[]string{"refresh_service_status", "rerun_diagnostics"},
			[]string{"restart_discord_bot"},
		)
	case "discord_voice_disconnected":
		return report(
			"Discord Bot が配信中の voice channel から切断されました。",
			"Bot が手動で VC から移動・切断された、Discord voice connection が切断された、権限変更や network 瞬断が発生した可能性があります。",
			0.82,
			evidence,
			"配信中の音声入力が止まり、Encoder/Recorder への audio forward と caption/STT 入力が欠落する可能性があります。",
			[]string{"discord.voice_disconnect_count と discord.voice_connected を確認する", "Bot が正しい voice channel に残っているか確認する", "Discord 側の Connect / Speak 権限と VC 移動履歴を確認する", "Encoder/Recorder の /streams/{id}/audio-status で packet 到達を確認する"},
			[]string{"refresh_service_status", "rerun_diagnostics"},
			[]string{"reconnect_discord_voice", "restart_discord_bot"},
		)
	case "media_input_timeout":
		return report(
			"メディア入力がタイムアウトしています。",
			"Discord Bot からの音声 packet、外部入力 stream、または Encoder 入力経路が遅延している可能性があります。",
			0.74,
			evidence,
			"配信映像または音声が停止し、録画にも欠損が残る可能性があります。",
			[]string{"入力 stream と Discord audio ingest の両方を確認する", "Discord audio bridge mode では /streams/{id}/audio-status の last_packet_age_sec を確認する", "Encoder/Recorder の process status と logs.jsonl を確認する"},
			[]string{"refresh_service_status", "rerun_diagnostics"},
			[]string{"restart_encoder_recorder", "restart_discord_bot"},
		)
	case "encoder_low_fps", "encoder_bitrate_low", "encoder_dropped_frames_high":
		return report(
			"Encoder の出力品質が低下しています。",
			"入力品質、CPU/GPU 負荷、encoder profile、または RTMPS 送信帯域の不足が考えられます。",
			0.70,
			evidence,
			"YouTube 配信のカクつき、画質低下、録画品質低下につながる可能性があります。",
			[]string{"Encoder host の CPU/GPU/メモリ負荷を確認する", "encoder profile の bitrate と fps を確認する", "入力 stream と上り帯域を確認する"},
			[]string{"refresh_service_status", "rerun_diagnostics"},
			[]string{"restart_encoder_recorder"},
		)
	case "worker_event_send_failed":
		return report(
			"Worker から Encoder/Recorder への event 送信に失敗しています。",
			"Encoder/Recorder API 停止、ENCODER_RECORDER_URL または token の誤り、network 到達性、stream assignment の不一致が考えられます。",
			0.78,
			evidence,
			"caption、telop、participant list、active speaker、overlay の反映が遅延または欠落する可能性があります。",
			[]string{"Control Panel の Streams 画面で Worker event path と Worker event sidecar を確認する", "Worker と Encoder/Recorder の service health を確認する", "ENCODER_RECORDER_URL と ENCODER_RECORDER_TOKEN を確認する", "Control Panel の stream assignment を確認する"},
			[]string{"refresh_service_status", "rerun_diagnostics"},
			[]string{"restart_worker", "restart_encoder_recorder"},
		)
	case "disk_low":
		return report(
			"録画先または host のディスク空き容量が不足しています。",
			"古い archive、logs、一時ファイルが蓄積している可能性があります。",
			0.82,
			evidence,
			"録画停止、remux 失敗、archive upload 失敗につながる可能性があります。",
			[]string{"archive directory の空き容量を確認する", "不要な一時ファイルを手動で整理する"},
			[]string{"refresh_service_status", "rerun_diagnostics"},
			[]string{},
		)
	case "stream_start_timeout":
		return report(
			"配信開始処理が想定時間内に完了していません。",
			"割り当て service の応答遅延、Encoder 起動失敗、Discord voice 接続失敗が考えられます。",
			0.75,
			evidence,
			"配信開始が利用者に完了として見えず、手動再試行が必要になる可能性があります。",
			[]string{"割り当て service の heartbeat と logs を確認する", "stream job の dispatch 結果を確認する"},
			[]string{"refresh_service_status", "rerun_diagnostics"},
			[]string{"restart_encoder_recorder", "restart_discord_bot", "restart_worker"},
		)
	case "stream_stop_timeout":
		return report(
			"配信停止処理が想定時間内に完了していません。",
			"Encoder 停止、remux、archive package、または upload 待ちで詰まっている可能性があります。",
			0.75,
			evidence,
			"録画ファイルの確定やアーカイブ作成が遅延する可能性があります。",
			[]string{"Encoder/Recorder の process 状態を確認する", "archive package 状態を確認する"},
			[]string{"refresh_service_status", "rerun_diagnostics", "retry_package_remux"},
			[]string{"restart_encoder_recorder"},
		)
	case "unexpected_stopped":
		return report(
			"配信中の stream が予期せず停止しました。",
			"Encoder 異常終了、Control Panel 以外からの停止、process 障害、または上流入力断絶が考えられます。",
			0.80,
			evidence,
			"Live 配信が中断し、録画とアーカイブが不完全になる可能性があります。",
			[]string{"stream lifecycle logs を確認する", "Encoder/Recorder と Discord Bot の直近ログを確認する"},
			[]string{"refresh_service_status", "rerun_diagnostics"},
			[]string{"restart_encoder_recorder", "restart_discord_bot"},
		)
	default:
		return report(
			"異常が検知されました。",
			"詳細な metrics と logs の確認が必要です。",
			0.40,
			evidence,
			"影響範囲は追加確認が必要です。",
			[]string{"関連ログと metrics を確認する"},
			[]string{"rerun_diagnostics"},
			[]string{},
		)
	}
}

func report(summary, likelyCause string, confidence float64, evidence []string, impact string, actions, safe, approval []string) Report {
	return Report{
		Summary:            summary,
		LikelyCause:        likelyCause,
		Confidence:         confidence,
		Evidence:           evidence,
		Impact:             impact,
		RecommendedActions: actions,
		SafeAutoCandidates: safe,
		ApprovalRequired:   approval,
	}
}

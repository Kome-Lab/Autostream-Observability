package notifications

import (
	"strings"
)

func NotificationActionLabel(action string) string {
	action = strings.TrimSpace(action)
	labels := map[string]string{
		"app.settings.test_email":               "テストメールを送信",
		"app.settings.update":                   "アプリ設定を更新",
		"api_tokens.create":                     "APIトークンを作成",
		"api_tokens.revoke":                     "APIトークンを失効",
		"api_tokens.rotate":                     "APIトークンを再生成",
		"archive.artifact.delete":               "録画ファイルを削除",
		"archive.artifact.download":             "録画ファイルをダウンロード",
		"archive.artifact.rename":               "録画ファイル名を変更",
		"archive.artifact.share.create":         "録画ファイルの共有リンクを作成",
		"archive.artifact.share.revoke":         "録画ファイルの共有リンクを無効化",
		"archive_destinations.create":           "Drive保存先を作成",
		"archive_destinations.delete":           "Drive保存先を削除",
		"archive_destinations.update":           "Drive保存先を更新",
		"archive_profiles.create":               "Archiveプロファイルを作成",
		"archive_profiles.delete":               "Archiveプロファイルを削除",
		"archive_profiles.update":               "Archiveプロファイルを更新",
		"auth.change_password":                  "パスワードを変更",
		"auth.email.change_request":             "メールアドレス変更を申請",
		"auth.email.confirm":                    "メールアドレス変更を確認",
		"auth.login":                            "管理画面へログイン",
		"auth.logout":                           "管理画面からログアウト",
		"auth.avatar.update":                    "プロフィール画像を更新",
		"auth.avatar.delete":                    "プロフィール画像を削除",
		"auth.oauth.login":                      "OAuthでログイン",
		"auth.oauth.provision_user":             "OAuthユーザーを作成",
		"auth.oauth.start":                      "OAuthログインを開始",
		"auth.passkey.login.start":              "Passkeyログインを開始",
		"auth.passkey.login.finish":             "Passkeyでログイン",
		"auth.oauth_link.create":                "OAuth連携を作成",
		"auth.oauth_link.delete":                "OAuth連携を解除",
		"discord_configs.create":                "Discord BOT設定を作成",
		"discord_configs.delete":                "Discord BOT設定を削除",
		"discord_configs.update":                "Discord BOT設定を更新",
		"diagnostics.run":                       "診断を再実行",
		"caption_profiles.create":               "Captionプロファイルを作成",
		"caption_profiles.delete":               "Captionプロファイルを削除",
		"caption_profiles.update":               "Captionプロファイルを更新",
		"encoder_profiles.create":               "Encoderプロファイルを作成",
		"encoder_profiles.delete":               "Encoderプロファイルを削除",
		"encoder_profiles.update":               "Encoderプロファイルを更新",
		"incidents.acknowledge":                 "インシデントを確認済みに変更",
		"incidents.resolve":                     "インシデントを解決済みに変更",
		"integrations.drive_destination.create": "Drive保存先を作成",
		"integrations.drive_destination.delete": "Drive保存先を削除",
		"integrations.drive_destination.update": "Drive保存先を更新",
		"integrations.oauth_account.connect":    "OAuth接続アカウントを接続",
		"integrations.oauth_account.create":     "OAuth接続アカウントを作成",
		"integrations.oauth_account.delete":     "OAuth接続アカウントを削除",
		"integrations.oauth_account.update":     "OAuth接続アカウントを更新",
		"integrations.oauth_provider.create":    "OAuthプロバイダを作成",
		"integrations.oauth_provider.delete":    "OAuthプロバイダを削除",
		"integrations.oauth_provider.update":    "OAuthプロバイダを更新",
		"mfa.disable":                           "MFAを無効化",
		"mfa.enroll":                            "MFAを登録",
		"mfa.recovery_codes.regenerate":         "MFAリカバリーコードを再発行",
		"mfa.verify":                            "MFAを確認",
		"nodes.configure_token.rotate":          "Node設定トークンを再生成",
		"nodes.delete":                          "Nodeを削除",
		"nodes.registration_token.create":       "Node登録トークンを発行",
		"nodes.runtime_token.rotate":            "Node Runtime Tokenを再生成",
		"nodes.update":                          "Nodeを更新",
		"notification_channels.create":          "通知先を作成",
		"notification_channels.delete":          "通知先を削除",
		"notification_channels.test":            "通知テストを送信",
		"notification_channels.update":          "通知先を更新",
		"oauth_accounts.create":                 "OAuth接続アカウントを作成",
		"oauth_accounts.delete":                 "OAuth接続アカウントを削除",
		"oauth_accounts.update":                 "OAuth接続アカウントを更新",
		"oauth_providers.create":                "OAuthプロバイダを作成",
		"oauth_providers.delete":                "OAuthプロバイダを削除",
		"oauth_providers.update":                "OAuthプロバイダを更新",
		"overlay_profiles.create":               "Overlayプロファイルを作成",
		"overlay_profiles.delete":               "Overlayプロファイルを削除",
		"overlay_profiles.update":               "Overlayプロファイルを更新",
		"passkeys.delete":                       "Passkeyを削除",
		"passkeys.registration.start":           "Passkey登録を開始",
		"passkeys.registration.finish":          "Passkey登録を完了",
		"remediation.approve":                   "復旧操作を承認",
		"remediation.execute":                   "復旧操作を実行",
		"roles.create":                          "ロールを作成",
		"roles.delete":                          "ロールを削除",
		"roles.update":                          "ロールを更新",
		"secrets.update":                        "シークレットを更新",
		"security.settings.update":              "セキュリティ設定を更新",
		"services.assign":                       "Nodeを割り当て",
		"services.delete":                       "Nodeを削除",
		"services.runtime_config.read":          "Nodeが実行設定を参照",
		"services.runtime_config.preview":       "Node実行設定をプレビュー",
		"services.unassign":                     "Nodeの割り当てを解除",
		"setup.first_admin":                     "初期管理者を作成",
		"system_updates.create":                 "システム更新を依頼",
		"system_updates.request":                "システム更新を依頼",
		"system_updates.cancel":                 "システム更新をキャンセル",
		"system_updates.claim":                  "システム更新ジョブを取得",
		"system_updates.authorize":              "システム更新の実行を承認",
		"system_updates.report":                 "システム更新の進捗を報告",
		"system_updates.succeeded":              "システム更新に成功",
		"system_updates.rolled_back":            "システム更新をロールバック",
		"system_updates.failed":                 "システム更新に失敗",
		"streams.create":                        "配信枠を作成",
		"streams.discord_youtube_notify":        "DiscordへYouTube配信を通知",
		"streams.force_stop":                    "配信を強制停止",
		"streams.mark_failed":                   "配信を失敗状態に変更",
		"streams.preview_link.create":           "プレビューリンクを作成",
		"streams.rearm":                         "配信枠を待機状態に戻す",
		"streams.retry_upload":                  "録画ファイルのアップロードを再試行",
		"streams.start":                         "配信を開始",
		"streams.stop":                          "配信を停止",
		"streams.update":                        "配信枠を更新",
		"streams.update_settings":               "配信設定を更新",
		"streams.worker_event_test":             "Workerイベントをテスト",
		"users.create":                          "ユーザーを作成",
		"users.delete":                          "ユーザーを削除",
		"users.disable":                         "ユーザーを無効化",
		"users.email_welcome":                   "ウェルカムメールを送信",
		"users.oauth_link.create":               "ユーザーのOAuth連携を作成",
		"users.oauth_link.delete":               "ユーザーのOAuth連携を解除",
		"users.force_password_change":           "次回ログイン時のパスワード変更を要求",
		"users.lock":                            "ユーザーをロック",
		"users.reset_password":                  "ユーザーのパスワードをリセット",
		"users.update":                          "ユーザーを更新",
		"users.unlock":                          "ユーザーのロックを解除",
		"workers.assign":                        "Workerを割り当て",
		"workers.restart":                       "Workerを再起動",
		"workers.unassign":                      "Workerの割り当てを解除",
		"youtube.complete":                      "YouTube配信を終了",
		"youtube_outputs.create":                "YouTube出力を作成",
		"youtube_outputs.delete":                "YouTube出力を削除",
		"youtube_outputs.update":                "YouTube出力を更新",
	}
	labels["streams.youtube_relay_static_recovery.resolve"] = "固定リレー配信の復旧を解決済みに変更"
	labels["youtube.relay_static_cleanup"] = "YouTube固定リレーの後始末を実行"
	if label := labels[action]; label != "" {
		return label
	}
	if action == "" {
		return "管理操作"
	}
	return action
}

func NotificationResourceLabel(resourceType string) string {
	resourceType = strings.TrimSpace(resourceType)
	labels := map[string]string{
		"archive_artifact":     "録画ファイル",
		"archive_destination":  "Drive保存先",
		"archive_share":        "共有リンク",
		"audit_log":            "監査ログ",
		"discord_config":       "Discord BOT設定",
		"node":                 "Node",
		"notification_channel": "通知先",
		"oauth_account":        "OAuth接続アカウント",
		"oauth_provider":       "OAuthプロバイダ",
		"profile":              "プロファイル",
		"role":                 "ロール",
		"secret":               "シークレット",
		"service":              "Node",
		"stream":               "配信枠",
		"user":                 "ユーザー",
		"worker":               "Worker Node",
		"youtube_output":       "YouTube出力",
	}
	if label := labels[resourceType]; label != "" {
		return label
	}
	return strings.ReplaceAll(resourceType, "_", " ")
}

func notificationRuleLabel(rule string) string {
	rule = strings.TrimSpace(rule)
	labels := map[string]string{
		"heartbeat_timeout":               "サービスの heartbeat 遅延",
		"encoder_process_exited":          "Encoder process 停止",
		"recorder_not_writing":            "録画書き込み停止",
		"disk_low":                        "ディスク空き容量不足",
		"archive_package_failed":          "アーカイブ package 失敗",
		"archive_remux_slow":              "アーカイブ remux 遅延",
		"gdrive_upload_failed":            "Google Drive upload 失敗",
		"gdrive_upload_retry_high":        "Google Drive retry 増加",
		"high_packet_loss":                "メディア packet loss 高騰",
		"rtmps_reconnect_loop":            "RTMPS 再接続ループ",
		"encoder_low_fps":                 "Encoder FPS 低下",
		"encoder_bitrate_low":             "Encoder bitrate 低下",
		"encoder_dropped_frames_high":     "Encoder dropped frames 増加",
		"audio_silence":                   "配信音声の無音",
		"audio_clipping":                  "配信音声 clipping",
		"discord_audio_not_receiving":     "Discord 音声受信停止",
		"discord_audio_forward_inactive":  "Discord 音声転送停止",
		"discord_audio_forward_failed":    "Discord 音声転送失敗",
		"discord_audio_forward_recovered": "Discord 音声転送回復",
		"discord_audio_forward_stale":     "Discord 音声転送停滞",
		"discord_reconnect_loop":          "Discord Gateway 再接続ループ",
		"discord_voice_disconnected":      "Discord VC 切断",
		"media_input_timeout":             "メディア入力 timeout",
		"worker_event_send_failed":        "Worker event 送信失敗",
		"stream_start_timeout":            "配信開始 timeout",
		"stream_stop_timeout":             "配信停止 timeout",
		"unexpected_stopped":              "配信の予期しない停止",
	}
	if label := labels[rule]; label != "" {
		return label
	}
	return rule
}

func notificationEventLabel(eventType string) string {
	labels := map[string]string{
		"incident.opened":              "インシデント発生",
		"incident.updated":             "インシデント更新",
		"incident.resolved":            "インシデント解決",
		"diagnostic.created":           "診断作成",
		"remediation.pending_approval": "復旧承認待ち",
		"remediation.executed":         "復旧実行",
		"admin.audit":                  "管理操作",
	}
	eventType = normalizedEventType(eventType)
	if label := labels[eventType]; label != "" {
		return label
	}
	return eventType
}

func notificationSeverityLabel(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "重大"
	case "error":
		return "エラー"
	case "warning":
		return "警告"
	case "info":
		return "情報"
	default:
		if severity = strings.TrimSpace(severity); severity != "" {
			return severity
		}
		return "情報"
	}
}

func notificationStatusLabel(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "success", "ok":
		return "成功"
	case "failure", "failed", "error":
		return "失敗"
	case "open":
		return "未対応"
	case "acknowledged":
		return "確認済み"
	case "resolved":
		return "解決済み"
	default:
		if status = strings.TrimSpace(status); status != "" {
			return status
		}
		return "記録済み"
	}
}

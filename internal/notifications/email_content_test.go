package notifications

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/example/autostream-observability/internal/store"
)

func TestEmailNotificationRelayAlternativesEscapeHTML(t *testing.T) {
	occurredAt := time.Date(2026, 7, 18, 3, 45, 0, 0, time.UTC)
	incident := store.Incident{
		Rule:      "secrets.update",
		Severity:  "warning",
		Status:    "success",
		SummaryJA: "シークレットを更新\n対象: <script>alert('resource')</script> & secret\n実行者: <img src=x onerror=alert(1)>",
		ServiceID: "control-panel",
		UpdatedAt: occurredAt,
	}
	plain := formatIncidentEmailText("admin.audit", incident)
	html := formatIncidentHTML("admin.audit", incident)
	if plain == "" || html == "" {
		t.Fatalf("plain or HTML relay alternative is missing: plain=%q html=%q", plain, html)
	}
	for _, want := range []string{"イベント", "操作 / ルール", "対象", "実行者", "結果", "重要度", "日時", "admin.audit", "secrets.update", occurredAt.Format(time.RFC3339)} {
		if !strings.Contains(html, want) {
			t.Fatalf("HTML card is missing %q: %s", want, html)
		}
	}
	if strings.Contains(html, "<script>") || strings.Contains(html, "<img") || !strings.Contains(html, "&lt;script&gt;") || !strings.Contains(html, "&amp; secret") {
		t.Fatalf("HTML notification did not escape dynamic content: %s", html)
	}
}

func TestEmailNotificationAlternativesStayWithinRelayLimits(t *testing.T) {
	incident := store.Incident{
		Rule:      strings.Repeat("rule", 5000),
		Severity:  "critical",
		Status:    "open",
		SummaryJA: strings.Repeat("非常に長い概要", 10000),
		ServiceID: strings.Repeat("service", 2000),
		UpdatedAt: time.Date(2026, 7, 18, 4, 0, 0, 0, time.UTC),
	}
	text := formatIncidentEmailText("incident.opened", incident)
	html := formatIncidentHTML("incident.opened", incident)
	if len(text) > maxNotificationEmailTextBytes || !utf8.ValidString(text) {
		t.Fatalf("plain alternative exceeded relay limits: bytes=%d valid_utf8=%t", len(text), utf8.ValidString(text))
	}
	if len(html) > 64*1024 || !utf8.ValidString(html) {
		t.Fatalf("HTML alternative exceeded relay limits: bytes=%d valid_utf8=%t", len(html), utf8.ValidString(html))
	}
	if subject := formatEmailSubject("incident.opened", incident); len([]rune(subject)) > 200 {
		t.Fatalf("email subject exceeded relay limit: runes=%d", len([]rune(subject)))
	}
}

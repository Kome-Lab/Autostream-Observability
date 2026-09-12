package notifications

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/example/autostream-observability/internal/store"
)

type recordingEmailRelay struct {
	recipients  []string
	subject     string
	text        string
	html        string
	attempts    int
	err         error
	deadline    time.Time
	hasDeadline bool
}

func (r *recordingEmailRelay) SendNotificationEmail(ctx context.Context, recipients []string, subject, text string) error {
	return r.record(ctx, recipients, subject, text, "")
}

func (r *recordingEmailRelay) SendNotificationEmailHTML(ctx context.Context, recipients []string, subject, text, html string) error {
	return r.record(ctx, recipients, subject, text, html)
}

func (r *recordingEmailRelay) record(ctx context.Context, recipients []string, subject, text, html string) error {
	r.attempts++
	r.recipients = append([]string(nil), recipients...)
	r.subject = subject
	r.text = text
	r.html = html
	r.deadline, r.hasDeadline = ctx.Deadline()
	return r.err
}

type codedEmailRelayError string

func (e codedEmailRelayError) Error() string { return string(e) }

func (e codedEmailRelayError) SafeDeliveryCode() string { return string(e) }

func TestEmailNotifierUsesGlobalSMTPRelay(t *testing.T) {
	relay := &recordingEmailRelay{}
	notifier := EmailNotifier{
		Channel: store.NotificationChannel{
			Type:              "email",
			UseGlobalSMTP:     true,
			EmailRecipients:   []string{"ops@example.com"},
			MaskedEmailTarget: "o***s@<EMAIL_DOMAIN>",
		},
		Relay: relay,
	}
	results, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-global", Rule: "encoder_down", Severity: "critical", Status: "open", SummaryJA: "Encoder process stopped.", ServiceID: "enc-01"})
	if err != nil {
		t.Fatal(err)
	}
	if relay.attempts != 1 || len(relay.recipients) != 1 || relay.recipients[0] != "ops@example.com" || relay.subject != "[AutoStream] CRITICAL encoder_down | インシデント発生: encoder_down" || !strings.Contains(relay.text, "Encoder process stopped.") {
		t.Fatalf("unexpected global email relay call: %#v", relay)
	}
	if len(results) != 1 || results[0].Status != "success" || results[0].Target != "o***s@<EMAIL_DOMAIN>" {
		t.Fatalf("unexpected result: %#v", results)
	}
}

func TestEmailNotifierReturnsOnlySafeGlobalSMTPFailureCodeWithoutRetry(t *testing.T) {
	for _, code := range []string{"smtp_auth_failed", "rate_limited"} {
		t.Run(code, func(t *testing.T) {
			relay := &recordingEmailRelay{err: codedEmailRelayError(code)}
			notifier := EmailNotifier{
				Channel: store.NotificationChannel{
					Type:              "email",
					UseGlobalSMTP:     true,
					EmailRecipients:   []string{"ops@example.com"},
					MaskedEmailTarget: "o***s@<EMAIL_DOMAIN>",
				},
				Relay: relay,
			}
			results, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-global-failure", Rule: "encoder_down", Severity: "critical", Status: "open", SummaryJA: "Encoder process stopped.", ServiceID: "enc-01"})
			if err == nil || relay.attempts != 1 {
				t.Fatalf("expected a single relay attempt, attempts=%d err=%v", relay.attempts, err)
			}
			if len(results) != 1 || results[0].Status != "failure" || results[0].Error != code || strings.Contains(results[0].Error, "example.com") {
				t.Fatalf("unexpected safe failure result: %#v", results)
			}
		})
	}
}

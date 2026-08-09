package httpapi

import (
	"testing"
	"time"

	"github.com/example/autostream-observability/internal/notifications"
	"github.com/example/autostream-observability/internal/store"
)

func TestNotificationDeduperBoundsEntriesExpiresAndAllowsNewLifecycle(t *testing.T) {
	now := time.Date(2026, time.August, 9, 1, 0, 0, 0, time.UTC)
	deduper := notificationDeduper{window: time.Minute, maxEntries: 2}
	incident := store.Incident{
		Rule:                     "worker_event_send_failed",
		Severity:                 "warning",
		Status:                   "open",
		ServiceID:                "worker-01",
		StreamID:                 "stream-01",
		NotificationResourceType: "stream",
		NotificationResourceID:   "stream-01",
	}

	opened := deduper.reserve("incident.opened", incident, now)
	if !opened.allowed {
		t.Fatal("first lifecycle event was unexpectedly suppressed")
	}
	duplicate := deduper.reserve("incident.opened", incident, now.Add(time.Second))
	if duplicate.allowed || !duplicate.recordSuppression || duplicate.suppressionCount != 1 {
		t.Fatalf("duplicate reservation = %#v", duplicate)
	}
	if next := deduper.reserve("incident.opened", incident, now.Add(2*time.Second)); next.allowed || next.recordSuppression || next.suppressionCount != 2 {
		t.Fatalf("subsequent duplicate reservation = %#v", next)
	}
	if update := deduper.reserve("incident.updated", incident, now.Add(3*time.Second)); !update.allowed {
		t.Fatalf("initial update transition was unexpectedly suppressed: %#v", update)
	}
	acknowledgedIncident := incident
	acknowledgedIncident.Status = "acknowledged"
	if acknowledged := deduper.reserve("incident.updated", acknowledgedIncident, now.Add(4*time.Second)); !acknowledged.allowed {
		t.Fatalf("changed update status was unexpectedly suppressed: %#v", acknowledged)
	}

	resolvedIncident := incident
	resolvedIncident.Status = "resolved"
	if resolved := deduper.reserve("incident.resolved", resolvedIncident, now.Add(5*time.Second)); !resolved.allowed {
		t.Fatalf("resolved transition was unexpectedly suppressed: %#v", resolved)
	}
	if reopened := deduper.reserve("incident.opened", incident, now.Add(6*time.Second)); !reopened.allowed {
		t.Fatalf("new lifecycle after resolution was unexpectedly suppressed: %#v", reopened)
	}

	for _, resourceID := range []string{"stream-02", "stream-03", "stream-04"} {
		next := incident
		next.NotificationResourceID = resourceID
		next.StreamID = resourceID
		if reservation := deduper.reserve("incident.opened", next, now.Add(7*time.Second)); !reservation.allowed {
			t.Fatalf("distinct incident %q was unexpectedly suppressed: %#v", resourceID, reservation)
		}
	}
	if len(deduper.entries) > 2 {
		t.Fatalf("dedupe entry cap was not enforced: %d entries", len(deduper.entries))
	}

	expiringDeduper := notificationDeduper{window: time.Minute, maxEntries: 2}
	if initial := expiringDeduper.reserve("incident.opened", incident, now); !initial.allowed {
		t.Fatalf("expiry initial reservation = %#v", initial)
	}
	if repeated := expiringDeduper.reserve("incident.opened", incident, now.Add(time.Second)); repeated.allowed {
		t.Fatalf("expiry duplicate reservation = %#v", repeated)
	}
	expired := expiringDeduper.reserve("incident.opened", incident, now.Add(2*time.Minute))
	if !expired.allowed {
		t.Fatalf("expired semantic event remained suppressed: %#v", expired)
	}
}

func TestNotificationDeduperDoesNotCoalesceAdministrativeAuditEvents(t *testing.T) {
	deduper := notificationDeduper{}
	incident := store.Incident{Rule: "oauth_accounts.update", Status: "success", ServiceID: "control-panel"}
	for i := 0; i < 2; i++ {
		reservation := deduper.reserve("admin.audit", incident, time.Date(2026, time.August, 9, 1, 0, i, 0, time.UTC))
		if !reservation.allowed || reservation.key != "" {
			t.Fatalf("admin audit reservation = %#v", reservation)
		}
	}
}

func TestNotificationDeduperRetainsSuccessfulChannelReceiptsAfterPartialDelivery(t *testing.T) {
	now := time.Date(2026, time.August, 9, 1, 0, 0, 0, time.UTC)
	deduper := notificationDeduper{}
	incident := store.Incident{Rule: "worker_event_send_failed", Status: "open", ServiceID: "worker-01"}
	first := deduper.reserve("incident.opened", incident, now)
	if !first.allowed {
		t.Fatalf("first reservation = %#v", first)
	}
	deduper.complete(first, []notifications.DeliveryResult{
		{Channel: "email", ChannelID: "email-01", Status: "success"},
		{Channel: "discord", ChannelID: "discord-01", Status: "failure"},
	})
	retry := deduper.reserve("incident.opened", incident, now.Add(time.Second))
	if !retry.allowed {
		t.Fatalf("partial delivery must remain retryable: %#v", retry)
	}
	if _, ok := retry.successfulChannelIDs["email-01"]; !ok || len(retry.successfulChannelIDs) != 1 {
		t.Fatalf("successful channel receipts were not retained: %#v", retry)
	}
	deduper.complete(retry, []notifications.DeliveryResult{{Channel: "discord", ChannelID: "discord-01", Status: "success"}})
	if duplicate := deduper.reserve("incident.opened", incident, now.Add(2*time.Second)); duplicate.allowed {
		t.Fatalf("fully delivered event was not coalesced: %#v", duplicate)
	}
}

package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/example/autostream-observability/internal/notifications"
	"github.com/example/autostream-observability/internal/store"
)

const (
	notificationDedupeWindow     = 2 * time.Minute
	notificationDedupeMaxEntries = 512
)

// notificationDeduper is deliberately process-local. It protects a configured
// notification channel from a short retry or event fan-out storm without
// turning the notification-delivery history into an authority for incident
// state. Incident, signal, and remediation state remain durable in the store.
type notificationDeduper struct {
	mu         sync.Mutex
	entries    map[string]notificationDedupeEntry
	window     time.Duration
	maxEntries int
}

type notificationDedupeEntry struct {
	base                 string
	expiresAt            time.Time
	suppressionCount     int
	suppressionRecorded  bool
	inFlight             bool
	fullyDelivered       bool
	successfulChannelIDs map[string]struct{}
}

type notificationDedupeReservation struct {
	key                  string
	allowed              bool
	suppressionCount     int
	recordSuppression    bool
	successfulChannelIDs map[string]struct{}
}

func (d *notificationDeduper) reserve(eventType string, incident store.Incident, now time.Time) notificationDedupeReservation {
	eventType = strings.TrimSpace(eventType)
	if !notificationEventDedupeEligible(eventType) {
		return notificationDedupeReservation{allowed: true}
	}
	key := notificationDedupeKey(eventType, incident)
	base := notificationDedupeBase(incident)
	now = now.UTC()

	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneLocked(now)
	if eventType == "incident.resolved" {
		// A resolution closes this lifecycle. A newly opened incident with the
		// same external resource must be able to notify immediately afterwards.
		for existingKey, entry := range d.entries {
			if existingKey != key && entry.base == base {
				delete(d.entries, existingKey)
			}
		}
	}
	if entry, ok := d.entries[key]; ok && entry.expiresAt.After(now) {
		if !entry.inFlight && !entry.fullyDelivered {
			entry.inFlight = true
			d.entries[key] = entry
			return notificationDedupeReservation{
				key:                  key,
				allowed:              true,
				successfulChannelIDs: cloneChannelIDSet(entry.successfulChannelIDs),
			}
		}
		entry.suppressionCount++
		record := !entry.suppressionRecorded
		entry.suppressionRecorded = true
		d.entries[key] = entry
		return notificationDedupeReservation{
			key:               key,
			allowed:           false,
			suppressionCount:  entry.suppressionCount,
			recordSuppression: record,
		}
	}
	d.evictForInsertLocked()
	d.entries[key] = notificationDedupeEntry{
		base:                 base,
		expiresAt:            now.Add(d.dedupeWindow()),
		inFlight:             true,
		successfulChannelIDs: make(map[string]struct{}),
	}
	return notificationDedupeReservation{key: key, allowed: true}
}

func (d *notificationDeduper) complete(reservation notificationDedupeReservation, results []notifications.DeliveryResult) {
	if reservation.key == "" || !reservation.allowed {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	entry, ok := d.entries[reservation.key]
	if !ok {
		return
	}
	entry.inFlight = false
	entry.fullyDelivered = notificationDeliverySucceeded(results)
	if entry.successfulChannelIDs == nil {
		entry.successfulChannelIDs = make(map[string]struct{})
	}
	for _, result := range results {
		if !notificationDeliverySucceeded([]notifications.DeliveryResult{result}) {
			continue
		}
		if channelID := strings.TrimSpace(result.ChannelID); channelID != "" {
			entry.successfulChannelIDs[channelID] = struct{}{}
		}
	}
	d.entries[reservation.key] = entry
}

func cloneChannelIDSet(source map[string]struct{}) map[string]struct{} {
	if len(source) == 0 {
		return nil
	}
	cloned := make(map[string]struct{}, len(source))
	for channelID := range source {
		cloned[channelID] = struct{}{}
	}
	return cloned
}

func (d *notificationDeduper) dedupeWindow() time.Duration {
	if d.window > 0 {
		return d.window
	}
	return notificationDedupeWindow
}

func (d *notificationDeduper) dedupeMaxEntries() int {
	if d.maxEntries > 0 {
		return d.maxEntries
	}
	return notificationDedupeMaxEntries
}

func (d *notificationDeduper) pruneLocked(now time.Time) {
	for key, entry := range d.entries {
		if !entry.expiresAt.After(now) {
			delete(d.entries, key)
		}
	}
}

func (d *notificationDeduper) evictForInsertLocked() {
	if d.entries == nil {
		d.entries = make(map[string]notificationDedupeEntry)
	}
	for len(d.entries) >= d.dedupeMaxEntries() {
		var oldestKey string
		var oldest time.Time
		for key, entry := range d.entries {
			if oldestKey == "" || entry.expiresAt.Before(oldest) {
				oldestKey = key
				oldest = entry.expiresAt
			}
		}
		if oldestKey == "" {
			return
		}
		delete(d.entries, oldestKey)
	}
}

func notificationEventDedupeEligible(eventType string) bool {
	switch eventType {
	case "incident.opened", "incident.updated", "incident.resolved", "diagnostic.created", "remediation.pending_approval", "remediation.executed":
		return true
	default:
		// Administrative audit records are intentionally not coalesced here.
		// They represent user-visible security and configuration actions.
		return false
	}
}

func notificationDedupeKey(eventType string, incident store.Incident) string {
	return notificationDedupeHash(struct {
		EventType        string `json:"event_type"`
		IncidentID       string `json:"incident_id"`
		Rule             string `json:"rule"`
		Severity         string `json:"severity"`
		Status           string `json:"status"`
		Summary          string `json:"summary"`
		SourceSummary    string `json:"source_summary"`
		ServiceID        string `json:"service_id"`
		StreamID         string `json:"stream_id"`
		ResourceType     string `json:"resource_type"`
		ResourceID       string `json:"resource_id"`
		Actor            string `json:"actor"`
		Details          string `json:"details"`
		DiagnosticReport any    `json:"diagnostic_report"`
	}{
		EventType:        eventType,
		IncidentID:       strings.TrimSpace(incident.ID),
		Rule:             strings.TrimSpace(incident.Rule),
		Severity:         strings.TrimSpace(incident.Severity),
		Status:           strings.TrimSpace(incident.Status),
		Summary:          strings.TrimSpace(incident.SummaryJA),
		SourceSummary:    strings.TrimSpace(incident.SourceSummary),
		ServiceID:        strings.TrimSpace(incident.ServiceID),
		StreamID:         strings.TrimSpace(incident.StreamID),
		ResourceType:     strings.TrimSpace(incident.NotificationResourceType),
		ResourceID:       strings.TrimSpace(incident.NotificationResourceID),
		Actor:            strings.TrimSpace(incident.NotificationActor),
		Details:          strings.TrimSpace(incident.NotificationDetails),
		DiagnosticReport: incident.Report,
	})
}

func notificationDedupeBase(incident store.Incident) string {
	return notificationDedupeHash(struct {
		IncidentID   string `json:"incident_id"`
		Rule         string `json:"rule"`
		ServiceID    string `json:"service_id"`
		StreamID     string `json:"stream_id"`
		ResourceType string `json:"resource_type"`
		ResourceID   string `json:"resource_id"`
	}{
		IncidentID:   strings.TrimSpace(incident.ID),
		Rule:         strings.TrimSpace(incident.Rule),
		ServiceID:    strings.TrimSpace(incident.ServiceID),
		StreamID:     strings.TrimSpace(incident.StreamID),
		ResourceType: strings.TrimSpace(incident.NotificationResourceType),
		ResourceID:   strings.TrimSpace(incident.NotificationResourceID),
	})
}

func notificationDedupeHash(value any) string {
	payload, err := json.Marshal(value)
	if err != nil {
		payload = []byte(fmt.Sprintf("%#v", value))
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

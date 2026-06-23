package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/example/autostream-observability/internal/diagnostics"
)

type Signal struct {
	ID          string         `json:"id"`
	Type        string         `json:"type"`
	Name        string         `json:"name"`
	ServiceID   string         `json:"service_id"`
	ServiceType string         `json:"service_type"`
	StreamID    string         `json:"stream_id,omitempty"`
	Status      string         `json:"status,omitempty"`
	Value       *float64       `json:"value,omitempty"`
	Attributes  map[string]any `json:"attributes,omitempty"`
	Timestamp   time.Time      `json:"timestamp"`
	CreatedAt   time.Time      `json:"created_at"`
}

type Incident struct {
	ID         string             `json:"id"`
	Rule       string             `json:"rule"`
	Severity   string             `json:"severity"`
	Status     string             `json:"status"`
	SummaryJA  string             `json:"summary_ja"`
	ServiceID  string             `json:"service_id"`
	StreamID   string             `json:"stream_id,omitempty"`
	SignalID   string             `json:"signal_id"`
	Report     diagnostics.Report `json:"diagnostic_report"`
	OpenedAt   time.Time          `json:"opened_at"`
	UpdatedAt  time.Time          `json:"updated_at"`
	ResolvedAt *time.Time         `json:"resolved_at,omitempty"`
}

type NotificationDelivery struct {
	ID         string         `json:"id"`
	EventType  string         `json:"event_type"`
	Channel    string         `json:"channel"`
	Target     string         `json:"target"`
	IncidentID string         `json:"incident_id,omitempty"`
	Status     string         `json:"status"`
	Error      string         `json:"error,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
}

type NotificationChannel struct {
	ID                     string    `json:"id"`
	Name                   string    `json:"name"`
	Type                   string    `json:"type"`
	Enabled                bool      `json:"enabled"`
	WebhookURL             string    `json:"-"`
	MaskedWebhookURL       string    `json:"masked_webhook_url,omitempty"`
	EmailRecipients        []string  `json:"email_recipients,omitempty"`
	SMTPHost               string    `json:"smtp_host,omitempty"`
	SMTPPort               int       `json:"smtp_port,omitempty"`
	SMTPTLS                bool      `json:"smtp_tls,omitempty"`
	SMTPFrom               string    `json:"smtp_from,omitempty"`
	SMTPUsername           string    `json:"smtp_username,omitempty"`
	SMTPPassword           string    `json:"-"`
	SMTPPasswordConfigured bool      `json:"smtp_password_configured,omitempty"`
	MaskedEmailTarget      string    `json:"masked_email_target,omitempty"`
	SeverityFilter         []string  `json:"severity_filter,omitempty"`
	EventTypeFilter        []string  `json:"event_type_filter,omitempty"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

func (c NotificationChannel) MarshalJSON() ([]byte, error) {
	type publicNotificationChannel struct {
		ID                     string    `json:"id"`
		Name                   string    `json:"name"`
		Type                   string    `json:"type"`
		Enabled                bool      `json:"enabled"`
		MaskedWebhookURL       string    `json:"masked_webhook_url,omitempty"`
		SMTPPasswordConfigured bool      `json:"smtp_password_configured,omitempty"`
		MaskedEmailTarget      string    `json:"masked_email_target,omitempty"`
		SeverityFilter         []string  `json:"severity_filter,omitempty"`
		EventTypeFilter        []string  `json:"event_type_filter,omitempty"`
		CreatedAt              time.Time `json:"created_at"`
		UpdatedAt              time.Time `json:"updated_at"`
	}
	return json.Marshal(publicNotificationChannel{
		ID:                     c.ID,
		Name:                   c.Name,
		Type:                   c.Type,
		Enabled:                c.Enabled,
		MaskedWebhookURL:       c.MaskedWebhookURL,
		SMTPPasswordConfigured: c.SMTPPasswordConfigured,
		MaskedEmailTarget:      c.MaskedEmailTarget,
		SeverityFilter:         c.SeverityFilter,
		EventTypeFilter:        c.EventTypeFilter,
		CreatedAt:              c.CreatedAt,
		UpdatedAt:              c.UpdatedAt,
	})
}

type RemediationAction struct {
	ID               string     `json:"id"`
	IncidentID       string     `json:"incident_id"`
	Action           string     `json:"action"`
	Mode             string     `json:"mode"`
	Status           string     `json:"status"`
	SafeAuto         bool       `json:"safe_auto"`
	RequiresApproval bool       `json:"requires_approval"`
	Result           string     `json:"result,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	ExecutedAt       *time.Time `json:"executed_at,omitempty"`
}

type MetricSnapshot struct {
	Name        string         `json:"name"`
	ServiceID   string         `json:"service_id"`
	ServiceType string         `json:"service_type"`
	StreamID    string         `json:"stream_id,omitempty"`
	Status      string         `json:"status,omitempty"`
	Value       *float64       `json:"value,omitempty"`
	Attributes  map[string]any `json:"attributes,omitempty"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

type Store interface {
	SaveSignal(ctx context.Context, signal Signal) (Signal, error)
	ListSignals(ctx context.Context, limit int) ([]Signal, error)
	UpsertIncident(ctx context.Context, incident Incident) (Incident, bool, error)
	ListIncidents(ctx context.Context) ([]Incident, error)
	GetIncident(ctx context.Context, id string) (Incident, error)
	UpdateIncidentStatus(ctx context.Context, id, status string) (Incident, error)
	SaveNotificationDelivery(ctx context.Context, delivery NotificationDelivery) (NotificationDelivery, error)
	ListNotificationDeliveries(ctx context.Context) ([]NotificationDelivery, error)
	ListNotificationChannels(ctx context.Context) ([]NotificationChannel, error)
	CreateNotificationChannel(ctx context.Context, channel NotificationChannel) (NotificationChannel, error)
	GetNotificationChannel(ctx context.Context, id string) (NotificationChannel, error)
	UpdateNotificationChannel(ctx context.Context, channel NotificationChannel) (NotificationChannel, error)
	DeleteNotificationChannel(ctx context.Context, id string) error
	CreateRemediationAction(ctx context.Context, action RemediationAction) (RemediationAction, error)
	ListRemediationActions(ctx context.Context) ([]RemediationAction, error)
	GetRemediationAction(ctx context.Context, id string) (RemediationAction, error)
	UpdateRemediationAction(ctx context.Context, action RemediationAction) (RemediationAction, error)
}

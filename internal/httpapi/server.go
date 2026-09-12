package httpapi

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/example/autostream-observability/internal/auth"
	"github.com/example/autostream-observability/internal/notifications"
	"github.com/example/autostream-observability/internal/store"
)

type Server struct {
	serviceType        string
	updaterIdentity    *UpdaterIdentityLatch
	store              store.Store
	ingestAuth         auth.Verifier
	adminAuth          auth.Verifier
	notifier           notifications.Notifier
	emailRelay         notifications.EmailRelay
	executor           controlExecutor
	rateLimiter        *rateLimiter
	logger             *log.Logger
	notificationDedupe notificationDeduper
}

const (
	adminScopeRead                = "observability.read"
	adminScopeIngest              = "observability.ingest"
	adminScopeIncidentsUpdate     = "incidents.update"
	adminScopeDiagnosticsRun      = "diagnostics.run"
	adminScopeNotificationsRead   = "notifications.read"
	adminScopeNotificationsManage = "notifications.manage"
	adminScopeRemediationRead     = "remediation.read"
	adminScopeRemediationApprove  = "remediation.approve"
	adminScopeRemediationExecute  = "remediation.execute"
	notificationWebhookTimeout    = 5 * time.Second
	notificationEmailTimeout      = 30 * time.Second
	notificationFanoutTimeout     = 35 * time.Second
)

func NewServer(serviceType string) http.Handler {
	return NewServerWithStore(serviceType, store.NewMemoryStore())
}

func NewServerWithStore(serviceType string, st store.Store) http.Handler {
	return NewServerWithStoreAuthz(serviceType, st, auth.Verifier{}, auth.Verifier{})
}

func NewServerWithStoreAndAuth(serviceType string, st store.Store, verifier auth.Verifier) http.Handler {
	return NewServerWithStoreAuthAndNotifier(serviceType, st, verifier, notifications.ChannelNotifier{Store: st, Fallback: notifications.FromEnv(), Timeout: notificationWebhookTimeout, EmailTimeout: notificationEmailTimeout, RetryMax: 3, RetryBaseDelay: time.Second})
}

func NewServerWithStoreAuthAndNotifier(serviceType string, st store.Store, verifier auth.Verifier, notifier notifications.Notifier) http.Handler {
	return NewServerWithStoreAuthNotifierAndExecutor(serviceType, st, verifier, notifier, envControlExecutor{})
}

func NewServerWithStoreAuthNotifierAndExecutor(serviceType string, st store.Store, verifier auth.Verifier, notifier notifications.Notifier, executor controlExecutor) http.Handler {
	return NewServerWithStoreAuthzNotifierAndExecutor(serviceType, st, verifier, verifier, notifier, executor)
}

func NewServerWithStoreAuthz(serviceType string, st store.Store, ingestVerifier, adminVerifier auth.Verifier) http.Handler {
	return NewServerWithStoreAuthzAndUpdaterIdentity(serviceType, st, ingestVerifier, adminVerifier, NewUpdaterIdentityLatch(serviceType))
}

func NewServerWithStoreAuthzAndUpdaterIdentity(serviceType string, st store.Store, ingestVerifier, adminVerifier auth.Verifier, updaterIdentity *UpdaterIdentityLatch) http.Handler {
	return NewServerWithStoreAuthzNotifierExecutorEmailRelayAndUpdaterIdentity(serviceType, st, ingestVerifier, adminVerifier, notifications.ChannelNotifier{Store: st, Fallback: notifications.FromEnv(), Timeout: notificationWebhookTimeout, EmailTimeout: notificationEmailTimeout, RetryMax: 3, RetryBaseDelay: time.Second}, envControlExecutor{}, envEmailRelay{}, updaterIdentity)
}

func NewServerWithStoreAuthzNotifierAndExecutor(serviceType string, st store.Store, ingestVerifier, adminVerifier auth.Verifier, notifier notifications.Notifier, executor controlExecutor) http.Handler {
	return NewServerWithStoreAuthzNotifierExecutorAndEmailRelay(serviceType, st, ingestVerifier, adminVerifier, notifier, executor, envEmailRelay{})
}

func NewServerWithStoreAuthzNotifierExecutorAndEmailRelay(serviceType string, st store.Store, ingestVerifier, adminVerifier auth.Verifier, notifier notifications.Notifier, executor controlExecutor, emailRelay notifications.EmailRelay) http.Handler {
	return NewServerWithStoreAuthzNotifierExecutorEmailRelayAndUpdaterIdentity(serviceType, st, ingestVerifier, adminVerifier, notifier, executor, emailRelay, NewUpdaterIdentityLatch(serviceType))
}

func NewServerWithStoreAuthzNotifierExecutorEmailRelayAndUpdaterIdentity(serviceType string, st store.Store, ingestVerifier, adminVerifier auth.Verifier, notifier notifications.Notifier, executor controlExecutor, emailRelay notifications.EmailRelay, updaterIdentity *UpdaterIdentityLatch) http.Handler {
	if st == nil {
		st = store.NewMemoryStore()
	}
	if updaterIdentity == nil {
		panic("observability updater identity latch is required")
	}
	if _, err := updaterIdentity.ResolveFromEnv(); err != nil && !errors.Is(err, ErrUpdaterIdentityPending) {
		panic(err)
	}
	switch configured := notifier.(type) {
	case notifications.ChannelNotifier:
		if configured.EmailRelay == nil {
			configured.EmailRelay = emailRelay
		}
		notifier = configured
	case *notifications.ChannelNotifier:
		if configured != nil && configured.EmailRelay == nil {
			configured.EmailRelay = emailRelay
		}
	}
	s := &Server{serviceType: serviceType, updaterIdentity: updaterIdentity, store: st, ingestAuth: ingestVerifier, adminAuth: adminVerifier, notifier: notifier, emailRelay: emailRelay, executor: executor, rateLimiter: rateLimiterFromEnv(st), logger: log.Default()}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.root)
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /status", s.status)
	mux.HandleFunc("GET /updater/version", s.updaterVersion)
	mux.HandleFunc("POST /heartbeat", s.heartbeat)
	mux.HandleFunc("POST /signals", s.ingestSignal)
	mux.HandleFunc("GET /signals", s.listSignals)
	mux.HandleFunc("GET /metrics", s.listMetrics)
	mux.HandleFunc("GET /diagnostics", s.listDiagnostics)
	mux.HandleFunc("GET /incidents", s.listIncidents)
	mux.HandleFunc("GET /incidents/{id}", s.getIncident)
	mux.HandleFunc("POST /incidents/{id}/diagnostics/rerun", s.rerunIncidentDiagnostics)
	mux.HandleFunc("POST /incidents/{id}/acknowledge", s.acknowledgeIncident)
	mux.HandleFunc("POST /incidents/{id}/resolve", s.resolveIncident)
	mux.HandleFunc("GET /notification-deliveries", s.listNotificationDeliveries)
	mux.HandleFunc("GET /notification-channels", s.listNotificationChannels)
	mux.HandleFunc("POST /notification-channels", s.createNotificationChannel)
	mux.HandleFunc("GET /notification-channels/{id}", s.getNotificationChannel)
	mux.HandleFunc("PUT /notification-channels/{id}", s.updateNotificationChannel)
	mux.HandleFunc("DELETE /notification-channels/{id}", s.deleteNotificationChannel)
	mux.HandleFunc("POST /notification-channels/{id}/test", s.testNotificationChannel)
	mux.HandleFunc("POST /notification-events", s.createNotificationEvent)
	mux.HandleFunc("GET /remediation-actions", s.listRemediationActions)
	mux.HandleFunc("GET /remediation-actions/{id}/dispatch-context", s.getRemediationDispatchContext)
	mux.HandleFunc("POST /remediation-actions/{id}/approve", s.approveRemediationAction)
	mux.HandleFunc("POST /remediation-actions/{id}/execute", s.executeRemediationAction)
	return securityHeaders(s.rateLimitSensitive(mux))
}

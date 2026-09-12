package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/example/autostream-observability/internal/control"
	"github.com/example/autostream-observability/internal/version"
)

type Status struct {
	ServiceType string    `json:"service_type"`
	ServiceID   string    `json:"service_id"`
	Status      string    `json:"status"`
	CheckedAt   time.Time `json:"checked_at"`
}

func (s *Server) root(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service_type": s.serviceType,
		"service_id":   observabilityServiceID(),
		"status":       "ready",
		"checked_at":   time.Now().UTC(),
		"endpoints": map[string]any{
			"health":  map[string]any{"path": "/health", "auth_required": false},
			"status":  map[string]any{"path": "/status", "auth_required": false},
			"metrics": map[string]any{"path": "/metrics", "auth_required": true},
		},
	})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, Status{ServiceType: s.serviceType, ServiceID: observabilityServiceID(), Status: "ready", CheckedAt: time.Now().UTC()})
}

func (s *Server) updaterVersion(w http.ResponseWriter, _ *http.Request) {
	identity, err := s.updaterIdentity.ResolveFromEnv()
	if err != nil {
		code := "updater_identity_invalid"
		if errors.Is(err, ErrUpdaterIdentityPending) {
			code = "updater_identity_pending"
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"code": code})
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Version        string `json:"version"`
		ServiceID      string `json:"service_id"`
		ServiceType    string `json:"service_type"`
		ConfigRevision int64  `json:"config_revision"`
	}{
		Version:        version.Current(),
		ServiceID:      identity.ServiceID,
		ServiceType:    identity.ServiceType,
		ConfigRevision: identity.ConfigRevision,
	})
}

func observabilityServiceID() string {
	return strings.TrimSpace(control.FromEnv().ServiceID)
}

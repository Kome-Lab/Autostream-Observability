package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/example/autostream-observability/internal/store"
)

func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeRead) {
		return
	}
	before, beforeID, err := parseHistoryCursor(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_history_cursor"})
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	if status != "" && status != "open" && status != "acknowledged" && status != "investigating" && status != "mitigated" && status != "resolved" && status != "ignored" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_incident_status"})
		return
	}
	incidents, err := s.store.ListIncidentHistory(r.Context(), parseLimit(r, 200), before, beforeID, status)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "list_incidents_failed"})
		return
	}
	writeJSON(w, http.StatusOK, incidents)
}

func parseHistoryCursor(r *http.Request) (time.Time, string, error) {
	rawBefore := strings.TrimSpace(r.URL.Query().Get("before"))
	beforeID := strings.TrimSpace(r.URL.Query().Get("before_id"))
	if rawBefore == "" && beforeID == "" {
		return time.Time{}, "", nil
	}
	if rawBefore == "" || beforeID == "" {
		return time.Time{}, "", errors.New("before and before_id are both required")
	}
	before, err := time.Parse(time.RFC3339Nano, rawBefore)
	if err != nil {
		return time.Time{}, "", err
	}
	return before.UTC(), beforeID, nil
}

func (s *Server) getIncident(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeRead) {
		return
	}
	incident, err := s.store.GetIncident(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"code": "not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "get_incident_failed"})
		return
	}
	writeJSON(w, http.StatusOK, incident)
}

func (s *Server) acknowledgeIncident(w http.ResponseWriter, r *http.Request) {
	s.updateIncidentStatus(w, r, "acknowledged")
}

func (s *Server) resolveIncident(w http.ResponseWriter, r *http.Request) {
	s.updateIncidentStatus(w, r, "resolved")
}

func (s *Server) updateIncidentStatus(w http.ResponseWriter, r *http.Request, status string) {
	if !s.authorizeAdmin(w, r, adminScopeIncidentsUpdate) {
		return
	}
	incident, err := s.store.UpdateIncidentStatus(r.Context(), r.PathValue("id"), status)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"code": "not_found"})
		return
	}
	if errors.Is(err, store.ErrInvalidStatus) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_incident_status"})
		return
	}
	if errors.Is(err, store.ErrInvalidTransition) {
		writeJSON(w, http.StatusConflict, map[string]string{"code": "invalid_incident_transition"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "update_incident_failed"})
		return
	}
	eventType := "incident.updated"
	if status == "resolved" {
		eventType = "incident.resolved"
	}
	if incident.StatusChanged {
		s.notifyIncidentEvent(r, eventType, incident)
	}
	writeJSON(w, http.StatusOK, incident)
}

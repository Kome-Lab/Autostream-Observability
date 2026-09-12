package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/example/autostream-observability/internal/diagnostics"
	"github.com/example/autostream-observability/internal/store"
)

type DiagnosticReportView struct {
	IncidentID string             `json:"incident_id"`
	Rule       string             `json:"rule"`
	Severity   string             `json:"severity"`
	Status     string             `json:"status"`
	ServiceID  string             `json:"service_id"`
	StreamID   string             `json:"stream_id,omitempty"`
	Report     diagnostics.Report `json:"diagnostic_report"`
	UpdatedAt  time.Time          `json:"updated_at"`
}

type diagnosticRerunResponse struct {
	Incident store.Incident `json:"incident"`
	Outcome  string         `json:"outcome"`
	Reason   string         `json:"reason,omitempty"`
}

func (s *Server) listDiagnostics(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeRead) {
		return
	}
	incidents, err := s.store.ListIncidents(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "list_diagnostics_failed"})
		return
	}
	out := make([]DiagnosticReportView, 0, len(incidents))
	for _, incident := range incidents {
		out = append(out, DiagnosticReportView{
			IncidentID: incident.ID,
			Rule:       incident.Rule,
			Severity:   incident.Severity,
			Status:     incident.Status,
			ServiceID:  incident.ServiceID,
			StreamID:   incident.StreamID,
			Report:     incident.Report,
			UpdatedAt:  incident.UpdatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) rerunIncidentDiagnostics(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeDiagnosticsRun) {
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
	if strings.TrimSpace(incident.SignalID) == "" {
		writeJSON(w, http.StatusOK, diagnosticRerunResponse{Incident: incident, Outcome: "inconclusive", Reason: "saved_signal_missing"})
		return
	}
	signal, err := s.store.GetSignal(r.Context(), incident.SignalID)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusOK, diagnosticRerunResponse{Incident: incident, Outcome: "inconclusive", Reason: "saved_signal_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "get_saved_signal_failed"})
		return
	}
	report, matched := diagnosticReportForSavedSignal(incident, signal)
	if !matched {
		writeJSON(w, http.StatusOK, diagnosticRerunResponse{Incident: incident, Outcome: "inconclusive", Reason: "saved_signal_no_longer_matches_rule"})
		return
	}
	updated, reportUpdated, err := s.store.UpdateIncidentDiagnostic(r.Context(), incident.ID, incident.SignalID, report)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"code": "not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "update_diagnostic_report_failed"})
		return
	}
	if !reportUpdated {
		writeJSON(w, http.StatusOK, diagnosticRerunResponse{Incident: updated, Outcome: "inconclusive", Reason: "incident_updated_during_rerun"})
		return
	}
	writeJSON(w, http.StatusOK, diagnosticRerunResponse{Incident: updated, Outcome: "evaluated"})
}

func diagnosticReportForSavedSignal(incident store.Incident, signal store.Signal) (diagnostics.Report, bool) {
	for _, detected := range detectSignal(signal) {
		if detected.Rule == incident.Rule {
			return diagnostics.JapaneseReport(detected.Rule, diagnosticEvidence(signal)), true
		}
	}
	return diagnostics.Report{}, false
}

func diagnosticEvidence(signal store.Signal) []string {
	evidence := []string{
		"signal_id=" + signal.ID,
		"signal_name=" + signal.Name,
		"service_id=" + signal.ServiceID,
	}
	if signal.StreamID != "" {
		evidence = append(evidence, "stream_id="+signal.StreamID)
	}
	return append(evidence, safeAttributeEvidence(signal.Attributes)...)
}

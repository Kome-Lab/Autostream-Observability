package httpapi

import (
	"context"
	"net/http"

	"github.com/example/autostream-observability/internal/detection"
	"github.com/example/autostream-observability/internal/diagnostics"
	"github.com/example/autostream-observability/internal/store"
)

type IngestResponse struct {
	Signal    store.Signal     `json:"signal"`
	Incidents []store.Incident `json:"incidents"`
}

func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request) {
	if !s.ingestAuthorized(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"code": "invalid_service_token"})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func (s *Server) ingestSignal(w http.ResponseWriter, r *http.Request) {
	tokenSubject, ok := s.ingestAuth.VerifyRequestSubject(r)
	if !ok {
		authenticated, authorized := s.adminAuth.AuthorizeRequest(r, adminScopeIngest)
		if !authenticated {
			authenticated, authorized = nodeRuntimeVerifier().AuthorizeRequest(r, adminScopeIngest)
		}
		if !authenticated {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"code": "invalid_service_token"})
			return
		}
		if !authorized {
			writeJSON(w, http.StatusForbidden, map[string]string{"code": "admin_scope_required"})
			return
		}
	}
	var signal store.Signal
	if err := decodeJSONBody(w, r, &signal); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "bad_request"})
		return
	}
	if signal.Type == "" || signal.Name == "" || signal.ServiceID == "" || signal.ServiceType == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_signal"})
		return
	}
	if tokenSubject.ServiceID != "" && (tokenSubject.ServiceID != signal.ServiceID || tokenSubject.ServiceType != signal.ServiceType) {
		writeJSON(w, http.StatusForbidden, map[string]string{"code": "service_identity_mismatch"})
		return
	}
	if err := validateSignalTopLevelFields(signal); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_signal_identifier"})
		return
	}
	if err := validateSignalAttributes(signal.Attributes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_signal_attributes"})
		return
	}
	signal.Attributes = safeSignalAttributes(signal.Attributes)
	signal, err := s.withCumulativeCounterDelta(r.Context(), signal)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "counter_state_lookup_failed"})
		return
	}
	saved, err := s.store.SaveSignal(r.Context(), signal)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "save_signal_failed"})
		return
	}
	createdIncidents, err := s.evaluateAndStoreIncidents(r, saved)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "incident_evaluation_failed"})
		return
	}
	writeJSON(w, http.StatusAccepted, IngestResponse{Signal: safeSignal(saved), Incidents: createdIncidents})
}

const counterDeltaAttribute = "observability.counter_delta"

var cumulativeCounterMetrics = map[string]struct{}{
	"encoder.dropped_frames_total":                {},
	"encoder.audio_clipping_total":                {},
	"worker.event_send_failures_total":            {},
	"discord.worker_event_publish_failures_total": {},
	"discord.audio_forward_errors_total":          {},
	"rtmp.reconnect_count":                        {},
	"encoder.rtmp_reconnect_count":                {},
	"discord.reconnect_count":                     {},
	"discord.voice_disconnect_count":              {},
}

func (s *Server) withCumulativeCounterDelta(ctx context.Context, signal store.Signal) (store.Signal, error) {
	if signal.Value == nil {
		return signal, nil
	}
	if _, ok := cumulativeCounterMetrics[signal.Name]; !ok {
		return signal, nil
	}
	previous, found, err := s.store.LatestMetricValue(ctx, signal.Name, signal.ServiceID, signal.StreamID)
	if err != nil {
		return store.Signal{}, err
	}
	delta := 0.0
	reset := false
	if found {
		if *signal.Value >= previous {
			delta = *signal.Value - previous
		} else {
			reset = true
		}
	}
	attributes := make(map[string]any, len(signal.Attributes)+2)
	for key, value := range signal.Attributes {
		attributes[key] = value
	}
	attributes[counterDeltaAttribute] = delta
	if reset {
		attributes["observability.counter_reset"] = true
	}
	signal.Attributes = attributes
	return signal, nil
}

func (s *Server) evaluateAndStoreIncidents(r *http.Request, signal store.Signal) ([]store.Incident, error) {
	evaluation := evaluateSignal(signal)
	for _, recovery := range evaluation.Recoveries {
		resolved, err := s.store.ResolveActiveIncidents(r.Context(), []string{recovery.Rule}, signal.ServiceID, signal.StreamID, signal.ID, recovery.Reason)
		if err != nil {
			return nil, err
		}
		for _, incident := range resolved {
			s.notifyIncidentEvent(r, "incident.resolved", incident)
		}
	}
	detected := evaluation.Incidents
	out := make([]store.Incident, 0, len(detected))
	for _, detectedIncident := range detected {
		evidence := diagnosticEvidence(signal)
		incident := store.Incident{
			Rule:      detectedIncident.Rule,
			Severity:  detectedIncident.Severity,
			Status:    "open",
			SummaryJA: detectedIncident.SummaryJA,
			ServiceID: signal.ServiceID,
			StreamID:  signal.StreamID,
			SignalID:  signal.ID,
			Report:    diagnostics.JapaneseReport(detectedIncident.Rule, evidence),
		}
		stored, created, err := s.store.UpsertIncident(r.Context(), incident)
		if err != nil {
			return nil, err
		}
		if created {
			s.notifyIncidentEvent(r, "incident.opened", stored)
			if err := s.createRemediationActions(r, stored); err != nil {
				return nil, err
			}
		} else if stored.SeverityChanged {
			s.notifyIncidentEvent(r, "incident.updated", stored)
		}
		out = append(out, stored)
	}
	return out, nil
}

func detectSignal(signal store.Signal) []detection.Incident {
	return evaluateSignal(signal).Incidents
}

func evaluateSignal(signal store.Signal) detection.Evaluation {
	value := 0.0
	if signal.Value != nil {
		value = *signal.Value
	}
	streamLive := signal.Attributes["stream_live"] == true || signal.Status == "live"
	return detection.EvaluateSignal(detection.Signal{
		Type:       signal.Type,
		Name:       signal.Name,
		Value:      value,
		StreamID:   signal.StreamID,
		StreamLive: streamLive,
		Status:     signal.Status,
		Attributes: signal.Attributes,
	})
}

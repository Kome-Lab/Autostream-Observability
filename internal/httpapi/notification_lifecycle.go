package httpapi

import (
	"errors"
	"net/http"

	lc "github.com/Kome-Lab/Autostream-Contracts/v3lifecycle"
	"github.com/example/autostream-observability/internal/notifications"
)

const notificationLifecycleHeader = "X-Autostream-Lifecycle"

func (s *Server) notificationEffectRequest(w http.ResponseWriter, r *http.Request) (lc.Record, bool) {
	if s.notificationEffects == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"code": "notification_effect_not_connected", "qualification": "NOT_QUALIFIED"})
		return lc.Record{}, false
	}
	values := r.Header.Values(notificationLifecycleHeader)
	if len(values) != 1 || values[0] == "" || len(values[0]) > 48<<10 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_notification_effect"})
		return lc.Record{}, false
	}
	record, result := s.notificationEffects.Decode([]byte(values[0]))
	if result.Kind != lc.StructurallyCoherent || record.Effect == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_notification_effect"})
		return lc.Record{}, false
	}
	return record, true
}
func (s *Server) dispatchNotificationEffect(w http.ResponseWriter, r *http.Request) {
	record, ok := s.notificationEffectRequest(w, r)
	if !ok {
		return
	}
	// V3 uses only owner-resolved non-secret ContentRef. The legacy request body
	// is not copied to the journal or interpreted as a provider receipt.
	result, err := s.notificationEffects.Dispatch(r.Context(), record)
	s.writeNotificationEffect(w, result, err)
}
func (s *Server) inspectNotificationEffect(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeNotificationsRead) {
		return
	}
	record, ok := s.notificationEffectRequest(w, r)
	if !ok {
		return
	}
	if string(record.Effect.EffectID) != r.PathValue("effect") || string(record.Header.Correlation.AttemptID) != r.PathValue("attempt") {
		writeJSON(w, http.StatusConflict, map[string]string{"code": "notification_effect_correlation_conflict"})
		return
	}
	result, err := s.notificationEffects.Inspect(r.Context(), record)
	s.writeNotificationEffect(w, result, err)
}
func (s *Server) writeNotificationEffect(w http.ResponseWriter, result lc.Record, err error) {
	status := http.StatusOK
	switch {
	case errors.Is(err, notifications.ErrEffectConflict), errors.Is(err, notifications.ErrEffectStale):
		status = http.StatusConflict
	case errors.Is(err, notifications.ErrEffectUnqualified):
		status = http.StatusForbidden
	case err != nil:
		status = http.StatusServiceUnavailable
	}
	if result.Inspection == nil {
		writeJSON(w, status, map[string]string{"code": "notification_effect_refused", "qualification": "NOT_QUALIFIED"})
		return
	}
	writeJSON(w, status, result)
}

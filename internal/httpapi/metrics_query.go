package httpapi

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/example/autostream-observability/internal/control"
	"github.com/example/autostream-observability/internal/store"
)

func (s *Server) listSignals(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeRead) {
		return
	}
	signals, err := s.store.ListSignals(r.Context(), parseLimit(r, 200))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "list_signals_failed"})
		return
	}
	writeJSON(w, http.StatusOK, safeSignals(signals))
}

func (s *Server) listMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeRead) {
		return
	}
	rangeSeconds := 3 * 60 * 60
	if raw := strings.TrimSpace(r.URL.Query().Get("range_sec")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 15*60 || parsed > 3*60*60 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_metric_range"})
			return
		}
		rangeSeconds = parsed
	}
	metrics, err := s.store.ListMetricSnapshots(r.Context(), store.MetricQuery{
		Since:              time.Now().UTC().Add(-time.Duration(rangeSeconds) * time.Second),
		MaxPointsPerSeries: 360,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "list_metrics_failed"})
		return
	}
	for index := range metrics {
		metrics[index].Attributes = safeSignalAttributes(metrics[index].Attributes)
	}
	writeJSON(w, http.StatusOK, appendSelfMetricSnapshots(metrics))
}

func metricSnapshots(signals []store.Signal) []store.MetricSnapshot {
	seen := map[string]bool{}
	out := make([]store.MetricSnapshot, 0, len(signals))
	for _, signal := range signals {
		key := signal.ServiceID + "\x00" + signal.StreamID + "\x00" + signal.Name
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, store.MetricSnapshot{
			Name:        signal.Name,
			ServiceID:   signal.ServiceID,
			ServiceType: signal.ServiceType,
			StreamID:    signal.StreamID,
			Status:      signal.Status,
			Value:       signal.Value,
			Attributes:  safeSignalAttributes(signal.Attributes),
			UpdatedAt:   signal.CreatedAt,
		})
	}
	return out
}

func appendSelfMetricSnapshots(metrics []store.MetricSnapshot) []store.MetricSnapshot {
	now := time.Now().UTC()
	serviceID := strings.TrimSpace(control.FromEnv().ServiceID)
	if serviceID == "" {
		serviceID = "observability-01"
	}
	for name, raw := range control.NodeRuntimeMetrics() {
		value, ok := numericMetricValue(raw)
		if !ok {
			continue
		}
		metrics = append(metrics, store.MetricSnapshot{
			Name:        name,
			ServiceID:   serviceID,
			ServiceType: control.ServiceType,
			Value:       &value,
			UpdatedAt:   now,
		})
	}
	return metrics
}

func numericMetricValue(raw any) (float64, bool) {
	switch value := raw.(type) {
	case int:
		return float64(value), true
	case int64:
		return float64(value), true
	case uint64:
		return float64(value), true
	case float64:
		return value, true
	default:
		return 0, false
	}
}

func parseLimit(r *http.Request, fallback int) int {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return fallback
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit <= 0 {
		return fallback
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}

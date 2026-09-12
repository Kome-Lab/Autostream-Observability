package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/example/autostream-observability/internal/control"
	"github.com/example/autostream-observability/internal/store"
)

func TestMetricsIncludesObservabilityRuntimeMetrics(t *testing.T) {
	handler := newTestServer(store.NewMemoryStore())
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
	}
	var metrics []store.MetricSnapshot
	if err := json.NewDecoder(res.Body).Decode(&metrics); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, metric := range metrics {
		if metric.ServiceType == control.ServiceType && metric.Name == "observability.goroutines" && metric.Value != nil {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("observability runtime metrics were not returned: %#v", metrics)
	}
}

func TestMetricsRangeReturnsPersistedHistory(t *testing.T) {
	st := store.NewMemoryStore()
	now := time.Now().UTC()
	for index, at := range []time.Time{now.Add(-20 * time.Minute), now.Add(-10 * time.Minute), now.Add(-time.Minute)} {
		value := float64(index + 1)
		if _, err := st.SaveSignal(t.Context(), store.Signal{Type: "metric", Name: "worker.cpu_percent", ServiceID: "worker-01", ServiceType: "worker", Value: &value, Timestamp: at}); err != nil {
			t.Fatal(err)
		}
	}
	handler := newTestServer(st)
	req := httptest.NewRequest(http.MethodGet, "/metrics?range_sec=900", nil)
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
	}
	var metrics []store.MetricSnapshot
	if err := json.NewDecoder(res.Body).Decode(&metrics); err != nil {
		t.Fatal(err)
	}
	var workerPoints []store.MetricSnapshot
	for _, metric := range metrics {
		if metric.ServiceID == "worker-01" && metric.Name == "worker.cpu_percent" {
			workerPoints = append(workerPoints, metric)
		}
	}
	if len(workerPoints) != 2 {
		t.Fatalf("range did not return persisted history: %#v", workerPoints)
	}
}

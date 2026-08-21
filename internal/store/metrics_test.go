package store

import (
	"strings"
	"testing"
)

func TestMetricSnapshotQueryCapsEachSeriesIndependently(t *testing.T) {
	for _, expected := range []string{
		"ROW_NUMBER() OVER",
		"PARTITION BY name, service_id, service_type, COALESCE(stream_id, '')",
		"WHERE series_rank <= ?",
	} {
		if !strings.Contains(metricSnapshotQuery, expected) {
			t.Fatalf("metric query must cap every series independently; missing %q in: %s", expected, metricSnapshotQuery)
		}
	}
	if strings.Contains(metricSnapshotQuery, "LIMIT 100000") {
		t.Fatalf("a global row cap can starve low-frequency series: %s", metricSnapshotQuery)
	}
}

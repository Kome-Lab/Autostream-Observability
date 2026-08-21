package store

import (
	"context"
	"sort"
	"strings"
	"time"
)

const defaultMaxMetricPointsPerSeries = 360

const metricSnapshotQuery = `SELECT id, signal_type, name, service_id, service_type, stream_id, status, value_double, attributes, occurred_at, created_at
FROM (
  SELECT id, signal_type, name, service_id, service_type,
    COALESCE(stream_id, '') AS stream_id,
    COALESCE(status, '') AS status,
    value_double, attributes, occurred_at, created_at,
    ROW_NUMBER() OVER (
      PARTITION BY name, service_id, service_type, COALESCE(stream_id, '')
      ORDER BY occurred_at DESC, created_at DESC, id DESC
    ) AS series_rank
  FROM signals
  WHERE value_double IS NOT NULL AND occurred_at >= ?
) ranked
WHERE series_rank <= ?
ORDER BY occurred_at ASC, created_at ASC, id ASC`

func (s *MemoryStore) ListMetricSnapshots(ctx context.Context, query MetricQuery) ([]MetricSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	signals := append([]Signal(nil), s.signals...)
	s.mu.Unlock()
	return metricSnapshotsFromSignals(signals, query), nil
}

func (s MariaDBStore) ListMetricSnapshots(ctx context.Context, query MetricQuery) ([]MetricSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	since := query.Since.UTC()
	if since.IsZero() {
		since = time.Now().UTC().Add(-3 * time.Hour)
	}
	maxPoints := query.MaxPointsPerSeries
	if maxPoints <= 0 {
		maxPoints = defaultMaxMetricPointsPerSeries
	}
	rows, err := s.DB.QueryContext(ctx, metricSnapshotQuery, since, maxPoints)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	signals := make([]Signal, 0)
	for rows.Next() {
		signal, err := scanSignal(rows)
		if err != nil {
			return nil, err
		}
		signals = append(signals, signal)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	query.Since = since
	return metricSnapshotsFromSignals(signals, query), nil
}

func metricSnapshotsFromSignals(signals []Signal, query MetricQuery) []MetricSnapshot {
	maxPoints := query.MaxPointsPerSeries
	if maxPoints <= 0 {
		maxPoints = defaultMaxMetricPointsPerSeries
	}
	series := map[string][]MetricSnapshot{}
	for _, signal := range signals {
		if signal.Value == nil {
			continue
		}
		updatedAt := signal.Timestamp.UTC()
		if updatedAt.IsZero() {
			updatedAt = signal.CreatedAt.UTC()
		}
		if !query.Since.IsZero() && updatedAt.Before(query.Since) {
			continue
		}
		key := strings.Join([]string{signal.ServiceID, signal.ServiceType, signal.StreamID, signal.Name}, "\x00")
		series[key] = append(series[key], MetricSnapshot{
			Name: signal.Name, ServiceID: signal.ServiceID, ServiceType: signal.ServiceType,
			StreamID: signal.StreamID, Status: signal.Status, Value: signal.Value,
			Attributes: signal.Attributes, UpdatedAt: updatedAt,
		})
	}
	out := make([]MetricSnapshot, 0)
	for _, points := range series {
		sort.Slice(points, func(i, j int) bool { return points[i].UpdatedAt.Before(points[j].UpdatedAt) })
		if len(points) > maxPoints {
			points = downsampleMetricSeries(points, maxPoints)
		}
		out = append(out, points...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UpdatedAt.Equal(out[j].UpdatedAt) {
			return out[i].ServiceID+out[i].Name < out[j].ServiceID+out[j].Name
		}
		return out[i].UpdatedAt.Before(out[j].UpdatedAt)
	})
	return out
}

func downsampleMetricSeries(points []MetricSnapshot, maxPoints int) []MetricSnapshot {
	if maxPoints <= 0 || len(points) <= maxPoints {
		return points
	}
	result := make([]MetricSnapshot, 0, maxPoints)
	for bucket := 0; bucket < maxPoints; bucket++ {
		start := bucket * len(points) / maxPoints
		end := (bucket + 1) * len(points) / maxPoints
		if end <= start {
			continue
		}
		// Keep the newest sample from each stable bucket so status/value and
		// timestamp describe the same observation.
		result = append(result, points[end-1])
	}
	return result
}

CREATE INDEX IF NOT EXISTS idx_signals_metric_series_occurred
  ON signals (name, service_id, service_type, stream_id, occurred_at, created_at, id);

CREATE INDEX IF NOT EXISTS idx_incidents_updated_id
  ON incidents (updated_at, id);

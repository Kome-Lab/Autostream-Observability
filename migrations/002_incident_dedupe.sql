-- Keep one active incident per rule/service/stream even when multiple
-- service workers report the same failure concurrently.
ALTER TABLE incidents
  ADD COLUMN dedupe_key VARCHAR(400) NULL,
  ADD UNIQUE KEY uq_incidents_active_dedupe (dedupe_key);

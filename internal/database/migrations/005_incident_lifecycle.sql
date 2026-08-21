ALTER TABLE incidents
  ADD COLUMN IF NOT EXISTS occurrence_count INT NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS last_seen_at DATETIME NULL,
  ADD COLUMN IF NOT EXISTS resolved_by_signal_id VARCHAR(64) NULL,
  ADD COLUMN IF NOT EXISTS resolution_reason VARCHAR(128) NULL,
  ADD COLUMN IF NOT EXISTS dedupe_key VARCHAR(400) NULL;

UPDATE incidents
SET occurrence_count = GREATEST(occurrence_count, 1),
    last_seen_at = COALESCE(last_seen_at, updated_at),
    dedupe_key = NULL;

-- Older runtime builds did not embed the active-incident dedupe migration.
-- Keep the newest active row and close older duplicates before populating the
-- unique key so an existing production database can always converge.
UPDATE incidents AS stale
JOIN incidents AS newer
  ON newer.rule = stale.rule
 AND newer.service_id = stale.service_id
 AND newer.stream_id <=> stale.stream_id
 AND newer.status NOT IN ('resolved', 'ignored')
 AND (
   newer.updated_at > stale.updated_at
   OR (newer.updated_at = stale.updated_at AND newer.id > stale.id)
 )
SET stale.status = 'resolved',
    stale.resolved_at = COALESCE(stale.resolved_at, stale.updated_at),
    stale.resolved_by_signal_id = NULL,
    stale.resolution_reason = COALESCE(NULLIF(stale.resolution_reason, ''), 'migration_duplicate_consolidated'),
    stale.dedupe_key = NULL
WHERE stale.status NOT IN ('resolved', 'ignored');

UPDATE incidents
SET dedupe_key = CASE
  WHEN status IN ('resolved', 'ignored') THEN NULL
  ELSE CONCAT(rule, CHAR(0), service_id, CHAR(0), COALESCE(stream_id, ''))
END;

CREATE UNIQUE INDEX IF NOT EXISTS uq_incidents_active_dedupe
  ON incidents (dedupe_key);

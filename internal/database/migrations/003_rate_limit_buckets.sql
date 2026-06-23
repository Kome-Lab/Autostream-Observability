CREATE TABLE IF NOT EXISTS rate_limit_buckets (
  bucket_key VARCHAR(512) PRIMARY KEY,
  window_start DATETIME NOT NULL,
  hit_count INT NOT NULL,
  updated_at DATETIME NOT NULL,
  INDEX idx_rate_limit_buckets_updated (updated_at)
);

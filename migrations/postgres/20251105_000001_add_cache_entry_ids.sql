CREATE TABLE IF NOT EXISTS cache_entry_ids (
    entry_id TEXT PRIMARY KEY REFERENCES cache_entries(id) ON DELETE CASCADE,
    numeric_id BIGINT NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_cache_entry_ids_numeric ON cache_entry_ids (numeric_id);

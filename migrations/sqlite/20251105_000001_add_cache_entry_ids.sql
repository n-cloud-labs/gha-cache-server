CREATE TABLE IF NOT EXISTS cache_entry_ids (
    entry_id TEXT PRIMARY KEY,
    numeric_id BIGINT NOT NULL UNIQUE,
    FOREIGN KEY (entry_id) REFERENCES cache_entries(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cache_entry_ids_numeric ON cache_entry_ids (numeric_id);

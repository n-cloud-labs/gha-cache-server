CREATE TABLE IF NOT EXISTS cache_entry_ids (
    entry_id VARCHAR(36) PRIMARY KEY,
    numeric_id BIGINT NOT NULL UNIQUE,
    CONSTRAINT fk_cache_entry_ids_entry FOREIGN KEY (entry_id) REFERENCES cache_entries(id) ON DELETE CASCADE
);

CREATE INDEX idx_cache_entry_ids_numeric ON cache_entry_ids (numeric_id);

CREATE TABLE IF NOT EXISTS cache_upload_parts (
    upload_id VARCHAR(255) NOT NULL,
    part_index INT NOT NULL,
    part_number INT NOT NULL,
    offset BIGINT NULL,
    size BIGINT NOT NULL,
    etag TEXT NULL,
    state VARCHAR(32) NOT NULL CHECK (state IN ('pending','completed')),
    created_at BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    updated_at BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    PRIMARY KEY (upload_id, part_index),
    CONSTRAINT fk_cache_upload_parts_upload FOREIGN KEY (upload_id) REFERENCES cache_uploads(upload_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_cache_upload_parts_state ON cache_upload_parts (upload_id, state, part_index);

CREATE TABLE IF NOT EXISTS cache_upload_parts (
    upload_id TEXT NOT NULL,
    part_index INTEGER NOT NULL,
    part_number INTEGER NOT NULL,
    "offset" BIGINT,
    size BIGINT NOT NULL,
    etag TEXT,
    state TEXT NOT NULL CHECK (state IN ('pending','completed')),
    created_at BIGINT NOT NULL DEFAULT (strftime('%s','now')),
    updated_at BIGINT NOT NULL DEFAULT (strftime('%s','now')),
    PRIMARY KEY (upload_id, part_index),
    FOREIGN KEY (upload_id) REFERENCES cache_uploads(upload_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cache_upload_parts_state ON cache_upload_parts (upload_id, state, part_index);

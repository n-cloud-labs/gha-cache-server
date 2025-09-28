CREATE TABLE cache_uploads_new (
    id TEXT PRIMARY KEY,
    entry_id TEXT,
    upload_id TEXT NOT NULL UNIQUE,
    parts_json TEXT NOT NULL DEFAULT '[]',
    state TEXT NOT NULL CHECK (state IN ('reserved','ready','uploading','finalizing','completed','committed','aborted')),
    active_part_count INTEGER NOT NULL DEFAULT 0,
    pending_finalize INTEGER NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL DEFAULT (strftime('%s','now')),
    updated_at BIGINT NOT NULL DEFAULT (strftime('%s','now')),
    FOREIGN KEY (entry_id) REFERENCES cache_entries(id) ON DELETE CASCADE
);

INSERT INTO cache_uploads_new (
    id,
    entry_id,
    upload_id,
    parts_json,
    state,
    active_part_count,
    pending_finalize,
    created_at,
    updated_at
)
SELECT
    id,
    entry_id,
    upload_id,
    parts_json,
    CASE state WHEN 'committed' THEN 'completed' ELSE state END,
    0,
    0,
    created_at,
    updated_at
FROM cache_uploads;

DROP TABLE cache_uploads;
ALTER TABLE cache_uploads_new RENAME TO cache_uploads;

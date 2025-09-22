CREATE TABLE IF NOT EXISTS cache_entries (
    id TEXT PRIMARY KEY,
    org TEXT NOT NULL,
    repo TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    scope TEXT NOT NULL,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    checksum TEXT,
    storage_key TEXT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::BIGINT,
    last_access_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::BIGINT,
    ttl_seconds BIGINT NOT NULL DEFAULT 1209600
);

CREATE TABLE IF NOT EXISTS cache_uploads (
    id TEXT PRIMARY KEY,
    entry_id TEXT REFERENCES cache_entries(id) ON DELETE CASCADE,
    upload_id TEXT NOT NULL UNIQUE,
    parts_json TEXT NOT NULL DEFAULT '[]',
    state TEXT NOT NULL CHECK (state IN ('reserved','uploading','committed','aborted')),
    created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::BIGINT,
    updated_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::BIGINT
);

CREATE INDEX IF NOT EXISTS idx_cache_entries_org_repo_key ON cache_entries (org, repo, cache_key);
CREATE INDEX IF NOT EXISTS idx_cache_entries_last_access ON cache_entries (last_access_at);

CREATE TABLE IF NOT EXISTS cache_entries (
    id VARCHAR(36) PRIMARY KEY,
    org VARCHAR(255) NOT NULL,
    repo VARCHAR(255) NOT NULL,
    cache_key VARCHAR(512) NOT NULL,
    scope VARCHAR(255) NOT NULL,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    checksum TEXT,
    storage_key TEXT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    last_access_at BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    ttl_seconds BIGINT NOT NULL DEFAULT 1209600
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS cache_uploads (
    id VARCHAR(36) PRIMARY KEY,
    entry_id VARCHAR(36),
    upload_id VARCHAR(255) NOT NULL UNIQUE,
    parts_json LONGTEXT NOT NULL DEFAULT '[]',
    state VARCHAR(32) NOT NULL CHECK (state IN ('reserved','uploading','committed','aborted')),
    created_at BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    updated_at BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_cache_upload_entry FOREIGN KEY (entry_id) REFERENCES cache_entries(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_cache_entries_org_repo_key ON cache_entries (org, repo, cache_key);
CREATE INDEX idx_cache_entries_last_access ON cache_entries (last_access_at);

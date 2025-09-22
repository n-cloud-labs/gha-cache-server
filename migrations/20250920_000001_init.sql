-- core tables
CREATE TABLE IF NOT EXISTS cache_entries (
    id UUID PRIMARY KEY,
    org TEXT NOT NULL,
    repo TEXT NOT NULL,
    key TEXT NOT NULL,
    scope TEXT NOT NULL, -- e.g. branch / commit scope
    size_bytes BIGINT NOT NULL DEFAULT 0,
    checksum TEXT,
    storage_key TEXT NOT NULL, -- object key in the bucket
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_access_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ttl_seconds BIGINT NOT NULL DEFAULT 1209600 -- 14 days default
);


CREATE TABLE IF NOT EXISTS cache_uploads (
    id UUID PRIMARY KEY,
    entry_id UUID REFERENCES cache_entries(id) ON DELETE CASCADE,
    upload_id TEXT NOT NULL, -- S3 multipart upload id
    parts_json JSONB NOT NULL DEFAULT '[]', -- [{partNumber, etag}]
    state TEXT NOT NULL CHECK (state IN ('reserved','uploading','committed','aborted')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cache_entries_org_repo_key ON cache_entries(org, repo, key);
CREATE INDEX IF NOT EXISTS idx_cache_entries_last_access ON cache_entries(last_access_at);

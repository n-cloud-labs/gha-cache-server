ALTER TABLE cache_entries
    ADD COLUMN cache_version TEXT NOT NULL DEFAULT '';
UPDATE cache_entries SET cache_version = scope WHERE cache_version = '';
UPDATE cache_entries SET scope = '_' WHERE scope <> '_';
DROP INDEX IF EXISTS idx_cache_entries_org_repo_key;
CREATE INDEX IF NOT EXISTS idx_cache_entries_org_repo_key ON cache_entries (org, repo, cache_key, cache_version);
CREATE INDEX IF NOT EXISTS idx_cache_entries_key_version ON cache_entries (cache_key, cache_version);

ALTER TABLE cache_entries
    ADD COLUMN cache_version VARCHAR(512) NOT NULL DEFAULT '';
UPDATE cache_entries SET cache_version = scope WHERE cache_version = '';
UPDATE cache_entries SET scope = '_' WHERE scope <> '_';
DROP INDEX idx_cache_entries_org_repo_key ON cache_entries;
CREATE INDEX idx_cache_entries_org_repo_key ON cache_entries (org(191), repo(191), cache_key(191), cache_version(191));
CREATE INDEX idx_cache_entries_key_version ON cache_entries (cache_key(191), cache_version(191));

ALTER TABLE cache_uploads
    ADD COLUMN active_part_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN pending_finalize BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE cache_uploads
    DROP CONSTRAINT IF EXISTS cache_uploads_state_check,
    ADD CONSTRAINT cache_uploads_state_check CHECK (state IN ('reserved','ready','uploading','finalizing','completed','committed','aborted'));

UPDATE cache_uploads SET state = 'completed' WHERE state = 'committed';

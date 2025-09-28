ALTER TABLE cache_uploads
    ADD COLUMN active_part_count BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN pending_finalize BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE cache_uploads SET state = 'completed' WHERE state = 'committed';

ALTER TABLE cache_uploads
    MODIFY COLUMN state ENUM('reserved','ready','uploading','finalizing','completed','committed','aborted') NOT NULL;

-- 0002_muc_mam_extensions.sql
-- Extends muc_rooms with subject persistence, muc_history with stanza_id,
-- and adds the muc_mam_archive partitioned table for per-room MAM.

ALTER TABLE muc_rooms ADD COLUMN IF NOT EXISTS subject    text        NOT NULL DEFAULT '';
ALTER TABLE muc_rooms ADD COLUMN IF NOT EXISTS subject_by text        NOT NULL DEFAULT '';
ALTER TABLE muc_rooms ADD COLUMN IF NOT EXISTS subject_ts timestamptz;

ALTER TABLE muc_history ADD COLUMN IF NOT EXISTS stanza_id text NOT NULL DEFAULT '';

-- ─── muc_mam_archive ─────────────────────────────────────────────────────────
-- Partitioned by month on ts, mirroring the mam_archive convention.
-- An external admin job must create new monthly partitions; the default
-- partition catches stragglers until the job runs.

CREATE TABLE IF NOT EXISTS muc_mam_archive (
    id              bigserial,
    room_jid        text        NOT NULL,
    sender_bare_jid text,
    ts              timestamptz NOT NULL,
    stanza_id       text        NOT NULL DEFAULT '',
    origin_id       text        NOT NULL DEFAULT '',
    stanza_xml      bytea       NOT NULL,
    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);

CREATE INDEX IF NOT EXISTS muc_mam_room_ts ON muc_mam_archive (room_jid, ts);

CREATE TABLE IF NOT EXISTS muc_mam_archive_default PARTITION OF muc_mam_archive DEFAULT;

DO $$
DECLARE
    m date;
BEGIN
    FOR i IN 0..2 LOOP
        m := date_trunc('month', now()) + (i || ' month')::interval;
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS muc_mam_archive_%s PARTITION OF muc_mam_archive '
            'FOR VALUES FROM (%L) TO (%L)',
            to_char(m, 'YYYY_MM'),
            m,
            m + interval '1 month'
        );
    END LOOP;
END
$$;

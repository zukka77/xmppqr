CREATE EXTENSION IF NOT EXISTS citext;

CREATE DOMAIN jid_t AS citext
    CHECK (VALUE ~ '^[^@/]+@[^@/]+(/.+)?$');

-- ─── users ────────────────────────────────────────────────────────────────────

CREATE TABLE users (
    username      citext      PRIMARY KEY,
    scram_salt    bytea       NOT NULL DEFAULT '',
    scram_iter    integer     NOT NULL DEFAULT 4096,
    argon2_params jsonb,
    stored_key256 bytea,
    server_key256 bytea,
    stored_key512 bytea,
    server_key512 bytea,
    created_at    timestamptz NOT NULL DEFAULT now(),
    disabled      boolean     NOT NULL DEFAULT false
);

-- ─── roster ───────────────────────────────────────────────────────────────────

CREATE TABLE roster (
    owner        citext  NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    contact      jid_t   NOT NULL,
    name         text    NOT NULL DEFAULT '',
    subscription smallint NOT NULL DEFAULT 0 CHECK (subscription BETWEEN 0 AND 3),
    ask          smallint NOT NULL DEFAULT 0 CHECK (ask BETWEEN 0 AND 2),
    groups       text[]  NOT NULL DEFAULT '{}',
    ver          bigint  NOT NULL DEFAULT 0,
    PRIMARY KEY (owner, contact)
);

CREATE INDEX roster_owner_ver ON roster (owner, ver);

-- ─── mam_archive ─────────────────────────────────────────────────────────────
-- Partitioned by month on ts. An external admin job must create new monthly
-- partitions; the default partition catches stragglers until the job runs.

CREATE TABLE mam_archive (
    id          bigserial,
    owner       citext      NOT NULL,
    with_jid    jid_t,
    ts          timestamptz NOT NULL,
    stanza_id   text        NOT NULL DEFAULT '',
    origin_id   text        NOT NULL DEFAULT '',
    direction   smallint    NOT NULL DEFAULT 0 CHECK (direction IN (0, 1)),
    stanza_xml  bytea       NOT NULL,
    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);

CREATE INDEX mam_owner_with_ts   ON mam_archive (owner, with_jid, ts);
CREATE INDEX mam_owner_stanza_id ON mam_archive (owner, stanza_id);

CREATE TABLE mam_archive_default PARTITION OF mam_archive DEFAULT;

DO $$
DECLARE
    m date;
BEGIN
    FOR i IN 0..2 LOOP
        m := date_trunc('month', now()) + (i || ' month')::interval;
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS mam_archive_%s PARTITION OF mam_archive '
            'FOR VALUES FROM (%L) TO (%L)',
            to_char(m, 'YYYY_MM'),
            m,
            m + interval '1 month'
        );
    END LOOP;
END
$$;

-- ─── pep_nodes ────────────────────────────────────────────────────────────────

CREATE TABLE pep_nodes (
    owner        citext   NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    node         text     NOT NULL,
    config       jsonb,
    access_model smallint NOT NULL DEFAULT 0 CHECK (access_model BETWEEN 0 AND 4),
    PRIMARY KEY (owner, node)
);

-- ─── pep_items ────────────────────────────────────────────────────────────────

CREATE TABLE pep_items (
    owner        citext      NOT NULL,
    node         text        NOT NULL,
    item_id      text        NOT NULL,
    publisher    jid_t,
    published_at timestamptz NOT NULL DEFAULT now(),
    payload      bytea       NOT NULL,
    PRIMARY KEY (owner, node, item_id),
    FOREIGN KEY (owner, node) REFERENCES pep_nodes(owner, node) ON DELETE CASCADE
);

ALTER TABLE pep_items ALTER COLUMN payload SET STORAGE EXTENDED;

-- ─── muc_rooms ────────────────────────────────────────────────────────────────

CREATE TABLE muc_rooms (
    jid        jid_t       PRIMARY KEY,
    config     jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    persistent boolean     NOT NULL DEFAULT false
);

-- ─── muc_affiliations ─────────────────────────────────────────────────────────

CREATE TABLE muc_affiliations (
    room_jid    jid_t    NOT NULL REFERENCES muc_rooms(jid) ON DELETE CASCADE,
    user_jid    jid_t    NOT NULL,
    affiliation smallint NOT NULL DEFAULT 0 CHECK (affiliation BETWEEN 0 AND 4),
    PRIMARY KEY (room_jid, user_jid)
);

-- ─── muc_history ──────────────────────────────────────────────────────────────

CREATE TABLE muc_history (
    id         bigserial   PRIMARY KEY,
    room_jid   jid_t       NOT NULL REFERENCES muc_rooms(jid) ON DELETE CASCADE,
    sender_jid jid_t,
    ts         timestamptz NOT NULL DEFAULT now(),
    stanza_xml bytea       NOT NULL
);

CREATE INDEX muc_history_room_ts ON muc_history (room_jid, ts);

-- ─── push_registrations ───────────────────────────────────────────────────────

CREATE TABLE push_registrations (
    owner       citext      NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    service_jid jid_t       NOT NULL,
    node        text        NOT NULL,
    form_xml    bytea,
    enabled_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (owner, service_jid, node)
);

-- ─── block_list ───────────────────────────────────────────────────────────────

CREATE TABLE block_list (
    owner       citext NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    blocked_jid jid_t  NOT NULL,
    PRIMARY KEY (owner, blocked_jid)
);

-- ─── offline_queue ────────────────────────────────────────────────────────────

CREATE TABLE offline_queue (
    id      bigserial   PRIMARY KEY,
    owner   citext      NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    ts      timestamptz NOT NULL DEFAULT now(),
    stanza  bytea       NOT NULL,
    expires timestamptz
);

CREATE INDEX offline_queue_owner_ts ON offline_queue (owner, ts);

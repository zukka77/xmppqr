-- 0003_pep_owner_relax.sql
-- Relax pep_nodes.owner to allow non-account JIDs (MUC room JIDs, etc.).
-- The column stays NOT NULL citext; only the FK to users(username) is dropped
-- so that MUC bare JIDs can own nodes without requiring a users row.

-- pep_nodes.owner → users(username) ON DELETE CASCADE
ALTER TABLE pep_nodes DROP CONSTRAINT IF EXISTS pep_nodes_owner_fkey;

-- pep_items references pep_nodes(owner, node) ON DELETE CASCADE.
-- That FK stays (items must belong to a node); only the user-account FK is removed.
-- No separate pep_items → users FK exists; pep_items_owner_node_fkey covers the
-- composite (owner, node) → pep_nodes primary key which is already fine.

-- pep_subscriptions does not exist in the current schema; subscriptions are
-- stored in the pep_subscriptions table introduced below by Wave 5a.

-- Fast index for last-item replay: most-recent item per (owner, node).
CREATE INDEX IF NOT EXISTS pep_items_owner_node_published_desc
    ON pep_items (owner, node, published_at DESC);

-- Subscription table: tracks per-subscriber interest in (owner, node) pairs.
-- owner is the JID that owns the node (user bare JID or room bare JID).
-- subscriber is the full or bare JID that subscribed.
CREATE TABLE IF NOT EXISTS pep_subscriptions (
    owner      citext NOT NULL,
    node       text   NOT NULL,
    subscriber text   NOT NULL,
    PRIMARY KEY (owner, node, subscriber),
    FOREIGN KEY (owner, node) REFERENCES pep_nodes(owner, node) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS pep_subscriptions_subscriber
    ON pep_subscriptions (subscriber);

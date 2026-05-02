package pg

import (
	"context"
	"fmt"
)

func (db *DB) NormalizeUsernamesToBareJIDs(ctx context.Context, domain string) error {
	if domain == "" {
		return nil
	}

	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	legacyCTE := `
WITH legacy AS (
	SELECT username AS old_username, username || '@' || $1 AS new_username
	FROM users
	WHERE POSITION('@' IN username) = 0
)`

	stmts := []string{
		legacyCTE + `
INSERT INTO users
	(username, scram_salt, scram_iter, argon2_params, stored_key256, server_key256, stored_key512, server_key512, created_at, disabled)
SELECT l.new_username, u.scram_salt, u.scram_iter, u.argon2_params, u.stored_key256, u.server_key256, u.stored_key512, u.server_key512, u.created_at, u.disabled
FROM users u
JOIN legacy l ON l.old_username = u.username
ON CONFLICT (username) DO NOTHING`,
		legacyCTE + ` UPDATE roster SET owner = legacy.new_username FROM legacy WHERE roster.owner = legacy.old_username`,
		legacyCTE + ` UPDATE mam_archive SET owner = legacy.new_username FROM legacy WHERE mam_archive.owner = legacy.old_username`,
		legacyCTE + `
INSERT INTO pep_nodes (owner, node, config, access_model)
SELECT legacy.new_username, pep_nodes.node, pep_nodes.config, pep_nodes.access_model
FROM pep_nodes
JOIN legacy ON pep_nodes.owner = legacy.old_username
ON CONFLICT (owner, node) DO NOTHING`,
		legacyCTE + ` UPDATE pep_items SET owner = legacy.new_username FROM legacy WHERE pep_items.owner = legacy.old_username`,
		legacyCTE + ` DELETE FROM pep_nodes USING legacy WHERE pep_nodes.owner = legacy.old_username`,
		legacyCTE + ` UPDATE push_registrations SET owner = legacy.new_username FROM legacy WHERE push_registrations.owner = legacy.old_username`,
		legacyCTE + ` UPDATE block_list SET owner = legacy.new_username FROM legacy WHERE block_list.owner = legacy.old_username`,
		legacyCTE + ` UPDATE offline_queue SET owner = legacy.new_username FROM legacy WHERE offline_queue.owner = legacy.old_username`,
		legacyCTE + ` DELETE FROM users USING legacy WHERE users.username = legacy.old_username`,
	}

	for i, stmt := range stmts {
		if _, err := tx.Exec(ctx, stmt, domain); err != nil {
			return fmt.Errorf("normalize stmt %d: %w", i+1, err)
		}
	}

	return tx.Commit(ctx)
}

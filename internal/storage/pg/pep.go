package pg

import (
	"context"
	"errors"

	"github.com/danielinux/xmppqr/internal/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type pgPEP struct{ pool *pgxpool.Pool }

func (s *pgPEP) PutNode(ctx context.Context, node *storage.PEPNode) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO pep_nodes (owner, node, config, access_model)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (owner, node) DO UPDATE SET
			config       = EXCLUDED.config,
			access_model = EXCLUDED.access_model`,
		node.Owner, node.Node, nullBytes(node.Config), node.AccessModel,
	)
	return err
}

func (s *pgPEP) GetNode(ctx context.Context, owner, node string) (*storage.PEPNode, error) {
	n := &storage.PEPNode{}
	var config []byte
	err := s.pool.QueryRow(ctx, `
		SELECT owner, node, config, access_model FROM pep_nodes WHERE owner=$1 AND node=$2`,
		owner, node,
	).Scan(&n.Owner, &n.Node, &config, &n.AccessModel)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	n.Config = config
	return n, nil
}

func (s *pgPEP) DeleteNode(ctx context.Context, owner, node string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM pep_nodes WHERE owner=$1 AND node=$2`, owner, node)
	return err
}

func (s *pgPEP) PutItem(ctx context.Context, item *storage.PEPItem) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO pep_items (owner, node, item_id, publisher, published_at, payload)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (owner, node, item_id) DO UPDATE SET
			publisher    = EXCLUDED.publisher,
			published_at = EXCLUDED.published_at,
			payload      = EXCLUDED.payload`,
		item.Owner, item.Node, item.ItemID, nullJID(item.Publisher), item.PublishedAt, item.Payload,
	)
	return err
}

func (s *pgPEP) GetItem(ctx context.Context, owner, node, itemID string) (*storage.PEPItem, error) {
	it := &storage.PEPItem{}
	var pub *string
	err := s.pool.QueryRow(ctx, `
		SELECT owner, node, item_id, publisher, published_at, payload
		FROM pep_items WHERE owner=$1 AND node=$2 AND item_id=$3`,
		owner, node, itemID,
	).Scan(&it.Owner, &it.Node, &it.ItemID, &pub, &it.PublishedAt, &it.Payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	if pub != nil {
		it.Publisher = *pub
	}
	return it, nil
}

func (s *pgPEP) ListItems(ctx context.Context, owner, node string, limit int) ([]*storage.PEPItem, error) {
	var (
		rows pgx.Rows
		err  error
	)
	if limit > 0 {
		rows, err = s.pool.Query(ctx, `
			SELECT owner, node, item_id, publisher, published_at, payload
			FROM pep_items WHERE owner=$1 AND node=$2
			ORDER BY published_at ASC LIMIT $3`,
			owner, node, limit,
		)
	} else {
		rows, err = s.pool.Query(ctx, `
			SELECT owner, node, item_id, publisher, published_at, payload
			FROM pep_items WHERE owner=$1 AND node=$2
			ORDER BY published_at ASC`,
			owner, node,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*storage.PEPItem
	for rows.Next() {
		it := &storage.PEPItem{}
		var pub *string
		if err := rows.Scan(&it.Owner, &it.Node, &it.ItemID, &pub, &it.PublishedAt, &it.Payload); err != nil {
			return nil, err
		}
		if pub != nil {
			it.Publisher = *pub
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

func (s *pgPEP) DeleteItem(ctx context.Context, owner, node, itemID string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM pep_items WHERE owner=$1 AND node=$2 AND item_id=$3`, owner, node, itemID)
	return err
}

func nullBytes(b []byte) *[]byte {
	if len(b) == 0 {
		return nil
	}
	return &b
}

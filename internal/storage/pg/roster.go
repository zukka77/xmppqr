package pg

import (
	"context"

	"github.com/danielinux/xmppqr/internal/storage"
	"github.com/jackc/pgx/v5/pgxpool"
)

type pgRoster struct{ pool *pgxpool.Pool }

func (s *pgRoster) Get(ctx context.Context, owner string) ([]*storage.RosterItem, int64, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT contact, name, subscription, ask, groups, ver
		FROM roster WHERE owner=$1`, owner)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*storage.RosterItem
	var maxVer int64
	for rows.Next() {
		ri := &storage.RosterItem{Owner: owner}
		if err := rows.Scan(&ri.Contact, &ri.Name, &ri.Subscription, &ri.Ask, &ri.Groups, &ri.Ver); err != nil {
			return nil, 0, err
		}
		if ri.Ver > maxVer {
			maxVer = ri.Ver
		}
		out = append(out, ri)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, maxVer, nil
}

func (s *pgRoster) Put(ctx context.Context, item *storage.RosterItem) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	var newVer int64
	err = tx.QueryRow(ctx, `
		SELECT COALESCE(MAX(ver), 0) + 1 FROM roster WHERE owner=$1`, item.Owner,
	).Scan(&newVer)
	if err != nil {
		return 0, err
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO roster (owner, contact, name, subscription, ask, groups, ver)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (owner, contact) DO UPDATE SET
			name         = EXCLUDED.name,
			subscription = EXCLUDED.subscription,
			ask          = EXCLUDED.ask,
			groups       = EXCLUDED.groups,
			ver          = EXCLUDED.ver`,
		item.Owner, item.Contact, item.Name, item.Subscription, item.Ask, item.Groups, newVer,
	)
	if err != nil {
		return 0, err
	}
	return newVer, tx.Commit(ctx)
}

func (s *pgRoster) Delete(ctx context.Context, owner string, contact storage.JID) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	var newVer int64
	err = tx.QueryRow(ctx, `
		SELECT COALESCE(MAX(ver), 0) + 1 FROM roster WHERE owner=$1`, owner,
	).Scan(&newVer)
	if err != nil {
		return 0, err
	}

	_, err = tx.Exec(ctx, `DELETE FROM roster WHERE owner=$1 AND contact=$2`, owner, contact)
	if err != nil {
		return 0, err
	}
	return newVer, tx.Commit(ctx)
}

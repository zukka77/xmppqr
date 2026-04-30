package pg

import (
	"context"

	"github.com/danielinux/xmppqr/internal/storage"
	"github.com/jackc/pgx/v5/pgxpool"
)

type pgOffline struct{ pool *pgxpool.Pool }

func (s *pgOffline) Push(ctx context.Context, msg *storage.OfflineMessage) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO offline_queue (owner, ts, stanza, expires)
		VALUES ($1,$2,$3,$4) RETURNING id`,
		msg.Owner, msg.TS, msg.Stanza, msg.Expires,
	).Scan(&id)
	return id, err
}

func (s *pgOffline) Pop(ctx context.Context, owner string, limit int) ([]*storage.OfflineMessage, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `
		SELECT id, owner, ts, stanza, expires
		FROM offline_queue WHERE owner=$1
		ORDER BY ts ASC LIMIT $2`, owner, limit)
	if err != nil {
		return nil, err
	}
	var out []*storage.OfflineMessage
	var ids []int64
	for rows.Next() {
		m := &storage.OfflineMessage{}
		if err := rows.Scan(&m.ID, &m.Owner, &m.TS, &m.Stanza, &m.Expires); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, m)
		ids = append(ids, m.ID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(ids) > 0 {
		_, err = tx.Exec(ctx, `DELETE FROM offline_queue WHERE id = ANY($1)`, ids)
		if err != nil {
			return nil, err
		}
	}
	return out, tx.Commit(ctx)
}

func (s *pgOffline) Count(ctx context.Context, owner string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM offline_queue WHERE owner=$1`, owner,
	).Scan(&n)
	return n, err
}

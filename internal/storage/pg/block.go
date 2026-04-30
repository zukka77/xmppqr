package pg

import (
	"context"

	"github.com/danielinux/xmppqr/internal/storage"
	"github.com/jackc/pgx/v5/pgxpool"
)

type pgBlock struct{ pool *pgxpool.Pool }

func (s *pgBlock) List(ctx context.Context, owner string) ([]storage.JID, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT blocked_jid FROM block_list WHERE owner=$1`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storage.JID
	for rows.Next() {
		var jid string
		if err := rows.Scan(&jid); err != nil {
			return nil, err
		}
		out = append(out, jid)
	}
	return out, rows.Err()
}

func (s *pgBlock) Add(ctx context.Context, owner string, blocked storage.JID) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO block_list (owner, blocked_jid) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
		owner, blocked)
	return err
}

func (s *pgBlock) Remove(ctx context.Context, owner string, blocked storage.JID) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM block_list WHERE owner=$1 AND blocked_jid=$2`, owner, blocked)
	return err
}

func (s *pgBlock) Clear(ctx context.Context, owner string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM block_list WHERE owner=$1`, owner)
	return err
}

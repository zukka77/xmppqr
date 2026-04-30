package pg

import (
	"context"

	"github.com/danielinux/xmppqr/internal/storage"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DB struct {
	pool *pgxpool.Pool
}

func Open(ctx context.Context, dsn string, maxConns int) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	if maxConns > 0 {
		cfg.MaxConns = int32(maxConns)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &DB{pool: pool}, nil
}

func (db *DB) Close() {
	db.pool.Close()
}

func (db *DB) Stores() *storage.Stores {
	return &storage.Stores{
		Users:   &pgUsers{pool: db.pool},
		Roster:  &pgRoster{pool: db.pool},
		MAM:     &pgMAM{pool: db.pool},
		PEP:     &pgPEP{pool: db.pool},
		MUC:     &pgMUC{pool: db.pool},
		Push:    &pgPush{pool: db.pool},
		Block:   &pgBlock{pool: db.pool},
		Offline: &pgOffline{pool: db.pool},
	}
}

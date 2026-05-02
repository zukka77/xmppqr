package main

import (
	"context"
	"errors"

	"github.com/danielinux/xmppqr/internal/config"
	"github.com/danielinux/xmppqr/internal/storage"
	"github.com/danielinux/xmppqr/internal/storage/pg"
)

type pgHandle struct {
	db *pg.DB
}

func (h *pgHandle) Close() { h.db.Close() }

func openStores(ctx context.Context, cfg *config.Config) (*storage.Stores, func(), error) {
	switch cfg.DB.Driver {
	case "postgres":
		db, err := pg.Open(ctx, cfg.DB.DSN, cfg.DB.MaxConns)
		if err != nil {
			return nil, nil, err
		}
		if cfg.DB.MigrateOnStart {
			if err := db.Migrate(ctx); err != nil {
				db.Close()
				return nil, nil, err
			}
		}
		if err := db.NormalizeUsernamesToBareJIDs(ctx, cfg.Server.Domain); err != nil {
			db.Close()
			return nil, nil, err
		}
		return db.Stores(), db.Close, nil
	case "memory":
		return nil, nil, errors.New("memory driver is not persistent; use postgres for this command")
	default:
		return nil, nil, errors.New("unknown db driver: " + cfg.DB.Driver)
	}
}

func openStoresWithMigrate(ctx context.Context, cfg *config.Config) (*storage.Stores, func(), *pg.DB, error) {
	if cfg.DB.Driver != "postgres" {
		return nil, nil, nil, errors.New("migrate requires postgres; memory driver has no migrations")
	}
	db, err := pg.Open(ctx, cfg.DB.DSN, cfg.DB.MaxConns)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := db.NormalizeUsernamesToBareJIDs(ctx, cfg.Server.Domain); err != nil {
		db.Close()
		return nil, nil, nil, err
	}
	return db.Stores(), db.Close, db, nil
}

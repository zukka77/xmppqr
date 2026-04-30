package pg

import (
	"context"
	"errors"

	"github.com/danielinux/xmppqr/internal/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type pgUsers struct{ pool *pgxpool.Pool }

func (s *pgUsers) Get(ctx context.Context, username string) (*storage.User, error) {
	u := &storage.User{}
	err := s.pool.QueryRow(ctx, `
		SELECT username, scram_salt, scram_iter, argon2_params,
		       stored_key256, server_key256, stored_key512, server_key512,
		       created_at, disabled
		FROM users WHERE username=$1`, username,
	).Scan(
		&u.Username, &u.ScramSalt, &u.ScramIter, &u.Argon2Params,
		&u.StoredKey256, &u.ServerKey256, &u.StoredKey512, &u.ServerKey512,
		&u.CreatedAt, &u.Disabled,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *pgUsers) Put(ctx context.Context, u *storage.User) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO users
			(username, scram_salt, scram_iter, argon2_params,
			 stored_key256, server_key256, stored_key512, server_key512,
			 created_at, disabled)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (username) DO UPDATE SET
			scram_salt    = EXCLUDED.scram_salt,
			scram_iter    = EXCLUDED.scram_iter,
			argon2_params = EXCLUDED.argon2_params,
			stored_key256 = EXCLUDED.stored_key256,
			server_key256 = EXCLUDED.server_key256,
			stored_key512 = EXCLUDED.stored_key512,
			server_key512 = EXCLUDED.server_key512,
			disabled      = EXCLUDED.disabled`,
		u.Username, u.ScramSalt, u.ScramIter, u.Argon2Params,
		u.StoredKey256, u.ServerKey256, u.StoredKey512, u.ServerKey512,
		u.CreatedAt, u.Disabled,
	)
	return err
}

func (s *pgUsers) Delete(ctx context.Context, username string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM users WHERE username=$1`, username)
	return err
}

func (s *pgUsers) List(ctx context.Context, limit, offset int) ([]*storage.User, error) {
	var limitVal any
	if limit > 0 {
		limitVal = limit
	} else {
		limitVal = nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT username, scram_salt, scram_iter, argon2_params,
		       stored_key256, server_key256, stored_key512, server_key512,
		       created_at, disabled
		FROM users ORDER BY username LIMIT $1 OFFSET $2`, limitVal, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*storage.User
	for rows.Next() {
		u := &storage.User{}
		if err := rows.Scan(
			&u.Username, &u.ScramSalt, &u.ScramIter, &u.Argon2Params,
			&u.StoredKey256, &u.ServerKey256, &u.StoredKey512, &u.ServerKey512,
			&u.CreatedAt, &u.Disabled,
		); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

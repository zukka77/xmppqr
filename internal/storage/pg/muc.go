package pg

import (
	"context"
	"errors"

	"github.com/danielinux/xmppqr/internal/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type pgMUC struct{ pool *pgxpool.Pool }

func (s *pgMUC) PutRoom(ctx context.Context, room *storage.MUCRoom) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO muc_rooms (jid, config, created_at, persistent)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (jid) DO UPDATE SET
			config     = EXCLUDED.config,
			persistent = EXCLUDED.persistent`,
		room.JID, nullBytes(room.Config), room.CreatedAt, room.Persistent,
	)
	return err
}

func (s *pgMUC) GetRoom(ctx context.Context, jid storage.JID) (*storage.MUCRoom, error) {
	r := &storage.MUCRoom{}
	var config []byte
	err := s.pool.QueryRow(ctx, `
		SELECT jid, config, created_at, persistent FROM muc_rooms WHERE jid=$1`, jid,
	).Scan(&r.JID, &config, &r.CreatedAt, &r.Persistent)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	r.Config = config
	return r, nil
}

func (s *pgMUC) DeleteRoom(ctx context.Context, jid storage.JID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM muc_rooms WHERE jid=$1`, jid)
	return err
}

func (s *pgMUC) PutAffiliation(ctx context.Context, a *storage.MUCAffiliation) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO muc_affiliations (room_jid, user_jid, affiliation)
		VALUES ($1,$2,$3)
		ON CONFLICT (room_jid, user_jid) DO UPDATE SET
			affiliation = EXCLUDED.affiliation`,
		a.RoomJID, a.UserJID, a.Affiliation,
	)
	return err
}

func (s *pgMUC) ListAffiliations(ctx context.Context, roomJID storage.JID) ([]*storage.MUCAffiliation, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT room_jid, user_jid, affiliation FROM muc_affiliations WHERE room_jid=$1`, roomJID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*storage.MUCAffiliation
	for rows.Next() {
		a := &storage.MUCAffiliation{}
		if err := rows.Scan(&a.RoomJID, &a.UserJID, &a.Affiliation); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *pgMUC) ListRooms(ctx context.Context) ([]*storage.MUCRoom, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT jid, config, created_at, persistent FROM muc_rooms`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*storage.MUCRoom
	for rows.Next() {
		r := &storage.MUCRoom{}
		var config []byte
		if err := rows.Scan(&r.JID, &config, &r.CreatedAt, &r.Persistent); err != nil {
			return nil, err
		}
		r.Config = config
		out = append(out, r)
	}
	return out, rows.Err()
}

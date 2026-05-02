package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

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

func (s *pgMUC) PutRoomSubject(ctx context.Context, roomJID storage.JID, subject, byNick string, ts time.Time) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE muc_rooms SET subject=$1, subject_by=$2, subject_ts=$3 WHERE jid=$4`,
		subject, byNick, ts, roomJID,
	)
	return err
}

func (s *pgMUC) GetRoomSubject(ctx context.Context, roomJID storage.JID) (subject, byNick string, ts time.Time, err error) {
	var subjectTS *time.Time
	err = s.pool.QueryRow(ctx, `
		SELECT subject, subject_by, subject_ts FROM muc_rooms WHERE jid=$1`, roomJID,
	).Scan(&subject, &byNick, &subjectTS)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", time.Time{}, errNotFound
	}
	if err != nil {
		return "", "", time.Time{}, err
	}
	if subjectTS != nil {
		ts = *subjectTS
	}
	return subject, byNick, ts, nil
}

func (s *pgMUC) AppendHistory(ctx context.Context, h *storage.MUCHistory) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO muc_history (room_jid, sender_jid, ts, stanza_id, stanza_xml)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING id`,
		h.RoomJID, nullJID(h.SenderJID), h.TS, h.StanzaID, h.StanzaXML,
	).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (s *pgMUC) QueryHistory(ctx context.Context, roomJID storage.JID, before, after *time.Time, limit int) ([]*storage.MUCHistory, error) {
	q := `SELECT id, room_jid, sender_jid, ts, stanza_id, stanza_xml FROM muc_history WHERE room_jid=$1`
	args := []any{roomJID}
	n := 2
	if after != nil {
		q += fmt.Sprintf(" AND ts > $%d", n)
		args = append(args, *after)
		n++
	}
	if before != nil {
		q += fmt.Sprintf(" AND ts < $%d", n)
		args = append(args, *before)
		n++
	}
	q += " ORDER BY ts ASC"
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT $%d", n)
		args = append(args, limit)
	}

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*storage.MUCHistory
	for rows.Next() {
		h := &storage.MUCHistory{}
		var senderJID *string
		if err := rows.Scan(&h.ID, &h.RoomJID, &senderJID, &h.TS, &h.StanzaID, &h.StanzaXML); err != nil {
			return nil, err
		}
		if senderJID != nil {
			h.SenderJID = *senderJID
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *pgMUC) DeleteHistoryBefore(ctx context.Context, roomJID storage.JID, ts time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM muc_history WHERE room_jid=$1 AND ts < $2`, roomJID, ts)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

package pg

import (
	"context"
	"fmt"
	"time"

	"github.com/danielinux/xmppqr/internal/storage"
	"github.com/jackc/pgx/v5/pgxpool"
)

type pgMAM struct{ pool *pgxpool.Pool }

func (s *pgMAM) Append(ctx context.Context, msg *storage.ArchivedStanza) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO mam_archive (owner, with_jid, ts, stanza_id, origin_id, direction, stanza_xml)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id`,
		msg.Owner, nullJID(msg.With), msg.TS, msg.StanzaID, msg.OriginID, msg.Direction, msg.StanzaXML,
	).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (s *pgMAM) Query(ctx context.Context, owner string, with *storage.JID, before, after *time.Time, limit int) ([]*storage.ArchivedStanza, error) {
	q := `SELECT id, owner, with_jid, ts, stanza_id, origin_id, direction, stanza_xml FROM mam_archive WHERE owner=$1`
	args := []any{owner}
	n := 2
	if with != nil {
		q += fmt.Sprintf(" AND with_jid=$%d", n)
		args = append(args, *with)
		n++
	}
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
	var out []*storage.ArchivedStanza
	for rows.Next() {
		m := &storage.ArchivedStanza{}
		var withJID *string
		if err := rows.Scan(&m.ID, &m.Owner, &withJID, &m.TS, &m.StanzaID, &m.OriginID, &m.Direction, &m.StanzaXML); err != nil {
			return nil, err
		}
		if withJID != nil {
			m.With = *withJID
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *pgMAM) Prune(ctx context.Context, owner string, olderThan time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM mam_archive WHERE owner=$1 AND ts < $2`, owner, olderThan)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func nullJID(j storage.JID) *string {
	if j == "" {
		return nil
	}
	return &j
}

func (s *pgMAM) AppendMUC(ctx context.Context, m *storage.MUCArchivedStanza) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO muc_mam_archive (room_jid, sender_bare_jid, ts, stanza_id, origin_id, stanza_xml)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id`,
		m.RoomJID, nullJID(m.SenderBareJID), m.TS, m.StanzaID, m.OriginID, m.StanzaXML,
	).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (s *pgMAM) QueryMUC(ctx context.Context, roomJID storage.JID, with *storage.JID, before, after *time.Time, limit int) ([]*storage.MUCArchivedStanza, error) {
	q := `SELECT id, room_jid, sender_bare_jid, ts, stanza_id, origin_id, stanza_xml FROM muc_mam_archive WHERE room_jid=$1`
	args := []any{roomJID}
	n := 2
	if with != nil {
		q += fmt.Sprintf(" AND sender_bare_jid=$%d", n)
		args = append(args, *with)
		n++
	}
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
	var out []*storage.MUCArchivedStanza
	for rows.Next() {
		m := &storage.MUCArchivedStanza{}
		var senderJID *string
		if err := rows.Scan(&m.ID, &m.RoomJID, &senderJID, &m.TS, &m.StanzaID, &m.OriginID, &m.StanzaXML); err != nil {
			return nil, err
		}
		if senderJID != nil {
			m.SenderBareJID = *senderJID
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *pgMAM) PruneMUC(ctx context.Context, roomJID storage.JID, olderThan time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM muc_mam_archive WHERE room_jid=$1 AND ts < $2`, roomJID, olderThan)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

package pg

import (
	"context"

	"github.com/danielinux/xmppqr/internal/storage"
	"github.com/jackc/pgx/v5/pgxpool"
)

type pgPush struct{ pool *pgxpool.Pool }

func (s *pgPush) Put(ctx context.Context, reg *storage.PushRegistration) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO push_registrations (owner, service_jid, node, form_xml, enabled_at)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (owner, service_jid, node) DO UPDATE SET
			form_xml   = EXCLUDED.form_xml,
			enabled_at = EXCLUDED.enabled_at`,
		reg.Owner, reg.ServiceJID, reg.Node, nullBytes(reg.FormXML), reg.EnabledAt,
	)
	return err
}

func (s *pgPush) List(ctx context.Context, owner string) ([]*storage.PushRegistration, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT owner, service_jid, node, form_xml, enabled_at
		FROM push_registrations WHERE owner=$1`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*storage.PushRegistration
	for rows.Next() {
		r := &storage.PushRegistration{}
		var formXML []byte
		if err := rows.Scan(&r.Owner, &r.ServiceJID, &r.Node, &formXML, &r.EnabledAt); err != nil {
			return nil, err
		}
		r.FormXML = formXML
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *pgPush) Delete(ctx context.Context, owner string, serviceJID storage.JID, node string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM push_registrations WHERE owner=$1 AND service_jid=$2 AND node=$3`,
		owner, serviceJID, node)
	return err
}

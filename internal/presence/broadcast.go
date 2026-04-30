// Package presence implements RFC 6121 §4 presence broadcasting.
package presence

import (
	"context"
	"log/slog"

	"github.com/danielinux/xmppqr/internal/roster"
	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/stanza"
)

type Session interface {
	router.Session
}

type Broadcaster struct {
	router *router.Router
	roster *roster.Manager
	logger *slog.Logger
}

func New(r *router.Router, rm *roster.Manager, l *slog.Logger) *Broadcaster {
	return &Broadcaster{router: r, roster: rm, logger: l}
}

func (b *Broadcaster) OnInitialPresence(ctx context.Context, sess Session, raw []byte) error {
	return b.fanOut(ctx, sess, raw, false)
}

func (b *Broadcaster) OnPresenceUpdate(ctx context.Context, sess Session, raw []byte) error {
	return b.fanOut(ctx, sess, raw, true)
}

func (b *Broadcaster) OnUnavailablePresence(ctx context.Context, sess Session, raw []byte) error {
	return b.fanOut(ctx, sess, raw, false)
}

func (b *Broadcaster) OnDirectedPresence(ctx context.Context, sess Session, to stanza.JID, raw []byte) error {
	return b.router.RouteToFull(ctx, to, raw)
}

func (b *Broadcaster) fanOut(ctx context.Context, sess Session, raw []byte, includeSelf bool) error {
	owner := sess.JID().Bare().String()
	items, _, err := b.roster.Get(ctx, owner)
	if err != nil {
		return err
	}

	for _, item := range items {
		// RFC 6121 §4.2.2: send to contacts with subscription from or both.
		if item.Subscription != 1 && item.Subscription != 3 {
			continue
		}
		cjid, err := stanza.Parse(item.Contact)
		if err != nil {
			continue
		}
		_, _ = b.router.RouteToBare(ctx, cjid, raw)
	}

	if includeSelf {
		// Also deliver to all bound resources of the same bare JID.
		_, _ = b.router.RouteToBare(ctx, sess.JID().Bare(), raw)
	}
	return nil
}


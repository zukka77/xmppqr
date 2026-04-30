package router

import (
	"context"
	"errors"

	"github.com/danielinux/xmppqr/internal/stanza"
)

type Session interface {
	JID() stanza.JID
	Priority() int
	IsAvailable() bool
	Deliver(ctx context.Context, raw []byte) error
}

var ErrBackpressure = errors.New("session outbound queue full")
var ErrNoSession = errors.New("no bound session for JID")

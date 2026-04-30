package s2s

import (
	"context"
	"log/slog"
	"net"

	xtls "github.com/danielinux/xmppqr/internal/tls"
)

type Listener struct {
	raw          net.Listener
	pool         *Pool
	tlsServerCtx *xtls.Context
	log          *slog.Logger
}

func NewListener(addr string, pool *Pool, tlsServerCtx *xtls.Context, log *slog.Logger) (*Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Listener{raw: l, pool: pool, tlsServerCtx: tlsServerCtx, log: log}, nil
}

func (l *Listener) Accept(ctx context.Context) error {
	for {
		conn, err := l.raw.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return err
			}
		}
		go func(c net.Conn) {
			if err := l.pool.AcceptInbound(ctx, c, l.tlsServerCtx); err != nil {
				l.log.Warn("s2s inbound error", "err", err)
			}
		}(conn)
	}
}

func (l *Listener) Close() error { return l.raw.Close() }

func (l *Listener) Addr() string { return l.raw.Addr().String() }

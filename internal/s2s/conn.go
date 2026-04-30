package s2s

import (
	"context"
	"io"
	"net"
	"sync/atomic"

	xmldec "github.com/danielinux/xmppqr/internal/xml"
)

// Conn wraps an s2s stream.  tlsConn may be a *xtls.Conn or, when skipTLS is
// set in tests, a plain net.Conn.
type Conn struct {
	remoteDomain string
	netConn      net.Conn
	dec          *xmldec.Decoder
	enc          *xmldec.Encoder
	streamID     string
	closed       atomic.Bool
}

func newConn(remoteDomain string, nc net.Conn, streamID string) *Conn {
	return &Conn{
		remoteDomain: remoteDomain,
		netConn:      nc,
		dec:          xmldec.NewDecoder(nc),
		enc:          xmldec.NewEncoder(nc),
		streamID:     streamID,
	}
}

func (c *Conn) WriteStanza(raw []byte) error {
	if c.closed.Load() {
		return io.ErrClosedPipe
	}
	_, err := c.enc.WriteRaw(raw)
	return err
}

func (c *Conn) ReadLoop(ctx context.Context, handler func(raw []byte) error) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_, raw, err := c.dec.NextElement()
		if err != nil {
			return err
		}
		if err := handler(raw); err != nil {
			return err
		}
	}
}

func (c *Conn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	return c.netConn.Close()
}

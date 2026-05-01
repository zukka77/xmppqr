package c2s

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/coder/websocket"
	xtls "github.com/danielinux/xmppqr/internal/tls"
)

type wsConn struct {
	ws      *websocket.Conn
	ctx     context.Context
	readBuf []byte
	readPos int
	readMu  sync.Mutex
	writeMu sync.Mutex
	remote  net.Addr
	local   net.Addr
}

func newWSConn(ctx context.Context, ws *websocket.Conn, remote, local net.Addr) *wsConn {
	return &wsConn{
		ws:     ws,
		ctx:    ctx,
		remote: remote,
		local:  local,
	}
}

func (c *wsConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for c.readPos >= len(c.readBuf) {
		c.readBuf = nil
		c.readPos = 0
		_, data, err := c.ws.Read(c.ctx)
		if err != nil {
			return 0, err
		}
		c.readBuf = data
	}

	n := copy(p, c.readBuf[c.readPos:])
	c.readPos += n
	return n, nil
}

func (c *wsConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	err := c.ws.Write(c.ctx, websocket.MessageText, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wsConn) Close() error {
	return c.ws.Close(websocket.StatusNormalClosure, "")
}

func (c *wsConn) LocalAddr() net.Addr  { return c.local }
func (c *wsConn) RemoteAddr() net.Addr { return c.remote }

func (c *wsConn) SetDeadline(t time.Time) error      { return nil }
func (c *wsConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *wsConn) SetWriteDeadline(t time.Time) error { return nil }

// SCRAM-PLUS channel binding is not available over WebSocket because the
// underlying TLS session is owned by the HTTP server and not exposed via
// net/http. PLAIN-over-HTTPS is acceptable since TLS is already enforced
// at the transport layer.
func (c *wsConn) Exporter(label string, ctx []byte, n int) ([]byte, error) {
	return nil, errors.New("ws: exporter not available")
}

func (c *wsConn) HandshakeState() xtls.HandshakeState {
	return xtls.HandshakeState{}
}

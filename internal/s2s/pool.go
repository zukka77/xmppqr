package s2s

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/danielinux/xmppqr/internal/stanza"
	xtls "github.com/danielinux/xmppqr/internal/tls"
)

type VerifyMode int

const (
	VerifyShared      VerifyMode = iota // verify key locally using shared secret
	VerifyBackChannel                   // open back-channel per XEP-0220 §2.4
)

type InboundRouter interface {
	RouteInbound(ctx context.Context, raw []byte) error
}

type Dialer interface {
	Dial(ctx context.Context, host, addr string) (net.Conn, error)
}

type defaultDialer struct{ tlsCtx *xtls.Context }

func (d *defaultDialer) Dial(_ context.Context, host, addr string) (net.Conn, error) {
	return xtls.Dial("tcp", addr, d.tlsCtx)
}

type plainDialer struct{}

func (d *plainDialer) Dial(ctx context.Context, _, addr string) (net.Conn, error) {
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", addr)
}

type Pool struct {
	domain    string
	secret    []byte
	tlsClient *xtls.Context
	inbound   InboundRouter
	log       *slog.Logger

	mu    sync.RWMutex
	conns map[string]*Conn

	streamIDs map[string]string

	pinTargets map[string]string

	skipTLS    bool
	mtlsEnabled bool
	dialer      Dialer
	verifyMode  VerifyMode
	verifyRL    *rateLimiter
}

func New(domain string, secret []byte, tlsClientCtx *xtls.Context, inbound InboundRouter, log *slog.Logger) *Pool {
	p := &Pool{
		domain:     domain,
		secret:     secret,
		tlsClient:  tlsClientCtx,
		inbound:    inbound,
		log:        log,
		conns:      make(map[string]*Conn),
		streamIDs:  make(map[string]string),
		pinTargets: make(map[string]string),
		verifyMode: VerifyShared,
		verifyRL:   newRateLimiter(10, time.Minute),
	}
	if tlsClientCtx != nil {
		p.dialer = &defaultDialer{tlsCtx: tlsClientCtx}
	}
	return p
}

func (p *Pool) SetSkipTLS(v bool) {
	p.skipTLS = v
	if v && p.dialer == nil {
		p.dialer = &plainDialer{}
	}
}

func (p *Pool) SetMTLS(enabled bool) {
	p.mtlsEnabled = enabled
}

func (p *Pool) SetVerifyMode(m VerifyMode) {
	p.verifyMode = m
}

// PinTarget overrides DNS SRV resolution for domain, forcing connections to addr ("host:port").
// Used in tests to bypass DNS.
func (p *Pool) PinTarget(domain, addr string) {
	p.mu.Lock()
	p.pinTargets[domain] = addr
	p.mu.Unlock()
}

func (p *Pool) Send(ctx context.Context, _, toBare stanza.JID, raw []byte) error {
	remote := toBare.Domain
	p.mu.RLock()
	c, ok := p.conns[remote]
	p.mu.RUnlock()
	if ok && !c.closed.Load() {
		return c.WriteStanza(raw)
	}

	c, err := p.connectOutbound(ctx, remote)
	if err != nil {
		return fmt.Errorf("s2s: dial %s: %w", remote, err)
	}
	return c.WriteStanza(raw)
}

func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		c.Close()
	}
	p.conns = make(map[string]*Conn)
}

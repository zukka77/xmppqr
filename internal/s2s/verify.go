package s2s

import (
	"context"
	"fmt"
	"net"

	xtls "github.com/danielinux/xmppqr/internal/tls"
	xmldec "github.com/danielinux/xmppqr/internal/xml"
)

// verifyDialback opens a fresh outbound connection to the originating server,
// sends <db:verify>, and waits for <db:verify type='valid|invalid'/>.
// This is the XEP-0220 §2.4 back-channel. Returns nil if valid, error otherwise.
func (p *Pool) verifyDialback(ctx context.Context, originating, streamID, key string) error {
	p.mu.RLock()
	pinned, hasPinned := p.pinTargets[originating]
	p.mu.RUnlock()

	var addr string
	if hasPinned {
		addr = pinned
	} else {
		var err error
		addr, err = resolveS2S(ctx, originating)
		if err != nil {
			return err
		}
	}

	nc, err := p.dialPlain(ctx, originating, addr)
	if err != nil {
		return fmt.Errorf("s2s verify: dial %s: %w", originating, err)
	}
	defer nc.Close()

	nc, err = p.openVerifyStream(ctx, nc, originating)
	if err != nil {
		return err
	}

	dbVerify := fmt.Sprintf(
		"<db:verify xmlns:db='%s' from='%s' to='%s' id='%s'>%s</db:verify>",
		nsDialback, p.domain, originating, streamID, key,
	)
	if _, err := nc.Write([]byte(dbVerify)); err != nil {
		return fmt.Errorf("s2s verify: send db:verify: %w", err)
	}

	dec := xmldec.NewDecoder(nc)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		start, _, err := dec.NextElement()
		if err != nil {
			return fmt.Errorf("s2s verify: read response: %w", err)
		}
		if start.Name.Local == "verify" && start.Name.Space == nsDB {
			typ := attrVal(start, "type")
			if typ == "valid" {
				return nil
			}
			return fmt.Errorf("s2s verify: key invalid (type=%q)", typ)
		}
	}
}

// openVerifyStream sends a stream open and reads the peer's stream open +
// features. For TLS-enabled pools it also does STARTTLS. Returns the
// (possibly upgraded) net.Conn.
func (p *Pool) openVerifyStream(ctx context.Context, nc net.Conn, remoteDomain string) (net.Conn, error) {
	if err := sendStreamOpen(nc, p.domain, remoteDomain); err != nil {
		return nil, err
	}

	dec := xmldec.NewDecoder(nc)

	if _, err := dec.OpenStream(ctx); err != nil {
		return nil, fmt.Errorf("s2s verify: peer stream open: %w", err)
	}

	if err := readFeatures(dec); err != nil {
		return nil, err
	}

	if p.skipTLS {
		return nc, nil
	}

	if _, err := nc.Write([]byte("<starttls xmlns='" + nsTLS + "'/>")); err != nil {
		return nil, fmt.Errorf("s2s verify: send starttls: %w", err)
	}

	if err := waitProceed(dec); err != nil {
		return nil, err
	}

	tcpConn, ok := nc.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("s2s verify: need *net.TCPConn for TLS, got %T", nc)
	}

	tlsConn, err := xtls.ClientHandshake(p.tlsClient, tcpConn, remoteDomain)
	if err != nil {
		return nil, fmt.Errorf("s2s verify: TLS handshake: %w", err)
	}

	if err := sendStreamOpen(tlsConn, p.domain, remoteDomain); err != nil {
		return nil, err
	}

	dec2 := xmldec.NewDecoder(tlsConn)
	if _, err := dec2.OpenStream(ctx); err != nil {
		return nil, fmt.Errorf("s2s verify: post-TLS stream open: %w", err)
	}

	return tlsConn, nil
}

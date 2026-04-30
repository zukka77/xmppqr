package s2s

import (
	"context"
	"fmt"
	"net"

	xtls "github.com/danielinux/xmppqr/internal/tls"
	xmldec "github.com/danielinux/xmppqr/internal/xml"
)

func (p *Pool) AcceptInbound(ctx context.Context, raw net.Conn, tlsServerCtx *xtls.Context) error {
	defer raw.Close()

	dec := xmldec.NewDecoder(raw)

	peerHdr, err := dec.OpenStream(ctx)
	if err != nil {
		return fmt.Errorf("s2s inbound: read stream open: %w", err)
	}
	remoteDomain := peerHdr.From
	if remoteDomain == "" {
		return fmt.Errorf("s2s inbound: missing from in stream header")
	}

	streamID := newStreamID()

	if err := sendInboundStreamOpen(raw, p.domain, remoteDomain, streamID); err != nil {
		return err
	}

	var nc net.Conn = raw

	if !p.skipTLS {
		features := fmt.Sprintf(
			"<stream:features>"+
				"<starttls xmlns='%s'><required/></starttls>"+
				"<dialback xmlns='urn:xmpp:features:dialback'/>"+
				"</stream:features>",
			nsTLS,
		)
		if _, err := raw.Write([]byte(features)); err != nil {
			return fmt.Errorf("s2s inbound: send features: %w", err)
		}

		if err := waitInboundSTARTTLS(dec); err != nil {
			return err
		}

		if _, err := raw.Write([]byte("<proceed xmlns='" + nsTLS + "'/>")); err != nil {
			return fmt.Errorf("s2s inbound: send proceed: %w", err)
		}

		tcpConn, ok := raw.(*net.TCPConn)
		if !ok {
			return fmt.Errorf("s2s inbound: need *net.TCPConn for TLS, got %T", raw)
		}
		tlsConn, err := xtls.ServerHandshake(tlsServerCtx, tcpConn)
		if err != nil {
			return fmt.Errorf("s2s inbound: TLS handshake: %w", err)
		}
		nc = tlsConn

		dec2 := xmldec.NewDecoder(nc)
		peerHdr2, err := dec2.OpenStream(ctx)
		if err != nil {
			return fmt.Errorf("s2s inbound: post-TLS stream open: %w", err)
		}
		if peerHdr2.From != "" {
			remoteDomain = peerHdr2.From
		}

		streamID = newStreamID()
		if err := sendInboundStreamOpen(nc, p.domain, remoteDomain, streamID); err != nil {
			return err
		}

		postFeatures := "<stream:features><dialback xmlns='urn:xmpp:features:dialback'/></stream:features>"
		if _, err := nc.Write([]byte(postFeatures)); err != nil {
			return fmt.Errorf("s2s inbound: send post-TLS features: %w", err)
		}
		dec = dec2
	} else {
		features := "<stream:features><dialback xmlns='urn:xmpp:features:dialback'/></stream:features>"
		if _, err := raw.Write([]byte(features)); err != nil {
			return fmt.Errorf("s2s inbound: send features: %w", err)
		}
	}

	if err := p.awaitAndVerifyDialback(ctx, nc, dec, remoteDomain, streamID); err != nil {
		return err
	}

	conn := newConn(remoteDomain, nc, streamID)
	p.mu.Lock()
	p.conns["inbound:"+remoteDomain] = conn
	p.mu.Unlock()

	return conn.ReadLoop(ctx, func(b []byte) error {
		return p.inbound.RouteInbound(ctx, b)
	})
}

// awaitAndVerifyDialback reads the peer's <db:result> carrying the key,
// verifies it locally, and sends back <db:result type='valid|invalid'/>.
func (p *Pool) awaitAndVerifyDialback(ctx context.Context, nc net.Conn, dec *xmldec.Decoder, remoteDomain, streamID string) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		start, raw, err := dec.NextElement()
		if err != nil {
			return fmt.Errorf("s2s inbound: wait db:result: %w", err)
		}

		if start.Name.Local == "result" && start.Name.Space == nsDB {
			claimedFrom := attrVal(start, "from")
			if claimedFrom != "" {
				remoteDomain = claimedFrom
			}
			key := extractTextBody(raw)
			if key == "" {
				return fmt.Errorf("s2s inbound: empty dialback key from %s", remoteDomain)
			}
			if !p.handleDBVerify(streamID, remoteDomain, p.domain, key) {
				reply := fmt.Sprintf("<db:result xmlns:db='%s' from='%s' to='%s' type='invalid'/>",
					nsDialback, p.domain, remoteDomain)
				_, _ = nc.Write([]byte(reply))
				return fmt.Errorf("s2s inbound: dialback key invalid from %s", remoteDomain)
			}
			reply := fmt.Sprintf("<db:result xmlns:db='%s' from='%s' to='%s' type='valid'/>",
				nsDialback, p.domain, remoteDomain)
			if _, err := nc.Write([]byte(reply)); err != nil {
				return fmt.Errorf("s2s inbound: send db:result valid: %w", err)
			}
			return nil
		}
	}
}

func sendInboundStreamOpen(w net.Conn, from, to, id string) error {
	hdr := fmt.Sprintf(
		"<?xml version='1.0'?><stream:stream xmlns='jabber:server' "+
			"xmlns:stream='http://etherx.jabber.org/streams' "+
			"xmlns:db='%s' from='%s' to='%s' id='%s' version='1.0'>",
		nsDialback, from, to, id,
	)
	_, err := w.Write([]byte(hdr))
	return err
}

func waitInboundSTARTTLS(dec *xmldec.Decoder) error {
	start, _, err := dec.NextElement()
	if err != nil {
		return fmt.Errorf("s2s inbound: wait starttls: %w", err)
	}
	if start.Name.Local != "starttls" {
		return fmt.Errorf("s2s inbound: expected starttls, got %s", start.Name.Local)
	}
	return nil
}

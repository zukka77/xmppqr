package s2s

import (
	"context"
	"encoding/xml"
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

		var peerCertDER []byte
		if xtlsConn, ok := nc.(*xtls.Conn); ok {
			hs := xtlsConn.HandshakeState()
			if len(hs.PeerCertChain) > 0 {
				peerCertDER = hs.PeerCertChain[0]
			}
		}

		if p.mtlsEnabled && len(peerCertDER) > 0 {
			postFeatures := fmt.Sprintf(
				"<stream:features>"+
					"<mechanisms xmlns='%s'><mechanism>EXTERNAL</mechanism></mechanisms>"+
					"<dialback xmlns='urn:xmpp:features:dialback'/>"+
					"</stream:features>",
				nsSASL,
			)
			if _, err := nc.Write([]byte(postFeatures)); err != nil {
				return fmt.Errorf("s2s inbound: send post-TLS features: %w", err)
			}
		} else {
			postFeatures := "<stream:features><dialback xmlns='urn:xmpp:features:dialback'/></stream:features>"
			if _, err := nc.Write([]byte(postFeatures)); err != nil {
				return fmt.Errorf("s2s inbound: send post-TLS features: %w", err)
			}
		}

		elem, elemRaw, err2 := dec2.NextElement()
		if err2 != nil {
			return fmt.Errorf("s2s inbound: read post-TLS element: %w", err2)
		}

		if elem.Name.Local == "auth" && elem.Name.Space == nsSASL {
			mech := attrVal(elem, "mechanism")
			if mech == "EXTERNAL" && len(peerCertDER) > 0 {
				if err := p.handleExternalAuth(nc, ctx, remoteDomain, peerCertDER); err != nil {
					return err
				}
				return nil
			}
			failure := fmt.Sprintf("<failure xmlns='%s'><not-authorized/></failure>", nsSASL)
			_, _ = nc.Write([]byte(failure))
			return fmt.Errorf("s2s inbound: EXTERNAL auth failed: no peer cert")
		}

		if err := p.processDialbackElement(ctx, nc, dec2, elem, elemRaw, remoteDomain, streamID); err != nil {
			return err
		}
		dec = dec2
	} else {
		features := "<stream:features><dialback xmlns='urn:xmpp:features:dialback'/></stream:features>"
		if _, err := raw.Write([]byte(features)); err != nil {
			return fmt.Errorf("s2s inbound: send features: %w", err)
		}
		if err := p.awaitAndVerifyDialback(ctx, nc, dec, remoteDomain, streamID); err != nil {
			return err
		}
	}

	conn := newConn(remoteDomain, nc, streamID)
	p.mu.Lock()
	p.conns["inbound:"+remoteDomain] = conn
	p.mu.Unlock()

	return conn.ReadLoop(ctx, func(b []byte) error {
		return p.inbound.RouteInbound(ctx, b)
	})
}

func (p *Pool) handleExternalAuth(nc net.Conn, ctx context.Context, remoteDomain string, peerCertDER []byte) error {
	matched, err := certMatchesDomain(peerCertDER, remoteDomain)
	if err != nil || !matched {
		failure := fmt.Sprintf("<failure xmlns='%s'><not-authorized/></failure>", nsSASL)
		_, _ = nc.Write([]byte(failure))
		if err != nil {
			return fmt.Errorf("s2s inbound: cert parse error: %w", err)
		}
		return fmt.Errorf("s2s inbound: EXTERNAL: cert SAN does not match domain %s", remoteDomain)
	}

	success := fmt.Sprintf("<success xmlns='%s'/>", nsSASL)
	if _, err := nc.Write([]byte(success)); err != nil {
		return fmt.Errorf("s2s inbound: send success: %w", err)
	}

	dec2 := xmldec.NewDecoder(nc)
	peerHdr3, err := dec2.OpenStream(ctx)
	if err != nil {
		return fmt.Errorf("s2s inbound: post-EXTERNAL stream open: %w", err)
	}
	if peerHdr3.From != "" {
		remoteDomain = peerHdr3.From
	}

	newStreamID := newStreamID()
	if err := sendInboundStreamOpen(nc, p.domain, remoteDomain, newStreamID); err != nil {
		return err
	}

	postAuthFeatures := "<stream:features/>"
	if _, err := nc.Write([]byte(postAuthFeatures)); err != nil {
		return fmt.Errorf("s2s inbound: send post-auth features: %w", err)
	}

	conn := newConn(remoteDomain, nc, newStreamID)
	p.mu.Lock()
	p.conns["inbound:"+remoteDomain] = conn
	p.mu.Unlock()

	return conn.ReadLoop(ctx, func(b []byte) error {
		return p.inbound.RouteInbound(ctx, b)
	})
}

func (p *Pool) awaitAndVerifyDialback(ctx context.Context, nc net.Conn, dec *xmldec.Decoder, remoteDomain, streamID string) error {
	return p.processDialbackElement(ctx, nc, dec, xml.StartElement{}, nil, remoteDomain, streamID)
}

func (p *Pool) processDialbackElement(ctx context.Context, nc net.Conn, dec *xmldec.Decoder, preStart xml.StartElement, preRaw []byte, remoteDomain, streamID string) error {
	first := preRaw != nil
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var start xml.StartElement
		var raw []byte
		if first {
			start, raw = preStart, preRaw
			first = false
		} else {
			var err error
			start, raw, err = dec.NextElement()
			if err != nil {
				return fmt.Errorf("s2s inbound: wait db:result: %w", err)
			}
		}

		if start.Name.Local == "verify" && start.Name.Space == nsDB {
			remoteAddr := ""
			if tc, ok := nc.(interface{ RemoteAddr() net.Addr }); ok {
				if addr := tc.RemoteAddr(); addr != nil {
					host, _, _ := net.SplitHostPort(addr.String())
					remoteAddr = host
				}
			}
			if remoteAddr != "" && !p.verifyRL.Allow(remoteAddr) {
				_, _ = nc.Write([]byte("<not-acceptable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"))
				return fmt.Errorf("s2s inbound: rate limit exceeded for %s", remoteAddr)
			}
			verifyID := attrVal(start, "id")
			verifyFrom := attrVal(start, "from")
			verifyTo := attrVal(start, "to")
			verifyKey := extractTextBody(raw)

			valid := p.handleDBVerify(verifyID, verifyTo, verifyFrom, verifyKey)
			typ := "invalid"
			if valid {
				typ = "valid"
			}
			reply := fmt.Sprintf(
				"<db:verify xmlns:db='%s' from='%s' to='%s' id='%s' type='%s'/>",
				nsDialback, verifyTo, verifyFrom, verifyID, typ,
			)
			_, _ = nc.Write([]byte(reply))
			return nil
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

			var valid bool
			if p.verifyMode == VerifyBackChannel {
				if err := p.verifyDialback(ctx, remoteDomain, streamID, key); err != nil {
					valid = false
				} else {
					valid = true
				}
			} else {
				valid = p.handleDBVerify(streamID, remoteDomain, p.domain, key)
			}

			if !valid {
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

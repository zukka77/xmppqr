package s2s

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"

	xtls "github.com/danielinux/xmppqr/internal/tls"
	xmldec "github.com/danielinux/xmppqr/internal/xml"
)

const nsSASL = "urn:ietf:params:xml:ns:xmpp-sasl"

const (
	nsDialback = "jabber:server:dialback"
	nsTLS      = "urn:ietf:params:xml:ns:xmpp-tls"
	nsDB       = "jabber:server:dialback"
)

func (p *Pool) connectOutbound(ctx context.Context, remoteDomain string) (*Conn, error) {
	p.mu.RLock()
	pinned, hasPinned := p.pinTargets[remoteDomain]
	p.mu.RUnlock()

	var addr string
	if hasPinned {
		addr = pinned
	} else {
		var err error
		addr, err = resolveS2S(ctx, remoteDomain)
		if err != nil {
			return nil, err
		}
	}

	nc, err := p.dialPlain(ctx, remoteDomain, addr)
	if err != nil {
		return nil, err
	}

	conn, err := p.negotiateOutbound(ctx, nc, remoteDomain)
	if err != nil {
		nc.Close()
		return nil, err
	}

	p.mu.Lock()
	p.conns[remoteDomain] = conn
	p.mu.Unlock()

	go conn.ReadLoop(ctx, func(raw []byte) error {
		return p.inbound.RouteInbound(ctx, raw)
	})

	return conn, nil
}

func resolveS2S(ctx context.Context, domain string) (string, error) {
	_, addrs, err := net.DefaultResolver.LookupSRV(ctx, "xmpp-server", "tcp", domain)
	if err == nil && len(addrs) > 0 {
		a := addrs[0]
		host := a.Target
		if len(host) > 0 && host[len(host)-1] == '.' {
			host = host[:len(host)-1]
		}
		return fmt.Sprintf("%s:%d", host, a.Port), nil
	}
	return fmt.Sprintf("%s:5269", domain), nil
}

func (p *Pool) dialPlain(ctx context.Context, host, addr string) (net.Conn, error) {
	if p.dialer != nil {
		return p.dialer.Dial(ctx, host, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

func (p *Pool) negotiateOutbound(ctx context.Context, nc net.Conn, remoteDomain string) (*Conn, error) {
	streamID, nc, postTLSFeatures, err := p.openS2SStream(ctx, nc, remoteDomain)
	if err != nil {
		return nil, err
	}

	if p.mtlsEnabled && postTLSFeatures != nil && featuresHasExternal(postTLSFeatures) {
		return p.negotiateExternal(ctx, nc, remoteDomain, streamID, postTLSFeatures)
	}

	p.mu.Lock()
	p.streamIDs[remoteDomain] = streamID
	p.mu.Unlock()

	key := DialbackKey(p.secret, remoteDomain, p.domain, streamID)

	dbResult := fmt.Sprintf(
		"<db:result xmlns:db='%s' from='%s' to='%s'>%s</db:result>",
		nsDialback, p.domain, remoteDomain, key,
	)
	if _, err := nc.Write([]byte(dbResult)); err != nil {
		return nil, fmt.Errorf("s2s outbound: send db:result: %w", err)
	}

	if err := waitDBResultValid(ctx, nc, remoteDomain); err != nil {
		return nil, err
	}

	return newConn(remoteDomain, nc, streamID), nil
}

func (p *Pool) negotiateExternal(ctx context.Context, nc net.Conn, remoteDomain, streamID string, _ *parsedFeatures) (*Conn, error) {
	authMsg := fmt.Sprintf(
		"<auth xmlns='%s' mechanism='EXTERNAL'>%s</auth>",
		nsSASL, base64.StdEncoding.EncodeToString([]byte("=")),
	)
	if _, err := nc.Write([]byte(authMsg)); err != nil {
		return nil, fmt.Errorf("s2s external: send auth: %w", err)
	}

	dec := xmldec.NewDecoder(nc)
	start, _, err := dec.NextElement()
	if err != nil {
		return nil, fmt.Errorf("s2s external: read response: %w", err)
	}
	if start.Name.Local == "failure" {
		return nil, fmt.Errorf("s2s external: auth failed")
	}
	if start.Name.Local != "success" {
		return nil, fmt.Errorf("s2s external: unexpected element %s", start.Name.Local)
	}

	if err := sendStreamOpen(nc, p.domain, remoteDomain); err != nil {
		return nil, err
	}

	dec2 := xmldec.NewDecoder(nc)
	hdr, err := dec2.OpenStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("s2s external: post-auth stream open: %w", err)
	}
	if hdr.ID != "" {
		streamID = hdr.ID
	}

	if err := readFeatures(dec2); err != nil {
		return nil, err
	}

	return newConn(remoteDomain, nc, streamID), nil
}

type parsedFeatures struct {
	hasExternal bool
	hasDialback bool
	raw         []byte
}

func featuresHasExternal(f *parsedFeatures) bool {
	return f != nil && f.hasExternal
}

func (p *Pool) openS2SStream(ctx context.Context, nc net.Conn, remoteDomain string) (string, net.Conn, *parsedFeatures, error) {
	if err := sendStreamOpen(nc, p.domain, remoteDomain); err != nil {
		return "", nil, nil, err
	}

	dec := xmldec.NewDecoder(nc)

	hdr, err := dec.OpenStream(ctx)
	if err != nil {
		return "", nil, nil, fmt.Errorf("s2s outbound: peer stream open: %w", err)
	}
	streamID := hdr.ID

	if err := readFeatures(dec); err != nil {
		return "", nil, nil, err
	}

	if p.skipTLS {
		return streamID, nc, nil, nil
	}

	if _, err := nc.Write([]byte("<starttls xmlns='" + nsTLS + "'/>")); err != nil {
		return "", nil, nil, fmt.Errorf("s2s outbound: send starttls: %w", err)
	}

	if err := waitProceed(dec); err != nil {
		return "", nil, nil, err
	}

	tcpConn, ok := nc.(*net.TCPConn)
	if !ok {
		return "", nil, nil, fmt.Errorf("s2s outbound: need *net.TCPConn for TLS, got %T", nc)
	}

	tlsConn, err := xtls.ClientHandshake(p.tlsClient, tcpConn, remoteDomain)
	if err != nil {
		return "", nil, nil, fmt.Errorf("s2s outbound: TLS handshake: %w", err)
	}

	if err := sendStreamOpen(tlsConn, p.domain, remoteDomain); err != nil {
		return "", nil, nil, err
	}

	dec2 := xmldec.NewDecoder(tlsConn)
	hdr2, err := dec2.OpenStream(ctx)
	if err != nil {
		return "", nil, nil, fmt.Errorf("s2s outbound: post-TLS stream open: %w", err)
	}

	feats, err := readFeaturesDetailed(dec2)
	if err != nil {
		return "", nil, nil, err
	}

	return hdr2.ID, tlsConn, feats, nil
}

func sendStreamOpen(w io.Writer, from, to string) error {
	hdr := fmt.Sprintf(
		"<?xml version='1.0'?><stream:stream xmlns='jabber:server' "+
			"xmlns:stream='http://etherx.jabber.org/streams' "+
			"xmlns:db='%s' from='%s' to='%s' version='1.0'>",
		nsDialback, from, to,
	)
	_, err := w.Write([]byte(hdr))
	return err
}

func readFeatures(dec *xmldec.Decoder) error {
	start, _, err := dec.NextElement()
	if err != nil {
		return fmt.Errorf("s2s: read features: %w", err)
	}
	if start.Name.Local != "features" {
		return fmt.Errorf("s2s: expected stream:features, got %s", start.Name.Local)
	}
	return nil
}

func readFeaturesDetailed(dec *xmldec.Decoder) (*parsedFeatures, error) {
	start, raw, err := dec.NextElement()
	if err != nil {
		return nil, fmt.Errorf("s2s: read features: %w", err)
	}
	if start.Name.Local != "features" {
		return nil, fmt.Errorf("s2s: expected stream:features, got %s", start.Name.Local)
	}
	f := &parsedFeatures{raw: raw}
	f.hasExternal = containsMechanism(raw, "EXTERNAL")
	f.hasDialback = bytes.Contains(raw, []byte("dialback"))
	return f, nil
}

func containsMechanism(raw []byte, mech string) bool {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	inMechanisms := false
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "mechanisms" {
				inMechanisms = true
			}
		case xml.EndElement:
			if t.Name.Local == "mechanisms" {
				inMechanisms = false
			}
		case xml.CharData:
			if inMechanisms && string(bytes.TrimSpace(t)) == mech {
				return true
			}
		}
	}
}

func waitProceed(dec *xmldec.Decoder) error {
	start, _, err := dec.NextElement()
	if err != nil {
		return fmt.Errorf("s2s: wait proceed: %w", err)
	}
	if start.Name.Local == "failure" {
		return errors.New("s2s: TLS not available on remote")
	}
	if start.Name.Local != "proceed" {
		return fmt.Errorf("s2s: expected proceed, got %s", start.Name.Local)
	}
	return nil
}

func waitDBResultValid(ctx context.Context, nc net.Conn, remoteDomain string) error {
	dec := xmldec.NewDecoder(nc)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		start, _, err := dec.NextElement()
		if err != nil {
			return fmt.Errorf("s2s outbound: wait db:result: %w", err)
		}
		if start.Name.Local == "result" && start.Name.Space == nsDB {
			typ := attrVal(start, "type")
			if typ == "valid" {
				return nil
			}
			return fmt.Errorf("s2s outbound: dialback invalid (type=%q)", typ)
		}
	}
}

func attrVal(start xml.StartElement, name string) string {
	for _, a := range start.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

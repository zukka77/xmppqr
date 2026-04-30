package c2s

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	xmldec "github.com/danielinux/xmppqr/internal/xml"
	xtls "github.com/danielinux/xmppqr/internal/tls"
)

const nsXMPPTLS = "urn:ietf:params:xml:ns:xmpp-tls"

// RunSTARTTLS drives the plaintext pre-TLS XMPP stream on tcp, performs the
// STARTTLS upgrade per RFC 6120 §5, then runs a normal c2s session on the
// resulting TLS connection.
//
// The flow:
//   1. Read client's <stream:stream> open
//   2. Send our stream header + <starttls/> required feature
//   3. Read client's <starttls/>
//   4. Send <proceed/>
//   5. wolfSSL handshake on the same TCP socket
//   6. Hand off to NewSession + Run
func RunSTARTTLS(ctx context.Context, tcp *net.TCPConn, tlsCtx *xtls.Context, cfg SessionConfig) error {
	defer tcp.Close()

	dec := xmldec.NewDecoder(tcp)
	enc := xmldec.NewEncoder(tcp)

	hdr, err := dec.OpenStream(ctx)
	if err != nil {
		return fmt.Errorf("starttls: pre-TLS stream open: %w", err)
	}

	if hdr.To != "" && hdr.To != cfg.Domain {
		_ = enc.OpenStream(xmldec.StreamHeader{From: cfg.Domain, Version: "1.0"})
		_, _ = enc.WriteRaw(streamError("host-unknown"))
		return fmt.Errorf("starttls: host-unknown: %q", hdr.To)
	}

	streamID := newStreamID()
	if err := enc.OpenStream(xmldec.StreamHeader{From: cfg.Domain, ID: streamID, Version: "1.0"}); err != nil {
		return fmt.Errorf("starttls: write stream header: %w", err)
	}

	preFeatures := []byte(`<stream:features><starttls xmlns='` + nsXMPPTLS + `'><required/></starttls></stream:features>`)
	if _, err := enc.WriteRaw(preFeatures); err != nil {
		return fmt.Errorf("starttls: write features: %w", err)
	}

	for {
		start, _, err := dec.NextElement()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("starttls: read element: %w", err)
		}
		if start.Name.Local == "starttls" && start.Name.Space == nsXMPPTLS {
			break
		}
		if cfg.Logger != nil {
			cfg.Logger.Warn("starttls: pre-TLS unexpected element", "local", start.Name.Local, "ns", start.Name.Space)
		}
	}

	if _, err := enc.WriteRaw([]byte(`<proceed xmlns='` + nsXMPPTLS + `'/>`)); err != nil {
		return fmt.Errorf("starttls: write proceed: %w", err)
	}

	tlsConn, err := xtls.ServerHandshake(tlsCtx, tcp)
	if err != nil {
		return fmt.Errorf("starttls: tls handshake: %w", err)
	}

	sess := newSession(tlsConn, cfg)
	return sess.Run(ctx)
}

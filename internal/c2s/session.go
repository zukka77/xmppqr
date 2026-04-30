// Package c2s implements the XMPP client-to-server session lifecycle.
package c2s

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"log/slog"
	"net"
	"sync/atomic"

	xmldec "github.com/danielinux/xmppqr/internal/xml"
	"github.com/danielinux/xmppqr/internal/csi"
	"github.com/danielinux/xmppqr/internal/push"
	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/sm"
	"github.com/danielinux/xmppqr/internal/stanza"
	xtls "github.com/danielinux/xmppqr/internal/tls"
)

// TLSConn must appear here for the interface definition; config.go references it by name.
// Redeclaring in config.go would cause a duplicate — define once here and use everywhere.

type tlsConnIface interface {
	net.Conn
	Exporter(label string, ctx []byte, n int) ([]byte, error)
	HandshakeState() xtls.HandshakeState
}

type Session struct {
	conn    tlsConnIface
	dec     *xmldec.Decoder
	enc     *xmldec.Encoder
	cfg     SessionConfig
	log     *slog.Logger

	jid      stanza.JID
	priority int32
	avail    int32 // 1 = available

	outbound chan []byte
	smQueue  *sm.OutQueue
	smInH    uint32 // atomic: SM inbound stanza counter (per-session, per XEP-0198)
	csiF     *csi.Filter

	// shutdown signal
	done chan struct{}
}

func newSession(conn tlsConnIface, cfg SessionConfig) *Session {
	dec := xmldec.NewDecoder(conn)
	if cfg.MaxStanzaBytes > 0 {
		dec.SetMaxBytes(cfg.MaxStanzaBytes)
	}
	enc := xmldec.NewEncoder(conn)
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Session{
		conn:     conn,
		dec:      dec,
		enc:      enc,
		cfg:      cfg,
		log:      log,
		outbound: make(chan []byte, 256),
		csiF:     csi.New(),
		done:     make(chan struct{}),
	}
}

func (s *Session) JID() stanza.JID { return s.jid }

func (s *Session) Priority() int { return int(atomic.LoadInt32(&s.priority)) }

func (s *Session) IsAvailable() bool { return atomic.LoadInt32(&s.avail) == 1 }

func (s *Session) Deliver(ctx context.Context, raw []byte) error {
	info := stanzaInfo(raw)
	deliver, hold := s.csiF.ShouldDeliver(info)
	if hold {
		from := ""
		if info.Kind == csi.KindPresence {
			from = info.FromJID
		}
		s.csiF.HoldPresence(from, raw)
		return nil
	}
	if !deliver {
		return nil
	}

	mods := s.cfg.Modules
	if mods != nil && info.Kind == csi.KindMessage {
		ownerBare := s.jid.Bare().String()

		if mods.MAM != nil {
			start, parseRaw, parseErr := parseMessageStart(raw)
			if parseErr == nil {
				if msg, merr := stanza.ParseMessage(start, parseRaw); merr == nil {
					_ = mods.MAM.Archive(ctx, ownerBare, msg, 0, raw)
				}
			}
		}

		if mods.Carbons != nil && s.cfg.Router != nil {
			allRes := s.cfg.Router.SessionsFor(ownerBare)
			jids := make([]stanza.JID, 0, len(allRes))
			for _, sess := range allRes {
				if !sess.JID().Equal(s.jid) {
					jids = append(jids, sess.JID())
				}
			}
			if len(jids) > 0 {
				_ = mods.Carbons.DeliverCarbons(ctx, s.jid.Bare(), s.jid, raw, 0, jids)
			}
		}

		if mods.Push != nil {
			shouldPush := !s.csiF.IsActive()
			if !shouldPush {
				// queue full / backpressure: len(outbound) at capacity
				shouldPush = len(s.outbound) >= cap(s.outbound)
			}
			if !shouldPush && s.cfg.Router != nil {
				sessions := s.cfg.Router.SessionsFor(ownerBare)
				hasAvailable := false
				for _, sess := range sessions {
					if sess.IsAvailable() {
						hasAvailable = true
						break
					}
				}
				shouldPush = !hasAvailable
			}
			if shouldPush {
				fromJID := extractAttr(raw, "from")
				body := extractBody(raw)
				mods.Push.Notify(ctx, s.jid.Bare(), push.Payload{
					MessageCount: 1,
					LastFromJID:  fromJID,
					LastBody:     body,
				})
			}
		}
	}

	select {
	case s.outbound <- raw:
		return nil
	default:
		return router.ErrBackpressure
	}
}

func (s *Session) Run(ctx context.Context) error {
	defer close(s.done)
	defer s.conn.Close()
	return runStream(ctx, s)
}

func parseMessageStart(raw []byte) (xml.StartElement, []byte, error) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return xml.StartElement{}, nil, err
	}
	se, ok := tok.(xml.StartElement)
	if !ok {
		return xml.StartElement{}, nil, errors.New("not a start element")
	}
	return se, raw, nil
}

func extractAttr(raw []byte, attr string) string {
	needle := []byte(attr + "=")
	idx := bytes.Index(raw, needle)
	if idx < 0 {
		return ""
	}
	rest := raw[idx+len(needle):]
	if len(rest) == 0 {
		return ""
	}
	q := rest[0]
	end := bytes.IndexByte(rest[1:], q)
	if end < 0 {
		return ""
	}
	return string(rest[1 : end+1])
}

func extractBody(raw []byte) string {
	open := []byte("<body>")
	close := []byte("</body>")
	start := bytes.Index(raw, open)
	if start < 0 {
		return ""
	}
	content := raw[start+len(open):]
	end := bytes.Index(content, close)
	if end < 0 {
		return ""
	}
	return string(content[:end])
}

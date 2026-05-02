// Package mam implements XEP-0313 Message Archive Management v2.
package mam

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"log/slog"
	"strconv"
	"time"

	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage"
)

type Service struct {
	store  storage.MAMStore
	logger *slog.Logger
}

func New(store storage.MAMStore, logger *slog.Logger) *Service {
	return &Service{store: store, logger: logger}
}

func (s *Service) Archive(ctx context.Context, owner string, msg *stanza.Message, direction int, raw []byte) error {
	sid := msg.ID
	if sid == "" {
		sid = newID()
	}

	rawWith := msg.From
	if direction == 1 {
		rawWith = msg.To
	}
	// Store bare JID so filter comparisons are resource-independent.
	withJID := rawWith
	if j, err := stanza.Parse(rawWith); err == nil {
		withJID = j.Bare().String()
	}

	a := &storage.ArchivedStanza{
		Owner:     owner,
		With:      withJID,
		TS:        time.Now().UTC(),
		StanzaID:  sid,
		OriginID:  msg.ID,
		Direction: direction,
		StanzaXML: raw,
	}
	_, err := s.store.Append(ctx, a)
	return err
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ArchiveMUC stores a groupchat message under a room scope.
// senderBare is the real bare JID of the sender (not the room/nick form).
// raw should be the post-rewrite (from='room/nick') stanza bytes that
// were broadcast to occupants — this is what gets replayed to MAM clients.
// Returns the stanzaID (base36-encoded nanosecond timestamp) assigned to
// the entry; the same value is stored in MUCArchivedStanza.StanzaID.
func (s *Service) ArchiveMUC(ctx context.Context, roomJID stanza.JID, senderBare stanza.JID, raw []byte) (string, error) {
	originID := extractOriginID(raw)
	ts := time.Now().UTC()

	// Use UnixNano encoded as base36 as a monotonic StanzaID so that RSM
	// cursors are human-comparable and the value is stored alongside the row.
	stanzaID := strconv.FormatInt(ts.UnixNano(), 36)

	m := &storage.MUCArchivedStanza{
		RoomJID:       roomJID.Bare().String(),
		SenderBareJID: senderBare.Bare().String(),
		TS:            ts,
		StanzaID:      stanzaID,
		OriginID:      originID,
		StanzaXML:     raw,
	}
	if _, err := s.store.AppendMUC(ctx, m); err != nil {
		return "", err
	}
	return stanzaID, nil
}

// extractOriginID scans raw XML bytes for an
// <origin-id xmlns='urn:xmpp:sid:0' id='...'/>  element and returns
// the id attribute value, or "" if not present.
func extractOriginID(raw []byte) string {
	const nsOriginID = "urn:xmpp:sid:0"
	dec := xml.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Local == "origin-id" && se.Name.Space == nsOriginID {
			for _, a := range se.Attr {
				if a.Name.Local == "id" {
					return a.Value
				}
			}
		}
	}
	return ""
}

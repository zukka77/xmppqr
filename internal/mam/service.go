// Package mam implements XEP-0313 Message Archive Management v2.
package mam

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
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

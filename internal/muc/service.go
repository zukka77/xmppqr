// Package muc implements Multi-User Chat per XEP-0045 + Self-Ping XEP-0410.
package muc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage"
)

type Service struct {
	domain    string
	subdomain string
	store     storage.MUCStore
	router    *router.Router
	logger    *slog.Logger
	rooms     sync.Map
}

func New(serverDomain, mucSubdomain string, store storage.MUCStore, r *router.Router, l *slog.Logger) *Service {
	return &Service{
		domain:    serverDomain,
		subdomain: fmt.Sprintf("%s.%s", mucSubdomain, serverDomain),
		store:     store,
		router:    r,
		logger:    l,
	}
}

func (s *Service) IsOurDomain(j stanza.JID) bool {
	return j.Domain == s.subdomain
}

func (s *Service) Domain() string {
	return s.subdomain
}

func (s *Service) LoadPersistent(ctx context.Context) error {
	if s.store == nil {
		return nil
	}
	rooms, err := s.store.ListRooms(ctx)
	if err != nil {
		return err
	}
	for _, sr := range rooms {
		if !sr.Persistent {
			continue
		}
		room, err := roomFromStorage(sr)
		if err != nil {
			s.logger.Warn("muc: skip malformed room", "jid", sr.JID, "err", err)
			continue
		}
		s.rooms.Store(room.jid.Bare().String(), room)
	}
	return nil
}

func (s *Service) getOrCreateRoom(ctx context.Context, roomJID stanza.JID, firstOwnerJID stanza.JID) *Room {
	key := roomJID.Bare().String()
	if v, ok := s.rooms.Load(key); ok {
		return v.(*Room)
	}

	cfg := RoomConfig{
		AnonymityMode: AnonymitySemi,
		HistoryMax:    20,
		Public:        true,
	}
	room := newRoom(roomJID.Bare(), cfg, false)

	ownerBare := firstOwnerJID.Bare().String()
	room.affiliations[ownerBare] = AffOwner

	actual, loaded := s.rooms.LoadOrStore(key, room)
	if loaded {
		return actual.(*Room)
	}
	return room
}

func (s *Service) getRoom(roomJID stanza.JID) *Room {
	key := roomJID.Bare().String()
	if v, ok := s.rooms.Load(key); ok {
		return v.(*Room)
	}
	return nil
}

func (s *Service) persistRoom(ctx context.Context, room *Room) error {
	room.mu.RLock()
	cfg := room.config
	persistent := room.persistent
	jid := room.jid
	room.mu.RUnlock()

	if !persistent || s.store == nil {
		return nil
	}
	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return s.store.PutRoom(ctx, &storage.MUCRoom{
		JID:        jid.String(),
		Config:     cfgBytes,
		Persistent: persistent,
	})
}

// Package muc implements Multi-User Chat per XEP-0045 + Self-Ping XEP-0410.
package muc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/danielinux/xmppqr/internal/mam"
	"github.com/danielinux/xmppqr/internal/pubsub"
	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage"
)

type Service struct {
	domain      string
	subdomain   string
	store       storage.MUCStore
	mam         *mam.Service
	router      *router.Router
	logger      *slog.Logger
	rooms       sync.Map
	pubsubHost  *pubsub.HostService
}

// New constructs a MUC Service.  mamSvc may be nil; when non-nil, groupchat
// messages are archived via MAM and MAM query IQs addressed to room JIDs are
// answered.  psSvc may be nil; when non-nil, pubsub IQs targeted at room JIDs
// are dispatched to a per-room pubsub host with MUC-affiliation-based auth.
func New(serverDomain, mucSubdomain string, store storage.MUCStore, mamSvc *mam.Service, psSvc *pubsub.Service, r *router.Router, l *slog.Logger) *Service {
	svc := &Service{
		domain:    serverDomain,
		subdomain: fmt.Sprintf("%s.%s", mucSubdomain, serverDomain),
		store:     store,
		mam:       mamSvc,
		router:    r,
		logger:    l,
	}
	if psSvc != nil {
		svc.pubsubHost = newPubsubHostService(psSvc, svc)
		// Register the global hook so Room.applyAffiliationLocked can drop
		// subscriptions without importing the pubsub package directly.
		dropPubsubSubscriptions = func(ctx context.Context, roomJID stanza.JID, subscriberBare string) {
			_ = svc.pubsubHost.DropSubscriptionsForUser(ctx, roomJID, subscriberBare)
		}
	}
	return svc
}

// CanQueryMAM returns true when requesterBare is allowed to retrieve MAM
// history for the given room.  Policy:
//   - affiliation >= AffMember always grants access.
//   - open (not members-only) AND public rooms are accessible to everyone.
func (s *Service) CanQueryMAM(roomJID stanza.JID, requesterBare string) bool {
	room := s.getRoom(roomJID)
	if room == nil {
		return false
	}
	room.mu.RLock()
	defer room.mu.RUnlock()

	aff := room.affiliations[requesterBare]
	if aff >= AffMember {
		return true
	}
	return !room.config.MembersOnly && room.config.Public
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
		room, err := roomFromStorage(sr, s.store, s.mam)
		if err != nil {
			s.logger.Warn("muc: skip malformed room", "jid", sr.JID, "err", err)
			continue
		}

		// Restore affiliations (including outcasts so bans survive restart).
		affs, aerr := s.store.ListAffiliations(ctx, room.jid.String())
		if aerr == nil {
			for _, a := range affs {
				room.affiliations[a.UserJID] = a.Affiliation
			}
		}

		// Restore subject; treat zero-value subject as "not set".
		subj, byNick, ts, serr := s.store.GetRoomSubject(ctx, room.jid.String())
		if serr == nil && subj != "" {
			room.subject = subj
			room.subjectChangedBy = byNick
			room.subjectTS = ts
		}

		s.rooms.Store(room.jid.Bare().String(), room)
	}
	return nil
}

func (s *Service) getOrCreateRoom(ctx context.Context, roomJID stanza.JID, firstOwnerJID stanza.JID) (*Room, bool) {
	key := roomJID.Bare().String()
	if v, ok := s.rooms.Load(key); ok {
		return v.(*Room), false
	}

	cfg := RoomConfig{
		AnonymityMode: AnonymitySemi,
		HistoryMax:    20,
		Public:        true,
	}
	room := newRoom(roomJID.Bare(), cfg, false, s.store, s.mam)

	ownerBare := firstOwnerJID.Bare().String()
	room.affiliations[ownerBare] = AffOwner

	actual, loaded := s.rooms.LoadOrStore(key, room)
	if loaded {
		return actual.(*Room), false
	}
	return room, true
}

func (s *Service) getRoom(roomJID stanza.JID) *Room {
	key := roomJID.Bare().String()
	if v, ok := s.rooms.Load(key); ok {
		return v.(*Room)
	}
	return nil
}

func (s *Service) listPublicRooms() []*Room {
	var out []*Room
	s.rooms.Range(func(_, v interface{}) bool {
		room := v.(*Room)
		room.mu.RLock()
		public := room.config.Public
		room.mu.RUnlock()
		if public {
			out = append(out, room)
		}
		return true
	})
	return out
}

// destroyRoom is the muc#owner <destroy/> handler. It broadcasts the tombstone
// presence to all occupants via Room.Destroy, then removes the room from the
// Service map and from storage so it does not survive a restart.
func (s *Service) destroyRoom(ctx context.Context, room *Room, altJID, reason string) error {
	room.Destroy(ctx, altJID, reason, s.router)
	s.rooms.Delete(room.JID().Bare().String())
	if s.store != nil {
		if err := s.store.DeleteRoom(ctx, room.JID().Bare().String()); err != nil {
			if s.logger != nil {
				s.logger.Warn("muc: DeleteRoom failed", "jid", room.JID().String(), "err", err)
			}
			// Best-effort: do not fail the IQ because the room is already
			// gone from the in-memory map and occupants have been evicted.
		}
	}
	// Delete all pubsub nodes owned by this room (e.g. urn:xmppqr:x3dhpq:group:0)
	// so they do not persist in storage after room destruction.
	if s.pubsubHost != nil {
		if err := s.pubsubHost.DeleteAllNodesForOwner(ctx, room.JID()); err != nil {
			if s.logger != nil {
				s.logger.Warn("muc: DeleteAllNodesForOwner failed", "jid", room.JID().String(), "err", err)
			}
		}
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

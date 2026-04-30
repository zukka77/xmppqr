package memstore

import (
	"context"
	"sync"

	"github.com/danielinux/xmppqr/internal/storage"
)

type mucAffKey struct{ roomJID, userJID string }

type mucStore struct {
	mu           sync.RWMutex
	rooms        map[string]*storage.MUCRoom
	affiliations map[mucAffKey]*storage.MUCAffiliation
}

func newMUCStore() *mucStore {
	return &mucStore{
		rooms:        make(map[string]*storage.MUCRoom),
		affiliations: make(map[mucAffKey]*storage.MUCAffiliation),
	}
}

func (s *mucStore) PutRoom(_ context.Context, room *storage.MUCRoom) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *room
	s.rooms[room.JID] = &cp
	return nil
}

func (s *mucStore) GetRoom(_ context.Context, jid storage.JID) (*storage.MUCRoom, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.rooms[jid]
	if !ok {
		return nil, errNotFound
	}
	cp := *r
	return &cp, nil
}

func (s *mucStore) DeleteRoom(_ context.Context, jid storage.JID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rooms, jid)
	for k := range s.affiliations {
		if k.roomJID == jid {
			delete(s.affiliations, k)
		}
	}
	return nil
}

func (s *mucStore) PutAffiliation(_ context.Context, a *storage.MUCAffiliation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *a
	s.affiliations[mucAffKey{a.RoomJID, a.UserJID}] = &cp
	return nil
}

func (s *mucStore) ListAffiliations(_ context.Context, roomJID storage.JID) ([]*storage.MUCAffiliation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*storage.MUCAffiliation
	for k, v := range s.affiliations {
		if k.roomJID == roomJID {
			cp := *v
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *mucStore) ListRooms(_ context.Context) ([]*storage.MUCRoom, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*storage.MUCRoom, 0, len(s.rooms))
	for _, r := range s.rooms {
		cp := *r
		out = append(out, &cp)
	}
	return out, nil
}

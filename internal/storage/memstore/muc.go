package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/danielinux/xmppqr/internal/storage"
)

type mucAffKey struct{ roomJID, userJID string }

type mucSubject struct {
	subject string
	byNick  string
	ts      time.Time
}

type mucStore struct {
	mu           sync.RWMutex
	rooms        map[string]*storage.MUCRoom
	affiliations map[mucAffKey]*storage.MUCAffiliation
	subjects     map[string]*mucSubject
	historySeq   int64
	history      []*storage.MUCHistory
}

func newMUCStore() *mucStore {
	return &mucStore{
		rooms:        make(map[string]*storage.MUCRoom),
		affiliations: make(map[mucAffKey]*storage.MUCAffiliation),
		subjects:     make(map[string]*mucSubject),
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

func (s *mucStore) PutRoomSubject(_ context.Context, roomJID storage.JID, subject, byNick string, ts time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subjects[roomJID] = &mucSubject{subject: subject, byNick: byNick, ts: ts}
	return nil
}

func (s *mucStore) GetRoomSubject(_ context.Context, roomJID storage.JID) (subject, byNick string, ts time.Time, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sub, ok := s.subjects[roomJID]
	if !ok {
		return "", "", time.Time{}, nil
	}
	return sub.subject, sub.byNick, sub.ts, nil
}

func (s *mucStore) AppendHistory(_ context.Context, h *storage.MUCHistory) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.historySeq++
	cp := *h
	cp.ID = s.historySeq
	s.history = append(s.history, &cp)
	return cp.ID, nil
}

func (s *mucStore) QueryHistory(_ context.Context, roomJID storage.JID, before, after *time.Time, limit int) ([]*storage.MUCHistory, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*storage.MUCHistory
	for _, h := range s.history {
		if h.RoomJID != roomJID {
			continue
		}
		if after != nil && !h.TS.After(*after) {
			continue
		}
		if before != nil && !h.TS.Before(*before) {
			continue
		}
		cp := *h
		out = append(out, &cp)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *mucStore) DeleteHistoryBefore(_ context.Context, roomJID storage.JID, ts time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.history[:0]
	removed := 0
	for _, h := range s.history {
		if h.RoomJID == roomJID && h.TS.Before(ts) {
			removed++
		} else {
			kept = append(kept, h)
		}
	}
	s.history = kept
	return removed, nil
}

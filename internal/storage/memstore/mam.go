package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/danielinux/xmppqr/internal/storage"
)

type mamStore struct {
	mu         sync.RWMutex
	seq        int64
	messages   []*storage.ArchivedStanza
	mucSeq     int64
	mucArchive []*storage.MUCArchivedStanza
}

func newMAMStore() *mamStore {
	return &mamStore{}
}

func (s *mamStore) Append(_ context.Context, msg *storage.ArchivedStanza) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	cp := *msg
	cp.ID = s.seq
	s.messages = append(s.messages, &cp)
	return cp.ID, nil
}

func (s *mamStore) Query(_ context.Context, owner string, with *storage.JID, before, after *time.Time, limit int) ([]*storage.ArchivedStanza, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*storage.ArchivedStanza
	for _, m := range s.messages {
		if m.Owner != owner {
			continue
		}
		if with != nil && m.With != *with {
			continue
		}
		if after != nil && !m.TS.After(*after) {
			continue
		}
		if before != nil && !m.TS.Before(*before) {
			continue
		}
		cp := *m
		out = append(out, &cp)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *mamStore) Prune(_ context.Context, owner string, olderThan time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.messages[:0]
	removed := 0
	for _, m := range s.messages {
		if m.Owner == owner && m.TS.Before(olderThan) {
			removed++
		} else {
			kept = append(kept, m)
		}
	}
	s.messages = kept
	return removed, nil
}

func (s *mamStore) AppendMUC(_ context.Context, m *storage.MUCArchivedStanza) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mucSeq++
	cp := *m
	cp.ID = s.mucSeq
	s.mucArchive = append(s.mucArchive, &cp)
	return cp.ID, nil
}

func (s *mamStore) QueryMUC(_ context.Context, roomJID storage.JID, with *storage.JID, before, after *time.Time, limit int) ([]*storage.MUCArchivedStanza, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*storage.MUCArchivedStanza
	for _, m := range s.mucArchive {
		if m.RoomJID != roomJID {
			continue
		}
		if with != nil && m.SenderBareJID != *with {
			continue
		}
		if after != nil && !m.TS.After(*after) {
			continue
		}
		if before != nil && !m.TS.Before(*before) {
			continue
		}
		cp := *m
		out = append(out, &cp)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *mamStore) PruneMUC(_ context.Context, roomJID storage.JID, olderThan time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.mucArchive[:0]
	removed := 0
	for _, m := range s.mucArchive {
		if m.RoomJID == roomJID && m.TS.Before(olderThan) {
			removed++
		} else {
			kept = append(kept, m)
		}
	}
	s.mucArchive = kept
	return removed, nil
}

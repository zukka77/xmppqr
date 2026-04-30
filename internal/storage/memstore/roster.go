package memstore

import (
	"context"
	"sync"

	"github.com/danielinux/xmppqr/internal/storage"
)

type rosterKey struct{ owner, contact string }

type rosterStore struct {
	mu    sync.RWMutex
	items map[rosterKey]*storage.RosterItem
	vers  map[string]int64
}

func newRosterStore() *rosterStore {
	return &rosterStore{
		items: make(map[rosterKey]*storage.RosterItem),
		vers:  make(map[string]int64),
	}
}

func (s *rosterStore) Get(_ context.Context, owner string) ([]*storage.RosterItem, int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*storage.RosterItem
	for k, v := range s.items {
		if k.owner == owner {
			cp := *v
			out = append(out, &cp)
		}
	}
	return out, s.vers[owner], nil
}

func (s *rosterStore) Put(_ context.Context, item *storage.RosterItem) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vers[item.Owner]++
	ver := s.vers[item.Owner]
	cp := *item
	cp.Ver = ver
	s.items[rosterKey{item.Owner, item.Contact}] = &cp
	return ver, nil
}

func (s *rosterStore) Delete(_ context.Context, owner string, contact storage.JID) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vers[owner]++
	ver := s.vers[owner]
	delete(s.items, rosterKey{owner, contact})
	return ver, nil
}

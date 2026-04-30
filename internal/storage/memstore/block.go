package memstore

import (
	"context"
	"sync"

	"github.com/danielinux/xmppqr/internal/storage"
)

type blockStore struct {
	mu     sync.RWMutex
	blocks map[string]map[storage.JID]struct{}
}

func newBlockStore() *blockStore {
	return &blockStore{blocks: make(map[string]map[storage.JID]struct{})}
}

func (s *blockStore) List(_ context.Context, owner string) ([]storage.JID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	set := s.blocks[owner]
	out := make([]storage.JID, 0, len(set))
	for jid := range set {
		out = append(out, jid)
	}
	return out, nil
}

func (s *blockStore) Add(_ context.Context, owner string, blocked storage.JID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.blocks[owner] == nil {
		s.blocks[owner] = make(map[storage.JID]struct{})
	}
	s.blocks[owner][blocked] = struct{}{}
	return nil
}

func (s *blockStore) Remove(_ context.Context, owner string, blocked storage.JID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.blocks[owner], blocked)
	return nil
}

func (s *blockStore) Clear(_ context.Context, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.blocks, owner)
	return nil
}

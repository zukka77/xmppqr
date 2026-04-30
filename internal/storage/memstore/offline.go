package memstore

import (
	"context"
	"sync"

	"github.com/danielinux/xmppqr/internal/storage"
)

type offlineStore struct {
	mu   sync.Mutex
	seq  int64
	msgs []*storage.OfflineMessage
}

func newOfflineStore() *offlineStore {
	return &offlineStore{}
}

func (s *offlineStore) Push(_ context.Context, msg *storage.OfflineMessage) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	cp := *msg
	cp.ID = s.seq
	s.msgs = append(s.msgs, &cp)
	return cp.ID, nil
}

func (s *offlineStore) Pop(_ context.Context, owner string, limit int) ([]*storage.OfflineMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*storage.OfflineMessage
	var remaining []*storage.OfflineMessage
	for _, m := range s.msgs {
		if m.Owner == owner && (limit <= 0 || len(out) < limit) {
			cp := *m
			out = append(out, &cp)
		} else {
			remaining = append(remaining, m)
		}
	}
	s.msgs = remaining
	return out, nil
}

func (s *offlineStore) Count(_ context.Context, owner string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, m := range s.msgs {
		if m.Owner == owner {
			n++
		}
	}
	return n, nil
}

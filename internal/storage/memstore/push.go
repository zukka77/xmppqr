package memstore

import (
	"context"
	"sync"

	"github.com/danielinux/xmppqr/internal/storage"
)

type pushKey struct{ owner, serviceJID, node string }

type pushStore struct {
	mu   sync.RWMutex
	regs map[pushKey]*storage.PushRegistration
}

func newPushStore() *pushStore {
	return &pushStore{regs: make(map[pushKey]*storage.PushRegistration)}
}

func (s *pushStore) Put(_ context.Context, reg *storage.PushRegistration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *reg
	s.regs[pushKey{reg.Owner, reg.ServiceJID, reg.Node}] = &cp
	return nil
}

func (s *pushStore) List(_ context.Context, owner string) ([]*storage.PushRegistration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*storage.PushRegistration
	for k, v := range s.regs {
		if k.owner == owner {
			cp := *v
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *pushStore) Delete(_ context.Context, owner string, serviceJID storage.JID, node string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.regs, pushKey{owner, serviceJID, node})
	return nil
}

package memstore

import (
	"context"
	"sync"

	"github.com/danielinux/xmppqr/internal/storage"
)

type pepNodeKey struct{ owner, node string }
type pepItemKey struct{ owner, node, itemID string }
type pepSubKey struct{ owner, node, subscriber string }

type pepStore struct {
	mu    sync.RWMutex
	nodes map[pepNodeKey]*storage.PEPNode
	items map[pepItemKey]*storage.PEPItem
	order []pepItemKey
	subs  map[pepSubKey]*storage.PEPSubscription
}

func newPEPStore() *pepStore {
	return &pepStore{
		nodes: make(map[pepNodeKey]*storage.PEPNode),
		items: make(map[pepItemKey]*storage.PEPItem),
		subs:  make(map[pepSubKey]*storage.PEPSubscription),
	}
}

func (s *pepStore) PutNode(_ context.Context, node *storage.PEPNode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *node
	s.nodes[pepNodeKey{node.Owner, node.Node}] = &cp
	return nil
}

func (s *pepStore) GetNode(_ context.Context, owner, node string) (*storage.PEPNode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n, ok := s.nodes[pepNodeKey{owner, node}]
	if !ok {
		return nil, errNotFound
	}
	cp := *n
	return &cp, nil
}

func (s *pepStore) DeleteNode(_ context.Context, owner, node string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.nodes, pepNodeKey{owner, node})
	kept := s.order[:0]
	for _, k := range s.order {
		if k.owner == owner && k.node == node {
			delete(s.items, k)
		} else {
			kept = append(kept, k)
		}
	}
	s.order = kept
	return nil
}

func (s *pepStore) PutItem(_ context.Context, item *storage.PEPItem) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := pepItemKey{item.Owner, item.Node, item.ItemID}
	if _, exists := s.items[k]; !exists {
		s.order = append(s.order, k)
	}
	cp := *item
	s.items[k] = &cp
	return nil
}

func (s *pepStore) GetItem(_ context.Context, owner, node, itemID string) (*storage.PEPItem, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	it, ok := s.items[pepItemKey{owner, node, itemID}]
	if !ok {
		return nil, errNotFound
	}
	cp := *it
	return &cp, nil
}

func (s *pepStore) ListItems(_ context.Context, owner, node string, limit int) ([]*storage.PEPItem, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*storage.PEPItem
	for _, k := range s.order {
		if k.owner == owner && k.node == node {
			cp := *s.items[k]
			out = append(out, &cp)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (s *pepStore) DeleteItem(_ context.Context, owner, node, itemID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := pepItemKey{owner, node, itemID}
	delete(s.items, k)
	kept := s.order[:0]
	for _, ok := range s.order {
		if ok != k {
			kept = append(kept, ok)
		}
	}
	s.order = kept
	return nil
}

func (s *pepStore) PutSubscription(_ context.Context, sub *storage.PEPSubscription) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *sub
	s.subs[pepSubKey{sub.Owner, sub.Node, sub.Subscriber}] = &cp
	return nil
}

func (s *pepStore) DeleteSubscription(_ context.Context, owner, node, subscriber string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.subs, pepSubKey{owner, node, subscriber})
	return nil
}

func (s *pepStore) DeleteSubscriptionsForSubscriber(_ context.Context, owner, subscriber string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.subs {
		if k.owner == owner && k.subscriber == subscriber {
			delete(s.subs, k)
		}
	}
	return nil
}

func (s *pepStore) ListSubscribers(_ context.Context, owner, node string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for k := range s.subs {
		if k.owner == owner && k.node == node {
			out = append(out, k.subscriber)
		}
	}
	return out, nil
}

// DeleteNodesForOwner removes every node, its items, and its subscriptions
// for the given owner.  Used when a MUC room is destroyed.
func (s *pepStore) DeleteNodesForOwner(_ context.Context, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.nodes {
		if k.owner == owner {
			delete(s.nodes, k)
		}
	}
	kept := s.order[:0]
	for _, k := range s.order {
		if k.owner == owner {
			delete(s.items, k)
		} else {
			kept = append(kept, k)
		}
	}
	s.order = kept
	for k := range s.subs {
		if k.owner == owner {
			delete(s.subs, k)
		}
	}
	return nil
}

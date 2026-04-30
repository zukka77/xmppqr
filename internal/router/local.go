package router

import (
	"context"
	"hash/fnv"
	"sync"

	"github.com/danielinux/xmppqr/internal/stanza"
)

type Router struct {
	shards      [256]*shard
	mu          sync.RWMutex
	localDomain string
	remote      RemoteRouter
}

func New() *Router {
	r := &Router{}
	for i := range r.shards {
		r.shards[i] = newShard()
	}
	return r
}

func (r *Router) shardFor(bareKey string) *shard {
	h := fnv.New32a()
	h.Write([]byte(bareKey))
	return r.shards[h.Sum32()%256]
}

func (r *Router) Register(s Session) {
	key := s.JID().Bare().String()
	r.shardFor(key).register(key, s)
}

func (r *Router) Unregister(s Session) {
	key := s.JID().Bare().String()
	r.shardFor(key).unregister(key, s)
}

func (r *Router) RouteToFull(ctx context.Context, full stanza.JID, raw []byte) error {
	r.mu.RLock()
	domain := r.localDomain
	remote := r.remote
	r.mu.RUnlock()

	if domain != "" && full.Domain != domain {
		if remote == nil {
			return ErrNoSession
		}
		return remote.Send(ctx, stanza.JID{}, full.Bare(), raw)
	}

	key := full.Bare().String()
	list := r.shardFor(key).get(key)
	for _, s := range list {
		if s.JID().Equal(full) {
			return s.Deliver(ctx, raw)
		}
	}
	return ErrNoSession
}

// SessionsFor returns a copy of all sessions registered for bareJID.
// The returned slice is safe for the caller to iterate without holding any lock.
func (r *Router) SessionsFor(bareJID string) []Session {
	return r.shardFor(bareJID).get(bareJID)
}

func (r *Router) RouteToBare(ctx context.Context, bare stanza.JID, raw []byte) (int, error) {
	r.mu.RLock()
	domain := r.localDomain
	remote := r.remote
	r.mu.RUnlock()

	if domain != "" && bare.Domain != domain {
		if remote == nil {
			return 0, ErrNoSession
		}
		err := remote.Send(ctx, stanza.JID{}, bare, raw)
		if err != nil {
			return 0, err
		}
		return 1, nil
	}

	key := bare.String()
	list := r.shardFor(key).get(key)

	maxPri := 0
	hasAvailable := false
	for _, s := range list {
		if !s.IsAvailable() {
			continue
		}
		p := s.Priority()
		if !hasAvailable || p > maxPri {
			maxPri = p
			hasAvailable = true
		}
	}
	if !hasAvailable {
		return 0, ErrNoSession
	}

	delivered := 0
	for _, s := range list {
		if s.IsAvailable() && s.Priority() == maxPri {
			if err := s.Deliver(ctx, raw); err == nil {
				delivered++
			}
		}
	}
	if delivered == 0 {
		return 0, ErrNoSession
	}
	return delivered, nil
}

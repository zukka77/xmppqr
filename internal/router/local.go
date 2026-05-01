package router

import (
	"context"
	"hash/fnv"
	"sync"

	"github.com/danielinux/xmppqr/internal/stanza"
)

type ParkedStore interface {
	LookupByJIDStr(fullJID stanza.JID) (string, bool)
	AppendByToken(token string, raw []byte) error
}

type Router struct {
	shards      [256]*shard
	mu          sync.RWMutex
	localDomain string
	remote      RemoteRouter
	parked      ParkedStore
}

func New() *Router {
	r := &Router{}
	for i := range r.shards {
		r.shards[i] = newShard()
	}
	return r
}

func (r *Router) SetParkedStore(p ParkedStore) {
	r.mu.Lock()
	r.parked = p
	r.mu.Unlock()
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
	parked := r.parked
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

	if parked != nil {
		if tok, ok := parked.LookupByJIDStr(full); ok {
			return parked.AppendByToken(tok, raw)
		}
	}

	return ErrNoSession
}

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

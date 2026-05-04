package router

import (
	"bytes"
	"context"
	"encoding/xml"
	"hash/fnv"
	"sync"
	"time"

	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage"
)

type ParkedStore interface {
	LookupByJIDStr(fullJID stanza.JID) (string, bool)
	AppendByToken(token string, raw []byte) error
}

type OfflineStore interface {
	Push(ctx context.Context, msg *storage.OfflineMessage) (int64, error)
}

type Router struct {
	shards      [256]*shard
	mu          sync.RWMutex
	localDomain string
	remote      RemoteRouter
	parked      ParkedStore
	offline     OfflineStore
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

func (r *Router) SetOfflineStore(o OfflineStore) {
	r.mu.Lock()
	r.offline = o
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
	offline := r.offline
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

	totalSessions := len(list)
	availableCount := 0
	maxPri := 0
	hasAvailable := false
	for _, s := range list {
		if !s.IsAvailable() {
			continue
		}
		availableCount++
		p := s.Priority()
		if !hasAvailable || p > maxPri {
			maxPri = p
			hasAvailable = true
		}
	}

	delivered := 0
	if hasAvailable {
		// Standard path: deliver to all available sessions tied for highest
		// priority (RFC 6121 §8.5.3.2.2 SHOULD).
		for _, s := range list {
			if s.IsAvailable() && s.Priority() == maxPri {
				if err := s.Deliver(ctx, raw); err == nil {
					delivered++
				}
			}
		}
	} else if totalSessions > 0 {
		// Fallback: no resource has broadcast `<presence>` (modern clients
		// using bind2/SASL2 sometimes skip the initial directed-presence
		// broadcast and only send MUC-join presences, leaving s.avail=0
		// even though the c2s session is fully bound and reading stanzas).
		// Without this fallback, every chat-typed pairwise message
		// addressed to such a client's bare JID gets dropped here while
		// MUC-routed groupchats reach them just fine — pure asymmetry
		// that surfaces as "Conversations doesn't see dino's pairwise
		// sender-chain announcements". Deliver to every bound session.
		for _, s := range list {
			if err := s.Deliver(ctx, raw); err == nil {
				delivered++
			}
		}
	}

	if delivered == 0 {
		if offline != nil && isMessageStanza(raw) {
			if _, err := offline.Push(ctx, &storage.OfflineMessage{
				Owner:  bare.String(),
				TS:     time.Now().UTC(),
				Stanza: append([]byte(nil), raw...),
			}); err == nil {
				return 1, nil
			}
		}
		return 0, ErrNoSession
	}
	return delivered, nil
}

func isMessageStanza(raw []byte) bool {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	se, ok := tok.(xml.StartElement)
	return ok && se.Name.Local == "message"
}

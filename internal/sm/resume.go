package sm

import (
	"context"
	"encoding/base64"
	"sync"

	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

type ResumeToken string

type entry struct {
	token ResumeToken
	jid   stanza.JID
}

type Store struct {
	mu       sync.Mutex
	capacity int
	order    []ResumeToken
	m        map[ResumeToken]stanza.JID
}

func NewStore(capacity int) *Store {
	return &Store{
		capacity: capacity,
		m:        make(map[ResumeToken]stanza.JID),
	}
}

func (s *Store) Issue(_ context.Context, jid stanza.JID) (ResumeToken, error) {
	var buf [16]byte
	if _, err := wolfcrypt.Read(buf[:]); err != nil {
		return "", err
	}
	tok := ResumeToken(base64.RawURLEncoding.EncodeToString(buf[:]))

	s.mu.Lock()
	defer s.mu.Unlock()

	for len(s.order) >= s.capacity {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.m, oldest)
	}

	s.m[tok] = jid
	s.order = append(s.order, tok)
	return tok, nil
}

func (s *Store) Lookup(t ResumeToken) (stanza.JID, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	jid, ok := s.m[t]
	if !ok {
		return stanza.JID{}, false
	}
	delete(s.m, t)
	for i, v := range s.order {
		if v == t {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	return jid, true
}

func (s *Store) Evict(t ResumeToken) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, t)
	for i, v := range s.order {
		if v == t {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
}

package sm

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

type ResumeToken string

var ErrTokenNotFound = errors.New("sm: resume token not found")

type ResumableState struct {
	JID          stanza.JID
	Pending      [][]byte
	OutQueueTail [][]byte
	LastInH      uint32
	ExpiresAt    time.Time
	ParkNow      func() // called by Take before returning; drains zombie session
}

type Store struct {
	mu       sync.Mutex
	capacity int
	order    []ResumeToken
	m        map[ResumeToken]*ResumableState
	byJID    map[string]ResumeToken
}

func NewStore(capacity int) *Store {
	return &Store{
		capacity: capacity,
		m:        make(map[ResumeToken]*ResumableState),
		byJID:    make(map[string]ResumeToken),
	}
}

func (s *Store) Issue(_ context.Context, jid stanza.JID, ttl time.Duration) (ResumeToken, error) {
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
		if st, ok := s.m[oldest]; ok {
			delete(s.byJID, st.JID.String())
		}
		delete(s.m, oldest)
	}

	s.m[tok] = &ResumableState{JID: jid, ExpiresAt: time.Now().Add(ttl)}
	s.order = append(s.order, tok)
	return tok, nil
}

func (s *Store) Lookup(t ResumeToken) (stanza.JID, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.m[t]
	if !ok {
		return stanza.JID{}, false
	}
	jid := st.JID
	delete(s.byJID, jid.String())
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
	if st, ok := s.m[t]; ok {
		delete(s.byJID, st.JID.String())
	}
	delete(s.m, t)
	for i, v := range s.order {
		if v == t {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
}

func (s *Store) Park(token ResumeToken, state *ResumableState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.m[token]
	if !ok {
		return ErrTokenNotFound
	}
	jidStr := state.JID.String()
	if existing.JID.String() != jidStr {
		delete(s.byJID, existing.JID.String())
	}
	s.m[token] = state
	s.byJID[jidStr] = token
	return nil
}

func (s *Store) Append(token ResumeToken, raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.m[token]
	if !ok {
		return ErrTokenNotFound
	}
	cp := make([]byte, len(raw))
	copy(cp, raw)
	st.Pending = append(st.Pending, cp)
	return nil
}

func (s *Store) Take(token ResumeToken) (*ResumableState, bool) {
	s.mu.Lock()
	st, ok := s.m[token]
	if !ok {
		s.mu.Unlock()
		return nil, false
	}
	if !st.ExpiresAt.IsZero() && time.Now().After(st.ExpiresAt) {
		delete(s.byJID, st.JID.String())
		delete(s.m, token)
		for i, v := range s.order {
			if v == token {
				s.order = append(s.order[:i], s.order[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
		return nil, false
	}

	parkNow := st.ParkNow
	s.mu.Unlock()

	if parkNow != nil {
		parkNow()
	}

	s.mu.Lock()
	st2, ok2 := s.m[token]
	if !ok2 {
		s.mu.Unlock()
		return nil, false
	}
	if !st2.ExpiresAt.IsZero() && time.Now().After(st2.ExpiresAt) {
		delete(s.byJID, st2.JID.String())
		delete(s.m, token)
		for i, v := range s.order {
			if v == token {
				s.order = append(s.order[:i], s.order[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
		return nil, false
	}
	delete(s.byJID, st2.JID.String())
	delete(s.m, token)
	for i, v := range s.order {
		if v == token {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	s.mu.Unlock()
	return st2, true
}

func (s *Store) LookupByJIDStr(fullJID stanza.JID) (string, bool) {
	tok, ok := s.LookupByJID(fullJID)
	return string(tok), ok
}

func (s *Store) SetParkCallback(token ResumeToken, cb func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.m[token]; ok {
		st.ParkNow = cb
	}
}

func (s *Store) AppendByToken(token string, raw []byte) error {
	return s.Append(ResumeToken(token), raw)
}

func (s *Store) LookupByJID(fullJID stanza.JID) (ResumeToken, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok, ok := s.byJID[fullJID.String()]
	if !ok {
		return "", false
	}
	st, exists := s.m[tok]
	if !exists {
		delete(s.byJID, fullJID.String())
		return "", false
	}
	if !st.ExpiresAt.IsZero() && time.Now().After(st.ExpiresAt) {
		delete(s.byJID, fullJID.String())
		delete(s.m, tok)
		for i, v := range s.order {
			if v == tok {
				s.order = append(s.order[:i], s.order[i+1:]...)
				break
			}
		}
		return "", false
	}
	return tok, true
}

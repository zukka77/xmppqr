package memstore

import (
	"context"
	"errors"
	"sync"

	"github.com/danielinux/xmppqr/internal/storage"
)

var errNotFound = errors.New("not found")

type userStore struct {
	mu    sync.RWMutex
	users map[string]*storage.User
}

func newUserStore() *userStore {
	return &userStore{users: make(map[string]*storage.User)}
}

func (s *userStore) Get(_ context.Context, username string) (*storage.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	if !ok {
		return nil, errNotFound
	}
	cp := *u
	return &cp, nil
}

func (s *userStore) Put(_ context.Context, u *storage.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *u
	s.users[u.Username] = &cp
	return nil
}

func (s *userStore) Delete(_ context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, username)
	return nil
}

func (s *userStore) List(_ context.Context, limit, offset int) ([]*storage.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	all := make([]*storage.User, 0, len(s.users))
	for _, u := range s.users {
		cp := *u
		all = append(all, &cp)
	}
	if offset >= len(all) {
		return nil, nil
	}
	all = all[offset:]
	if limit > 0 && limit < len(all) {
		all = all[:limit]
	}
	return all, nil
}

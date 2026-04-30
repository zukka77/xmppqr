package router

import "sync"

type shard struct {
	mu       sync.RWMutex
	sessions map[string][]Session
}

func newShard() *shard {
	return &shard{sessions: make(map[string][]Session)}
}

func (s *shard) register(key string, sess Session) {
	s.mu.Lock()
	s.sessions[key] = append(s.sessions[key], sess)
	s.mu.Unlock()
}

func (s *shard) unregister(key string, sess Session) {
	s.mu.Lock()
	list := s.sessions[key]
	for i, v := range list {
		if v == sess {
			list[i] = list[len(list)-1]
			list[len(list)-1] = nil
			list = list[:len(list)-1]
			break
		}
	}
	if len(list) == 0 {
		delete(s.sessions, key)
	} else {
		s.sessions[key] = list
	}
	s.mu.Unlock()
}

func (s *shard) get(key string) []Session {
	s.mu.RLock()
	list := s.sessions[key]
	if len(list) == 0 {
		s.mu.RUnlock()
		return nil
	}
	cp := make([]Session, len(list))
	copy(cp, list)
	s.mu.RUnlock()
	return cp
}

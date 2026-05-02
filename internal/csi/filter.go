package csi

import "sync"

type StanzaKind int

const (
	KindMessage  StanzaKind = iota
	KindPresence StanzaKind = iota
	KindIQ       StanzaKind = iota
)

type StanzaInfo struct {
	Kind         StanzaKind
	FromJID      string
	HasBody      bool
	HasChatState bool
	IsError      bool
	IsMUCSubject bool
}

type Filter struct {
	mu              sync.Mutex
	active          bool
	pendingPresence map[string][]byte
}

func New() *Filter {
	return &Filter{
		active:          true,
		pendingPresence: make(map[string][]byte),
	}
}

func (f *Filter) SetActive(active bool) [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.active = active
	if !active {
		return nil
	}
	if len(f.pendingPresence) == 0 {
		return nil
	}
	out := make([][]byte, 0, len(f.pendingPresence))
	for _, raw := range f.pendingPresence {
		out = append(out, raw)
	}
	f.pendingPresence = make(map[string][]byte)
	return out
}

func (f *Filter) ShouldDeliver(si StanzaInfo) (deliver bool, holdAsPresence bool) {
	f.mu.Lock()
	active := f.active
	f.mu.Unlock()

	if active {
		return true, false
	}

	switch si.Kind {
	case KindPresence:
		return false, true
	case KindIQ:
		return true, false
	case KindMessage:
		if si.IsError || si.IsMUCSubject {
			return true, false
		}
		if si.HasBody {
			return true, false
		}
		if si.HasChatState && !si.HasBody {
			return false, false
		}
		return true, false
	}
	return true, false
}

func (f *Filter) HoldPresence(fromJID string, raw []byte) {
	f.mu.Lock()
	cp := make([]byte, len(raw))
	copy(cp, raw)
	f.pendingPresence[fromJID] = cp
	f.mu.Unlock()
}

func (f *Filter) IsActive() bool {
	f.mu.Lock()
	v := f.active
	f.mu.Unlock()
	return v
}

func (f *Filter) FlushHeld() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.pendingPresence) == 0 {
		return nil
	}
	out := make([][]byte, 0, len(f.pendingPresence))
	for _, raw := range f.pendingPresence {
		out = append(out, raw)
	}
	f.pendingPresence = make(map[string][]byte)
	return out
}

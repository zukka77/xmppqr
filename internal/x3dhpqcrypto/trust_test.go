// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"errors"
	"testing"
)

func TestTrustStateString(t *testing.T) {
	cases := []struct {
		s    TrustState
		want string
	}{
		{TrustUnverified, "unverified"},
		{TrustPinned, "pinned"},
		{TrustRotated, "rotated"},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("TrustState(%d).String() = %q, want %q", int(c.s), got, c.want)
		}
	}
}

type memTrustStore struct {
	entries map[string]*TrustEntry
}

func newMemTrustStore() *memTrustStore {
	return &memTrustStore{entries: make(map[string]*TrustEntry)}
}

func (m *memTrustStore) Get(aik *AccountIdentityPub) (*TrustEntry, error) {
	key := string(aik.Marshal())
	e, ok := m.entries[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return e, nil
}

func (m *memTrustStore) Put(entry *TrustEntry) error {
	m.entries[string(entry.AIKPub.Marshal())] = entry
	return nil
}

func TestTrustEntryRoundTrip(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	succ, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}

	store := newMemTrustStore()

	entry := &TrustEntry{
		AIKPub:    aik.Public(),
		State:     TrustRotated,
		PinnedAt:  1700000000,
		Successor: succ.Public(),
	}
	if err := store.Put(entry); err != nil {
		t.Fatal(err)
	}

	got, err := store.Get(aik.Public())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.State != TrustRotated {
		t.Errorf("State = %v, want TrustRotated", got.State)
	}
	if got.PinnedAt != 1700000000 {
		t.Errorf("PinnedAt = %d, want 1700000000", got.PinnedAt)
	}
	if !got.AIKPub.Equal(aik.Public()) {
		t.Error("AIKPub mismatch")
	}
	if !got.Successor.Equal(succ.Public()) {
		t.Error("Successor mismatch")
	}
}

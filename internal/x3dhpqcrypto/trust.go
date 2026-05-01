// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

type TrustState int

const (
	TrustUnverified TrustState = iota
	TrustPinned
	TrustRotated
)

func (s TrustState) String() string {
	switch s {
	case TrustPinned:
		return "pinned"
	case TrustRotated:
		return "rotated"
	default:
		return "unverified"
	}
}

type TrustEntry struct {
	AIKPub    *AccountIdentityPub
	State     TrustState
	PinnedAt  int64
	Successor *AccountIdentityPub
}

type TrustStore interface {
	Get(aik *AccountIdentityPub) (*TrustEntry, error)
	Put(entry *TrustEntry) error
}

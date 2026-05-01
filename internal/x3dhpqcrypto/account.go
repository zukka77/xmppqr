// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

type AccountIdentityKey struct {
	PrivEd25519 []byte
	PubEd25519  []byte
	PubMLDSA    []byte // reserved; nil for v1
}

type AccountIdentityPub struct {
	PubEd25519 []byte
	PubMLDSA   []byte // nil for v1
}

func GenerateAccountIdentity() (*AccountIdentityKey, error) {
	pub, priv, err := wolfcrypt.GenerateEd25519()
	if err != nil {
		return nil, err
	}
	return &AccountIdentityKey{
		PrivEd25519: priv,
		PubEd25519:  pub,
	}, nil
}

func (a *AccountIdentityKey) Public() *AccountIdentityPub {
	return &AccountIdentityPub{
		PubEd25519: a.PubEd25519,
		PubMLDSA:   a.PubMLDSA,
	}
}

func (a *AccountIdentityPub) Equal(b *AccountIdentityPub) bool {
	return bytes.Equal(a.PubEd25519, b.PubEd25519) && bytes.Equal(a.PubMLDSA, b.PubMLDSA)
}

// Marshal returns a stable, canonical byte encoding of the public AIK.
// Format: uint16 version (=1) | uint8 hasMLDSA | 32 bytes Ed25519 pub | (var) MLDSA pub
func (a *AccountIdentityPub) Marshal() []byte {
	hasMLDSA := uint8(0)
	if len(a.PubMLDSA) > 0 {
		hasMLDSA = 1
	}
	size := 2 + 1 + len(a.PubEd25519) + len(a.PubMLDSA)
	out := make([]byte, size)
	binary.BigEndian.PutUint16(out[0:2], 1)
	out[2] = hasMLDSA
	copy(out[3:], a.PubEd25519)
	if len(a.PubMLDSA) > 0 {
		copy(out[3+len(a.PubEd25519):], a.PubMLDSA)
	}
	return out
}

func UnmarshalAccountIdentityPub(b []byte) (*AccountIdentityPub, error) {
	if len(b) < 3 {
		return nil, errors.New("x3dhpqcrypto: AIK pub too short")
	}
	ver := binary.BigEndian.Uint16(b[0:2])
	if ver != 1 {
		return nil, fmt.Errorf("x3dhpqcrypto: unsupported AIK version %d", ver)
	}
	hasMLDSA := b[2]
	off := 3
	if off+32 > len(b) {
		return nil, errors.New("x3dhpqcrypto: AIK pub truncated")
	}
	pub := &AccountIdentityPub{
		PubEd25519: b[off : off+32],
	}
	off += 32
	if hasMLDSA == 1 && off < len(b) {
		pub.PubMLDSA = b[off:]
	}
	return pub, nil
}

// Fingerprint returns BLAKE2b-160 over the canonical-encoded public AIK,
// formatted as 30 hex chars in 6 groups of 5 separated by spaces.
func (a *AccountIdentityPub) Fingerprint() string {
	digest, err := wolfcrypt.Blake2b160(a.Marshal())
	if err != nil {
		panic("x3dhpqcrypto: blake2b160 failed: " + err.Error())
	}
	hex := fmt.Sprintf("%X", digest[:])
	// 40 hex chars → 6 groups of 5 (first 5 groups × 5 = 25, then last 5) but 20 bytes = 40 hex chars
	// 40 / 6 doesn't divide evenly; use groups: 7×5 = 35, last = 5 → 8 groups of 5
	// Spec says "30 hex chars in 6 groups of 5". 20 bytes = 40 hex chars, so truncate to 30.
	// Truncating to first 15 bytes (30 hex) is fine for display.
	h30 := hex[:30]
	return fmt.Sprintf("%s %s %s %s %s %s",
		h30[0:5], h30[5:10], h30[10:15], h30[15:20], h30[20:25], h30[25:30])
}

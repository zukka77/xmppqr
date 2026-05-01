// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

var ErrAccountIdentityMissingMLDSA = errors.New("x3dhpqcrypto: AIK missing ML-DSA-65 public key")

type AccountIdentityKey struct {
	PrivEd25519, PubEd25519 []byte
	PrivMLDSA, PubMLDSA     []byte
}

type AccountIdentityPub struct {
	PubEd25519 []byte
	PubMLDSA   []byte
}

func GenerateAccountIdentity() (*AccountIdentityKey, error) {
	ePub, ePriv, err := wolfcrypt.GenerateEd25519()
	if err != nil {
		return nil, err
	}
	mPub, mPriv, err := wolfcrypt.GenerateMLDSA65()
	if err != nil {
		return nil, err
	}
	return &AccountIdentityKey{
		PrivEd25519: ePriv,
		PubEd25519:  ePub,
		PrivMLDSA:   mPriv,
		PubMLDSA:    mPub,
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

func (a *AccountIdentityPub) Marshal() []byte {
	size := 2 + 1 + len(a.PubEd25519) + len(a.PubMLDSA)
	out := make([]byte, size)
	binary.BigEndian.PutUint16(out[0:2], 1)
	out[2] = 1
	copy(out[3:], a.PubEd25519)
	copy(out[3+len(a.PubEd25519):], a.PubMLDSA)
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
	if hasMLDSA != 1 {
		return nil, ErrAccountIdentityMissingMLDSA
	}
	off := 3
	if off+32 > len(b) {
		return nil, errors.New("x3dhpqcrypto: AIK pub truncated")
	}
	pub := &AccountIdentityPub{
		PubEd25519: b[off : off+32],
	}
	off += 32
	if off+wolfcrypt.MLDSA65PubSize > len(b) {
		return nil, ErrAccountIdentityMissingMLDSA
	}
	pub.PubMLDSA = b[off : off+wolfcrypt.MLDSA65PubSize]
	return pub, nil
}

func (a *AccountIdentityPub) Fingerprint() string {
	digest, err := wolfcrypt.Blake2b160(a.Marshal())
	if err != nil {
		panic("x3dhpqcrypto: blake2b160 failed: " + err.Error())
	}
	hex := fmt.Sprintf("%X", digest[:])
	h30 := hex[:30]
	return fmt.Sprintf("%s %s %s %s %s %s",
		h30[0:5], h30[5:10], h30[10:15], h30[15:20], h30[20:25], h30[25:30])
}

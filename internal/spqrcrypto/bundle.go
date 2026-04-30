// SPDX-License-Identifier: AGPL-3.0-or-later
package spqrcrypto

import (
	"encoding/binary"
	"errors"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

type SignedPreKey struct {
	ID        uint32
	PrivX25519 []byte
	PubX25519  []byte
	Signature  []byte
}

type KEMPreKey struct {
	ID      uint32
	PrivMLKEM []byte
	PubMLKEM  []byte
}

type OneTimePreKey struct {
	ID        uint32
	PrivX25519 []byte
	PubX25519  []byte
}

type Bundle struct {
	Identity       *IdentityKey
	SignedPreKey    *SignedPreKey
	KEMPreKeys      []*KEMPreKey
	OneTimePreKeys  []*OneTimePreKey
}

type PublicKEMPreKey struct {
	ID     uint32
	PubMLKEM []byte
}

type PublicOPK struct {
	ID        uint32
	PubX25519 []byte
}

type PublicBundle struct {
	IdentityPubX25519  []byte
	IdentityPubEd25519 []byte
	SPKID              uint32
	SPKPub             []byte
	SPKSig             []byte
	KEMPreKeys         []*PublicKEMPreKey
	OPKs               []*PublicOPK
}

func spkSignInput(pub []byte, id uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, id)
	return append(b, pub...)
}

func NewBundle(identity *IdentityKey, kemPreKeys, otpks int) (*Bundle, error) {
	if identity == nil {
		return nil, errors.New("spqrcrypto: nil identity")
	}

	xPub, xPriv, err := wolfcrypt.GenerateX25519()
	if err != nil {
		return nil, err
	}
	spkID := uint32(1)
	sig, err := wolfcrypt.Ed25519Sign(identity.PrivEd25519, spkSignInput(xPub, spkID))
	if err != nil {
		return nil, err
	}
	spk := &SignedPreKey{ID: spkID, PrivX25519: xPriv, PubX25519: xPub, Signature: sig}

	kems := make([]*KEMPreKey, kemPreKeys)
	for i := range kems {
		pub, priv, err := wolfcrypt.GenerateMLKEM768()
		if err != nil {
			return nil, err
		}
		kems[i] = &KEMPreKey{ID: uint32(i + 1), PrivMLKEM: priv, PubMLKEM: pub}
	}

	opks := make([]*OneTimePreKey, otpks)
	for i := range opks {
		pub, priv, err := wolfcrypt.GenerateX25519()
		if err != nil {
			return nil, err
		}
		opks[i] = &OneTimePreKey{ID: uint32(i + 1), PrivX25519: priv, PubX25519: pub}
	}

	return &Bundle{
		Identity:      identity,
		SignedPreKey:  spk,
		KEMPreKeys:    kems,
		OneTimePreKeys: opks,
	}, nil
}

func (b *Bundle) PublicView() *PublicBundle {
	kems := make([]*PublicKEMPreKey, len(b.KEMPreKeys))
	for i, k := range b.KEMPreKeys {
		kems[i] = &PublicKEMPreKey{ID: k.ID, PubMLKEM: k.PubMLKEM}
	}
	opks := make([]*PublicOPK, len(b.OneTimePreKeys))
	for i, o := range b.OneTimePreKeys {
		opks[i] = &PublicOPK{ID: o.ID, PubX25519: o.PubX25519}
	}
	return &PublicBundle{
		IdentityPubX25519:  b.Identity.PubX25519,
		IdentityPubEd25519: b.Identity.PubEd25519,
		SPKID:              b.SignedPreKey.ID,
		SPKPub:             b.SignedPreKey.PubX25519,
		SPKSig:             b.SignedPreKey.Signature,
		KEMPreKeys:         kems,
		OPKs:               opks,
	}
}

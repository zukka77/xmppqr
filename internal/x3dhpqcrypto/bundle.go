// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"encoding/binary"
	"errors"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

type SignedPreKey struct {
	ID         uint32
	PrivX25519 []byte
	PubX25519  []byte
	Signature  []byte
}

type PublicSignedPreKey struct {
	ID        uint32
	PubX25519 []byte
	Signature []byte
}

type KEMPreKey struct {
	ID       uint32
	PrivMLKEM []byte
	PubMLKEM  []byte
}

type OneTimePreKey struct {
	ID         uint32
	PrivX25519 []byte
	PubX25519  []byte
}

type Bundle struct {
	DeviceIdentity  *DeviceIdentityKey
	AccountIdentity *AccountIdentityKey // may be nil if AIK priv not held on this device
	DeviceCert      *DeviceCertificate
	SignedPreKey    *SignedPreKey
	KEMPreKeys      []*KEMPreKey
	OneTimePreKeys  []*OneTimePreKey
}

type PublicKEMPreKey struct {
	ID       uint32
	PubMLKEM []byte
}

type PublicOneTimePreKey struct {
	ID        uint32
	PubX25519 []byte
}

// PublicOPK is an alias kept for internal test helpers.
type PublicOPK = PublicOneTimePreKey

type PublicBundle struct {
	AIKPub         *AccountIdentityPub
	DeviceCert     *DeviceCertificate
	SignedPreKey   *PublicSignedPreKey
	KEMPreKeys     []*PublicKEMPreKey
	OneTimePreKeys []*PublicOneTimePreKey
	// Legacy flattened fields retained for x3dh.go internal use.
	IdentityPubX25519  []byte
	IdentityPubEd25519 []byte
	SPKID              uint32
	SPKPub             []byte
	SPKSig             []byte
	OPKs               []*PublicOPK
}

func spkSignInput(pub []byte, id uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, id)
	return append(b, pub...)
}

func NewBundle(dik *DeviceIdentityKey, dc *DeviceCertificate, kemPreKeys, otpks int) (*Bundle, error) {
	if dik == nil {
		return nil, errors.New("x3dhpqcrypto: nil device identity")
	}

	xPub, xPriv, err := wolfcrypt.GenerateX25519()
	if err != nil {
		return nil, err
	}
	spkID := uint32(1)
	sig, err := wolfcrypt.Ed25519Sign(dik.PrivEd25519, spkSignInput(xPub, spkID))
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
		DeviceIdentity: dik,
		DeviceCert:     dc,
		SignedPreKey:   spk,
		KEMPreKeys:     kems,
		OneTimePreKeys: opks,
	}, nil
}

func (b *Bundle) PublicView() *PublicBundle {
	if b.DeviceCert == nil {
		panic("x3dhpqcrypto: PublicView called on bundle with no DeviceCert")
	}

	kems := make([]*PublicKEMPreKey, len(b.KEMPreKeys))
	for i, k := range b.KEMPreKeys {
		kems[i] = &PublicKEMPreKey{ID: k.ID, PubMLKEM: k.PubMLKEM}
	}
	opks := make([]*PublicOneTimePreKey, len(b.OneTimePreKeys))
	for i, o := range b.OneTimePreKeys {
		opks[i] = &PublicOneTimePreKey{ID: o.ID, PubX25519: o.PubX25519}
	}

	var aikPub *AccountIdentityPub
	if b.AccountIdentity != nil {
		aikPub = b.AccountIdentity.Public()
	}

	spkPub := &PublicSignedPreKey{
		ID:        b.SignedPreKey.ID,
		PubX25519: b.SignedPreKey.PubX25519,
		Signature: b.SignedPreKey.Signature,
	}

	return &PublicBundle{
		AIKPub:             aikPub,
		DeviceCert:         b.DeviceCert,
		SignedPreKey:       spkPub,
		KEMPreKeys:         kems,
		OneTimePreKeys:     opks,
		IdentityPubX25519:  b.DeviceIdentity.PubX25519,
		IdentityPubEd25519: b.DeviceIdentity.PubEd25519,
		SPKID:              b.SignedPreKey.ID,
		SPKPub:             b.SignedPreKey.PubX25519,
		SPKSig:             b.SignedPreKey.Signature,
		OPKs:               opks,
	}
}

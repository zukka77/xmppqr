// SPDX-License-Identifier: AGPL-3.0-or-later
// Package x3dhpqcrypto implements the X3DHPQ Triple Ratchet cryptography layer.
package x3dhpqcrypto

import "github.com/danielinux/xmppqr/internal/wolfcrypt"

type IdentityKey = DeviceIdentityKey

type DeviceIdentityKey struct {
	PrivX25519, PubX25519   []byte
	PrivEd25519, PubEd25519 []byte
	PrivMLDSA, PubMLDSA     []byte
}

func GenerateDeviceIdentity() (*DeviceIdentityKey, error) {
	xPub, xPriv, err := wolfcrypt.GenerateX25519()
	if err != nil {
		return nil, err
	}
	ePub, ePriv, err := wolfcrypt.GenerateEd25519()
	if err != nil {
		return nil, err
	}
	mPub, mPriv, err := wolfcrypt.GenerateMLDSA65()
	if err != nil {
		return nil, err
	}
	return &DeviceIdentityKey{
		PrivX25519:  xPriv,
		PubX25519:   xPub,
		PrivEd25519: ePriv,
		PubEd25519:  ePub,
		PrivMLDSA:   mPriv,
		PubMLDSA:    mPub,
	}, nil
}

func GenerateIdentity() (*DeviceIdentityKey, error) {
	return GenerateDeviceIdentity()
}

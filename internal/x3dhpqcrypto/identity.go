// SPDX-License-Identifier: AGPL-3.0-or-later
// Package x3dhpqcrypto implements the X3DHPQ Triple Ratchet cryptography layer.
package x3dhpqcrypto

import "github.com/danielinux/xmppqr/internal/wolfcrypt"

type IdentityKey struct {
	PrivX25519  []byte
	PubX25519   []byte
	PrivEd25519 []byte
	PubEd25519  []byte
}

func GenerateIdentity() (*IdentityKey, error) {
	xPub, xPriv, err := wolfcrypt.GenerateX25519()
	if err != nil {
		return nil, err
	}
	ePub, ePriv, err := wolfcrypt.GenerateEd25519()
	if err != nil {
		return nil, err
	}
	return &IdentityKey{
		PrivX25519:  xPriv,
		PubX25519:   xPub,
		PrivEd25519: ePriv,
		PubEd25519:  ePub,
	}, nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// peerAIK is REQUIRED in InitiateSession and RespondSession; nil is never tolerated.
package x3dhpqcrypto

import (
	"errors"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

const (
	infoX3DH          = "X3DHPQ-X3DH-PQ-v0"
	infoRootKey       = "X3DHPQ-RootKey-v0"
	infoHybridRoot    = "X3DHPQ-HybridRoot-v0"
	infoTripleRatchet = "X3DHPQ-TripleRatchet-v0"
	infoMessageKey    = "X3DHPQ-MessageKey-v0"
)

var ErrUntrustedDevice = errors.New("x3dhpqcrypto: device certificate not signed by expected AIK")

// hkdf64 derives 64 bytes using HKDF-SHA512 with a zero salt.
func hkdf64(salt, ikm []byte, info string) ([]byte, error) {
	if len(salt) == 0 {
		salt = make([]byte, 64)
	}
	prk, err := wolfcrypt.HKDFExtract(salt, ikm)
	if err != nil {
		return nil, err
	}
	return wolfcrypt.HKDFExpand(prk, []byte(info), 64)
}

// hkdf32 derives 32 bytes using HKDF-SHA512.
func hkdf32(salt, ikm []byte, info string) ([]byte, error) {
	if len(salt) == 0 {
		salt = make([]byte, 64)
	}
	prk, err := wolfcrypt.HKDFExtract(salt, ikm)
	if err != nil {
		return nil, err
	}
	return wolfcrypt.HKDFExpand(prk, []byte(info), 32)
}

// hkdf44 derives 44 bytes (32 AES key + 12 nonce).
func hkdf44(salt, ikm []byte, info string) ([]byte, error) {
	if len(salt) == 0 {
		salt = make([]byte, 64)
	}
	prk, err := wolfcrypt.HKDFExtract(salt, ikm)
	if err != nil {
		return nil, err
	}
	return wolfcrypt.HKDFExpand(prk, []byte(info), 44)
}

// InitiateSession performs PQXDH key agreement as the initiator (Alice).
// peer.DeviceCert is verified against peerAIK before any DH or KEM is performed.
// AD folds in both AIK public keys to bind the session to both identities.
func InitiateSession(
	myDIK *DeviceIdentityKey,
	myEphemX25519Priv, myEphemX25519Pub []byte,
	peer *PublicBundle,
	peerAIK *AccountIdentityPub,
	opkID uint32,
	kemPreKeyID uint32,
) (rootKey []byte, ad []byte, kemCiphertext []byte, opkUsed bool, err error) {
	if myDIK == nil || peer == nil {
		return nil, nil, nil, false, errors.New("x3dhpqcrypto: nil argument")
	}

	if peerAIK == nil {
		return nil, nil, nil, false, ErrUntrustedDevice
	}
	if peer.DeviceCert == nil {
		return nil, nil, nil, false, ErrUntrustedDevice
	}
	if err := peer.DeviceCert.Verify(peerAIK); err != nil {
		return nil, nil, nil, false, ErrUntrustedDevice
	}

	dh1, err := wolfcrypt.X25519SharedSecret(myDIK.PrivX25519, peer.SPKPub)
	if err != nil {
		return nil, nil, nil, false, err
	}
	dh2, err := wolfcrypt.X25519SharedSecret(myEphemX25519Priv, peer.IdentityPubX25519)
	if err != nil {
		return nil, nil, nil, false, err
	}
	dh3, err := wolfcrypt.X25519SharedSecret(myEphemX25519Priv, peer.SPKPub)
	if err != nil {
		return nil, nil, nil, false, err
	}

	material := make([]byte, 0, 4*32+32)
	material = append(material, dh1...)
	material = append(material, dh2...)
	material = append(material, dh3...)

	var opk *PublicOneTimePreKey
	if opkID != 0 {
		for _, o := range peer.OPKs {
			if o.ID == opkID {
				opk = o
				break
			}
		}
	}
	if opk != nil {
		dh4, err2 := wolfcrypt.X25519SharedSecret(myEphemX25519Priv, opk.PubX25519)
		if err2 != nil {
			return nil, nil, nil, false, err2
		}
		material = append(material, dh4...)
		opkUsed = true
	}

	var kemPub []byte
	for _, k := range peer.KEMPreKeys {
		if k.ID == kemPreKeyID {
			kemPub = k.PubMLKEM
			break
		}
	}
	if kemPub == nil {
		return nil, nil, nil, false, errors.New("x3dhpqcrypto: KEM prekey not found")
	}
	ct, kemSS, err := wolfcrypt.MLKEM768Encapsulate(kemPub)
	if err != nil {
		return nil, nil, nil, false, err
	}
	material = append(material, kemSS...)

	rk, err := hkdf64(nil, material, infoX3DH)
	if err != nil {
		return nil, nil, nil, false, err
	}

	// AD: initiator_DIK_pub || responder_DIK_pub (symmetric with RespondSession).
	ad = append(myDIK.PubX25519, peer.IdentityPubX25519...)
	return rk, ad, ct, opkUsed, nil
}

// RespondSession performs PQXDH key agreement as the responder (Bob).
// peerDC is verified against peerAIK before any computation.
func RespondSession(
	myDIK *DeviceIdentityKey,
	mySPKPriv []byte,
	mySPKOPKPriv []byte,
	peerDC *DeviceCertificate,
	peerAIK *AccountIdentityPub,
	peerEphemPub []byte,
	kemPreKeyPriv []byte,
	kemCiphertext []byte,
) (rootKey []byte, ad []byte, err error) {
	if peerAIK == nil {
		return nil, nil, ErrUntrustedDevice
	}
	if peerDC == nil {
		return nil, nil, ErrUntrustedDevice
	}
	if err := peerDC.Verify(peerAIK); err != nil {
		return nil, nil, ErrUntrustedDevice
	}

	peerIdentityPubX25519 := peerDC.DIKPubX25519

	dh1, err := wolfcrypt.X25519SharedSecret(mySPKPriv, peerIdentityPubX25519)
	if err != nil {
		return nil, nil, err
	}
	dh2, err := wolfcrypt.X25519SharedSecret(myDIK.PrivX25519, peerEphemPub)
	if err != nil {
		return nil, nil, err
	}
	dh3, err := wolfcrypt.X25519SharedSecret(mySPKPriv, peerEphemPub)
	if err != nil {
		return nil, nil, err
	}

	material := make([]byte, 0, 5*32)
	material = append(material, dh1...)
	material = append(material, dh2...)
	material = append(material, dh3...)

	if mySPKOPKPriv != nil {
		dh4, err2 := wolfcrypt.X25519SharedSecret(mySPKOPKPriv, peerEphemPub)
		if err2 != nil {
			return nil, nil, err2
		}
		material = append(material, dh4...)
	}

	kemSS, err := wolfcrypt.MLKEM768Decapsulate(kemPreKeyPriv, kemCiphertext)
	if err != nil {
		return nil, nil, err
	}
	material = append(material, kemSS...)

	rk, err := hkdf64(nil, material, infoX3DH)
	if err != nil {
		return nil, nil, err
	}

	// AD: initiator_DIK_pub || responder_DIK_pub (symmetric with InitiateSession).
	ad = append(peerIdentityPubX25519, myDIK.PubX25519...)
	return rk, ad, nil
}

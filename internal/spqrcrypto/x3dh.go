// SPDX-License-Identifier: AGPL-3.0-or-later
package spqrcrypto

import (
	"errors"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

const (
	infoX3DH           = "SPQR-X3DH-PQ-v0"
	infoRootKey        = "SPQR-RootKey-v0"
	infoHybridRoot     = "SPQR-HybridRoot-v0"
	infoTripleRatchet  = "SPQR-TripleRatchet-v0"
	infoMessageKey     = "SPQR-MessageKey-v0"
)

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
// Returns rootKey (64 bytes, first 32=RK second 32=initial CK), ad, kemCiphertext.
func InitiateSession(
	myIdentity *IdentityKey,
	myEphemX25519Priv, myEphemX25519Pub []byte,
	peer *PublicBundle,
	opkID uint32,
	kemPreKeyID uint32,
) (rootKey []byte, ad []byte, kemCiphertext []byte, opkUsed bool, err error) {
	if myIdentity == nil || peer == nil {
		return nil, nil, nil, false, errors.New("spqrcrypto: nil argument")
	}

	dh1, err := wolfcrypt.X25519SharedSecret(myIdentity.PrivX25519, peer.SPKPub)
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

	// DH4: optional OPK
	var opk *PublicOPK
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

	// KEM: find the KEM prekey
	var kemPub []byte
	for _, k := range peer.KEMPreKeys {
		if k.ID == kemPreKeyID {
			kemPub = k.PubMLKEM
			break
		}
	}
	if kemPub == nil {
		return nil, nil, nil, false, errors.New("spqrcrypto: KEM prekey not found")
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

	ad = append(myIdentity.PubX25519, peer.IdentityPubX25519...)
	return rk, ad, ct, opkUsed, nil
}

// RespondSession performs PQXDH key agreement as the responder (Bob).
// mySPK_OPK_priv is the private key of the OPK (if used, else nil).
func RespondSession(
	myIdentity *IdentityKey,
	mySPKPriv []byte,
	mySPKOPKPriv []byte,
	peerIdentityPubX25519, peerEphemPub []byte,
	kemPreKeyPriv []byte,
	kemCiphertext []byte,
) (rootKey []byte, ad []byte, err error) {
	// DH1 = X25519(SPK_B_priv, IK_A_pub)
	dh1, err := wolfcrypt.X25519SharedSecret(mySPKPriv, peerIdentityPubX25519)
	if err != nil {
		return nil, nil, err
	}
	// DH2 = X25519(IK_B_priv, EK_A_pub)
	dh2, err := wolfcrypt.X25519SharedSecret(myIdentity.PrivX25519, peerEphemPub)
	if err != nil {
		return nil, nil, err
	}
	// DH3 = X25519(SPK_B_priv, EK_A_pub)
	dh3, err := wolfcrypt.X25519SharedSecret(mySPKPriv, peerEphemPub)
	if err != nil {
		return nil, nil, err
	}

	material := make([]byte, 0, 5*32)
	material = append(material, dh1...)
	material = append(material, dh2...)
	material = append(material, dh3...)

	// DH4: optional OPK
	if mySPKOPKPriv != nil {
		dh4, err2 := wolfcrypt.X25519SharedSecret(mySPKOPKPriv, peerEphemPub)
		if err2 != nil {
			return nil, nil, err2
		}
		material = append(material, dh4...)
	}

	// KEM decapsulate
	kemSS, err := wolfcrypt.MLKEM768Decapsulate(kemPreKeyPriv, kemCiphertext)
	if err != nil {
		return nil, nil, err
	}
	material = append(material, kemSS...)

	rk, err := hkdf64(nil, material, infoX3DH)
	if err != nil {
		return nil, nil, err
	}

	ad = append(peerIdentityPubX25519, myIdentity.PubX25519...)
	return rk, ad, nil
}

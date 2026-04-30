// SPDX-License-Identifier: AGPL-3.0-or-later
package spqrcrypto

import (
	"bytes"
	"errors"
	"time"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

const (
	kemCheckpointK   = 50
	kemCheckpointT   = 3600 * time.Second
	maxSkipKeys      = 1000
)

type PrivPub struct {
	Priv []byte
	Pub  []byte
}

type SkipKey struct {
	DHPub string
	N     uint32
}

// skipKey is an alias kept for internal use clarity.
type skipKey = SkipKey

type State struct {
	RK               []byte
	ChainSendKey     []byte
	ChainRecvKey     []byte
	SendingDH        PrivPub
	RemoteDHPub      []byte
	SendCount        uint32
	RecvCount        uint32
	PrevSendCount    uint32

	// KEM ratchet state
	KEMSendPub           []byte // peer's current KEM pub (we encapsulate to this)
	KEMRecvPriv          []byte // our current KEM priv (peer encapsulates to this)
	KEMRecvPub           []byte // our current KEM pub (advertised to peer)
	KEMSinceCheckpoint   uint32
	LastCheckpointTime   time.Time

	MessageKeys map[skipKey][]byte
	AD          []byte

	// whether we have received at least one message (enables DH ratchet on send)
	receivedFirst bool
	// pending DH ratchet step on next send
	pendingDHRatchet bool
}

// chainStep advances a chain key, returning (messageKey, nextChainKey).
func chainStep(ck []byte) (mk, nextCK []byte, err error) {
	mk, err = wolfcrypt.HMACSHA256(ck, []byte{0x01})
	if err != nil {
		return nil, nil, err
	}
	nextCK, err = wolfcrypt.HMACSHA256(ck, []byte{0x02})
	if err != nil {
		return nil, nil, err
	}
	return mk, nextCK, nil
}

// dhRatchetStep runs a DH ratchet step given a new remote DH public key.
// It returns (newRK, newCK).
func dhRatchetStep(rk, dhPriv, remotePub []byte) (newRK, newCK []byte, err error) {
	dhOut, err := wolfcrypt.X25519SharedSecret(dhPriv, remotePub)
	if err != nil {
		return nil, nil, err
	}
	out, err := hkdf64(rk, dhOut, infoRootKey)
	if err != nil {
		return nil, nil, err
	}
	return out[:32], out[32:], nil
}

// kemRatchetStep mixes a KEM shared secret into the chain.
// Returns new chain key.
func kemRatchetStep(ck, kemSS []byte) ([]byte, error) {
	return hkdf32(ck, kemSS, infoTripleRatchet)
}

// deriveMessageKey expands a raw message key into AES key + nonce (44 bytes).
func deriveMessageKey(mk []byte) (aesKey, nonce []byte, err error) {
	out, err := hkdf44(nil, mk, infoMessageKey)
	if err != nil {
		return nil, nil, err
	}
	return out[:32], out[32:44], nil
}

func NewSendingState(rootKey, ad []byte, peerDHPub []byte) (*State, error) {
	// Generate our initial sending DH keypair.
	pub, priv, err := wolfcrypt.GenerateX25519()
	if err != nil {
		return nil, err
	}
	rk := rootKey[:32]
	ck := rootKey[32:]

	// Run one DH ratchet step immediately so the send chain is initialized.
	newRK, sendCK, err := dhRatchetStep(rk, priv, peerDHPub)
	if err != nil {
		return nil, err
	}

	s := &State{
		RK:                 newRK,
		ChainSendKey:       sendCK,
		SendingDH:          PrivPub{Priv: priv, Pub: pub},
		RemoteDHPub:        peerDHPub,
		AD:                 ad,
		MessageKeys:        make(map[skipKey][]byte),
		LastCheckpointTime: time.Now(),
	}
	_ = ck
	return s, nil
}

func NewReceivingState(rootKey, ad []byte, myDH PrivPub) (*State, error) {
	s := &State{
		RK:                 rootKey[:32],
		ChainRecvKey:       rootKey[32:],
		SendingDH:          myDH,
		AD:                 ad,
		MessageKeys:        make(map[skipKey][]byte),
		LastCheckpointTime: time.Now(),
	}
	return s, nil
}

func (s *State) EncryptMessage(plaintext []byte, now time.Time) (*MessageHeader, []byte, error) {
	// Determine if we need a KEM checkpoint.
	needKEM := s.KEMSendPub != nil && (s.KEMSinceCheckpoint >= kemCheckpointK ||
		(!s.LastCheckpointTime.IsZero() && now.Sub(s.LastCheckpointTime) >= kemCheckpointT))

	var kemCT []byte
	var newKEMPub []byte
	var newKEMPriv []byte

	if needKEM {
		// Generate fresh KEM keypair to advertise for next checkpoint.
		kPub, kPriv, err := wolfcrypt.GenerateMLKEM768()
		if err != nil {
			return nil, nil, err
		}
		// Encapsulate to peer's current KEM pub.
		ct, kemSS, err := wolfcrypt.MLKEM768Encapsulate(s.KEMSendPub)
		if err != nil {
			return nil, nil, err
		}
		kemCT = ct
		newKEMPub = kPub
		newKEMPriv = kPriv

		// Mix into send chain.
		newCK, err := kemRatchetStep(s.ChainSendKey, kemSS)
		if err != nil {
			return nil, nil, err
		}
		s.ChainSendKey = newCK
		s.KEMSinceCheckpoint = 0
		s.LastCheckpointTime = now
		s.KEMRecvPriv = newKEMPriv
		s.KEMRecvPub = newKEMPub
	}

	// Advance send chain.
	mk, nextCK, err := chainStep(s.ChainSendKey)
	if err != nil {
		return nil, nil, err
	}
	s.ChainSendKey = nextCK

	hdr := &MessageHeader{
		DHPub:        s.SendingDH.Pub,
		PrevChainLen: s.PrevSendCount,
		N:            s.SendCount,
	}
	if needKEM {
		hdr.KEMCiphertext = kemCT
		hdr.KEMPubForReply = newKEMPub
	} else if s.KEMRecvPub != nil {
		// Always advertise our current KEM pub so the peer can send checkpoints to us.
		hdr.KEMPubForReply = s.KEMRecvPub
	}

	// Encrypt: AES-256-GCM(mk, nonce, plaintext, AD||header)
	aesKey, nonce, err := deriveMessageKey(mk)
	if err != nil {
		return nil, nil, err
	}
	aead, err := wolfcrypt.NewAESGCM(aesKey)
	if err != nil {
		return nil, nil, err
	}
	aadData := append(s.AD, hdr.Marshal()...)
	ct, err := aead.Seal(nonce, plaintext, aadData)
	if err != nil {
		return nil, nil, err
	}

	s.SendCount++
	s.KEMSinceCheckpoint++

	return hdr, ct, nil
}

func (s *State) skipMessageKeys(dhPub string, until uint32) error {
	if until-s.RecvCount > maxSkipKeys {
		return errors.New("spqrcrypto: too many skipped messages")
	}
	for s.RecvCount < until {
		mk, nextCK, err := chainStep(s.ChainRecvKey)
		if err != nil {
			return err
		}
		s.MessageKeys[skipKey{DHPub: dhPub, N: s.RecvCount}] = mk
		s.ChainRecvKey = nextCK
		s.RecvCount++
	}
	return nil
}

func (s *State) DecryptMessage(header *MessageHeader, ciphertext []byte) ([]byte, error) {
	// Update KEM send pub if the header advertises one.
	if len(header.KEMPubForReply) > 0 {
		s.KEMSendPub = header.KEMPubForReply
	}

	dhStr := string(header.DHPub)

	// Check skip cache first.
	sk := skipKey{DHPub: dhStr, N: header.N}
	if mk, ok := s.MessageKeys[sk]; ok {
		delete(s.MessageKeys, sk)
		return s.decryptWithMK(mk, header, ciphertext)
	}

	// DH ratchet step if new DHPub.
	if !bytes.Equal(header.DHPub, s.RemoteDHPub) {
		// Save skipped keys on current recv chain before ratchet.
		if s.ChainRecvKey != nil {
			if err := s.skipMessageKeys(string(s.RemoteDHPub), header.PrevChainLen); err != nil {
				return nil, err
			}
		}
		s.PrevSendCount = s.SendCount
		s.SendCount = 0
		s.RecvCount = 0

		// Advance receiving chain with new DHPub.
		newRK, recvCK, err := dhRatchetStep(s.RK, s.SendingDH.Priv, header.DHPub)
		if err != nil {
			return nil, err
		}
		s.RK = newRK
		s.ChainRecvKey = recvCK
		s.RemoteDHPub = header.DHPub

		// Generate new sending DH keypair for next turn.
		newPub, newPriv, err := wolfcrypt.GenerateX25519()
		if err != nil {
			return nil, err
		}
		newRK2, sendCK, err := dhRatchetStep(s.RK, newPriv, header.DHPub)
		if err != nil {
			return nil, err
		}
		s.RK = newRK2
		s.ChainSendKey = sendCK
		s.SendingDH = PrivPub{Priv: newPriv, Pub: newPub}
	}

	// Handle KEM checkpoint if present.
	if len(header.KEMCiphertext) > 0 && s.KEMRecvPriv != nil {
		kemSS, err := wolfcrypt.MLKEM768Decapsulate(s.KEMRecvPriv, header.KEMCiphertext)
		if err != nil {
			return nil, err
		}
		newCK, err := kemRatchetStep(s.ChainRecvKey, kemSS)
		if err != nil {
			return nil, err
		}
		s.ChainRecvKey = newCK
	}

	// Skip to the message's position.
	if err := s.skipMessageKeys(dhStr, header.N); err != nil {
		return nil, err
	}

	// Advance one more step for message N.
	mk, nextCK, err := chainStep(s.ChainRecvKey)
	if err != nil {
		return nil, err
	}
	s.ChainRecvKey = nextCK
	s.RecvCount++

	return s.decryptWithMK(mk, header, ciphertext)
}

func (s *State) decryptWithMK(mk []byte, header *MessageHeader, ciphertext []byte) ([]byte, error) {
	aesKey, nonce, err := deriveMessageKey(mk)
	if err != nil {
		return nil, err
	}
	aead, err := wolfcrypt.NewAESGCM(aesKey)
	if err != nil {
		return nil, err
	}
	aadData := append(s.AD, header.Marshal()...)
	return aead.Open(nonce, ciphertext, aadData)
}

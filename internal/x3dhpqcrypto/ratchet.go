// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"bytes"
	"encoding/binary"
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

	// KEMHistory accumulates entropy from every observed KEM checkpoint.
	// Both parties update it identically (deterministic from kem_ss + transcript).
	// It is mixed into the next DH ratchet step's RK derivation, so an
	// attacker who has the current RK but missed any prior kem_ss cannot
	// derive the post-DH-ratchet RK. This gives the "RK is healed by KEM
	// checkpoints" property without requiring sender/receiver RK sync
	// (which is impossible in an asymmetric Double Ratchet flow).
	KEMHistory []byte

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
// kemHistory is folded into the IKM so any KEM-injected entropy from prior
// checkpoints carries forward into the new RK. Both parties update KEMHistory
// identically, so the resulting RK stays in sync.
// It returns (newRK, newCK).
func dhRatchetStep(rk, dhPriv, remotePub, kemHistory []byte) (newRK, newCK []byte, err error) {
	dhOut, err := wolfcrypt.X25519SharedSecret(dhPriv, remotePub)
	if err != nil {
		return nil, nil, err
	}
	ikm := make([]byte, 0, len(dhOut)+len(kemHistory))
	ikm = append(ikm, dhOut...)
	ikm = append(ikm, kemHistory...)
	out, err := hkdf64(rk, ikm, infoRootKey)
	if err != nil {
		return nil, nil, err
	}
	return out[:32], out[32:], nil
}

// kemCheckpointMix re-derives both directions' chain keys and updates the
// KEM history. Uses the SENDER's chain key (sender's CK_send == receiver's
// CK_recv after every DH ratchet step) as the synchronized salt — this
// avoids the desync issue that would occur with raw RK in asymmetric flows.
//
// The KEM history is a separate, deterministically-updated 32-byte digest
// that both parties carry forward and inject at the next DH ratchet step,
// healing the RK with PQ entropy.
//
// transcript_hash = SHA-512("X3DHPQ-Checkpoint-Transcript-v1\0" || uint32be(epoch) || senderDH || kemCT)
// prk             = HKDF-Extract(salt=senderCK, ikm=kemSS||transcript_hash)
// newCKs          = HKDF-Expand(prk, "X3DHPQ-ChainSend-v1", 32)
// newCKr          = HKDF-Expand(prk, "X3DHPQ-ChainRecv-v1", 32)
// newKEMHistory   = SHA-512("X3DHPQ-KEMHistory-v1\0" || prevHistory || kemSS || transcript_hash)[:32]
func kemCheckpointMix(senderCK, kemSS, senderDH, kemCT []byte, epoch uint32, prevHistory []byte) (newCKs, newCKr, newHistory []byte, err error) {
	const transcriptLabel = "X3DHPQ-Checkpoint-Transcript-v1\x00"
	const historyLabel = "X3DHPQ-KEMHistory-v1\x00"
	epochBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(epochBuf, epoch)
	transcriptInput := make([]byte, 0, len(transcriptLabel)+4+len(senderDH)+len(kemCT))
	transcriptInput = append(transcriptInput, transcriptLabel...)
	transcriptInput = append(transcriptInput, epochBuf...)
	transcriptInput = append(transcriptInput, senderDH...)
	transcriptInput = append(transcriptInput, kemCT...)
	th := wolfcrypt.SHA512(transcriptInput)

	ikm := make([]byte, 0, len(kemSS)+64)
	ikm = append(ikm, kemSS...)
	ikm = append(ikm, th[:]...)

	prk, err := wolfcrypt.HKDFExtract(senderCK, ikm)
	if err != nil {
		return nil, nil, nil, err
	}
	newCKs, err = wolfcrypt.HKDFExpand(prk, []byte(infoCheckpointChainSend), 32)
	if err != nil {
		return nil, nil, nil, err
	}
	newCKr, err = wolfcrypt.HKDFExpand(prk, []byte(infoCheckpointChainRecv), 32)
	if err != nil {
		return nil, nil, nil, err
	}

	histInput := make([]byte, 0, len(historyLabel)+len(prevHistory)+len(kemSS)+64)
	histInput = append(histInput, historyLabel...)
	histInput = append(histInput, prevHistory...)
	histInput = append(histInput, kemSS...)
	histInput = append(histInput, th[:]...)
	histDigest := wolfcrypt.SHA512(histInput)
	newHistory = histDigest[:32]

	return newCKs, newCKr, newHistory, nil
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
	// Use a 32-zero-byte KEMHistory: matches the responder's initial state
	// (NewReceivingState). On the responder's first DH ratchet (when they
	// see the initiator's first message), they use the same zero-bytes,
	// keeping RK in sync.
	newRK, sendCK, err := dhRatchetStep(rk, priv, peerDHPub, make([]byte, 32))
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
		KEMHistory:         make([]byte, 32),
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
		KEMHistory:         make([]byte, 32),
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

		newCKs, newCKr, newHistory, err := kemCheckpointMix(
			s.ChainSendKey, kemSS, s.SendingDH.Pub, kemCT, s.SendCount, s.KEMHistory,
		)
		if err != nil {
			return nil, nil, err
		}
		s.ChainSendKey = newCKs
		s.ChainRecvKey = newCKr
		s.KEMHistory = newHistory
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
		return errors.New("x3dhpqcrypto: too many skipped messages")
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

		// Advance receiving chain with new DHPub. KEMHistory mixes any prior
		// PQ-checkpoint entropy into RK so post-DH-ratchet RK heals across
		// any KEM checkpoint observed before this DH ratchet step.
		newRK, recvCK, err := dhRatchetStep(s.RK, s.SendingDH.Priv, header.DHPub, s.KEMHistory)
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
		newRK2, sendCK, err := dhRatchetStep(s.RK, newPriv, header.DHPub, s.KEMHistory)
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
		newCKs, newCKr, newHistory, err := kemCheckpointMix(
			s.ChainRecvKey, kemSS, header.DHPub, header.KEMCiphertext, header.N, s.KEMHistory,
		)
		if err != nil {
			return nil, err
		}
		s.ChainRecvKey = newCKs
		s.ChainSendKey = newCKr
		s.KEMHistory = newHistory
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

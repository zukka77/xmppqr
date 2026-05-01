// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"encoding/binary"
	"errors"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

var ErrPairingProtocol = errors.New("pairing: protocol violation")
var ErrPairingAuth = errors.New("pairing: authentication failed (wrong code or key confirm)")

type PairingMsgType uint8

const (
	PairingMsgPAKE1   PairingMsgType = 1
	PairingMsgPAKE2   PairingMsgType = 2
	PairingMsgConfirm PairingMsgType = 3
	PairingMsgPayload PairingMsgType = 4
	PairingMsgAck     PairingMsgType = 5
)

type PairingMsg struct {
	Type    PairingMsgType
	Payload []byte
}

func (m *PairingMsg) Marshal() []byte {
	out := make([]byte, 1+4+len(m.Payload))
	out[0] = uint8(m.Type)
	binary.BigEndian.PutUint32(out[1:5], uint32(len(m.Payload)))
	copy(out[5:], m.Payload)
	return out
}

func UnmarshalPairingMsg(b []byte) (*PairingMsg, error) {
	if len(b) < 5 {
		return nil, ErrPairingProtocol
	}
	t := PairingMsgType(b[0])
	l := int(binary.BigEndian.Uint32(b[1:5]))
	if len(b) < 5+l {
		return nil, ErrPairingProtocol
	}
	payload := make([]byte, l)
	copy(payload, b[5:5+l])
	return &PairingMsg{Type: t, Payload: payload}, nil
}

type PairingOptions struct {
	NewDeviceID    uint32
	SharePrimary   bool
	StateBlob      []byte
	NewDeviceFlags uint8
}

type PairingResult struct {
	AIKPub  *AccountIdentityPub
	Cert    *DeviceCertificate
	AIKPriv *AccountIdentityKey
	State   []byte
}

type pairingStep int

const (
	pairingStepInit           pairingStep = iota // 0
	pairingStepSentPAKE1                         // 1: E sent PAKE1, N sent PAKE2
	pairingStepSentConfirm                       // 2: E sent ConfirmE, N sent ConfirmN
	pairingStepWaitDIK                           // 3: E waiting for N's encrypted DIK_pub
	pairingStepSentPayload                       // 4: E sent issuance payload, waiting for ACK
	pairingStepDone                              // 5
)

type PairingExisting struct {
	aik        *AccountIdentityKey
	cpace      *CPaceState
	sid        []byte
	opts       PairingOptions
	sessionKey []byte
	gcm        *wolfcrypt.AESGCM
	issuedCert *DeviceCertificate
	step       pairingStep
	encCounter uint64
	decCounter uint64
}

func NewPairingExisting(aik *AccountIdentityKey, code string, sid []byte, opts PairingOptions) (*PairingExisting, error) {
	c, err := NewCPace(CPaceInitiator, []byte(code), sid, nil, nil)
	if err != nil {
		return nil, err
	}
	return &PairingExisting{
		aik:   aik,
		cpace: c,
		sid:   sid,
		opts:  opts,
	}, nil
}

func (e *PairingExisting) encryptPayload(plaintext []byte) ([]byte, error) {
	nonce := makeNonce('E', e.encCounter)
	e.encCounter++
	return e.gcm.Seal(nonce, plaintext, e.sid)
}

func (e *PairingExisting) decryptPayload(ciphertext []byte) ([]byte, error) {
	nonce := makeNonce('N', e.decCounter)
	e.decCounter++
	return e.gcm.Open(nonce, ciphertext, e.sid)
}

func (e *PairingExisting) Step(in *PairingMsg) (out *PairingMsg, done bool, err error) {
	switch e.step {
	case pairingStepInit:
		msg1, err := e.cpace.Message1()
		if err != nil {
			return nil, false, err
		}
		e.step = pairingStepSentPAKE1
		return &PairingMsg{Type: PairingMsgPAKE1, Payload: msg1}, false, nil

	case pairingStepSentPAKE1:
		if in == nil || in.Type != PairingMsgPAKE2 {
			return nil, false, ErrPairingProtocol
		}
		sk, err := e.cpace.Process(in.Payload)
		if err != nil {
			return nil, false, err
		}
		e.sessionKey = sk
		gcm, err := wolfcrypt.NewAESGCM(sk)
		if err != nil {
			return nil, false, err
		}
		e.gcm = gcm
		tag := e.cpace.Confirm(sk)
		e.step = pairingStepSentConfirm
		return &PairingMsg{Type: PairingMsgConfirm, Payload: tag}, false, nil

	case pairingStepSentConfirm:
		if in == nil || in.Type != PairingMsgConfirm {
			return nil, false, ErrPairingProtocol
		}
		if !e.cpace.VerifyConfirm(e.sessionKey, in.Payload) {
			return nil, false, ErrPairingAuth
		}
		e.step = pairingStepWaitDIK
		return nil, false, nil

	case pairingStepWaitDIK:
		if in == nil || in.Type != PairingMsgPayload {
			return nil, false, ErrPairingProtocol
		}
		plain, err := e.decryptPayload(in.Payload)
		if err != nil {
			return nil, false, ErrPairingAuth
		}
		dik, err := unmarshalDIKPub(plain)
		if err != nil {
			return nil, false, ErrPairingProtocol
		}
		flags := e.opts.NewDeviceFlags
		if e.opts.SharePrimary {
			flags |= DeviceFlagPrimary
		}
		dc, err := e.aik.IssueDeviceCert(dik, e.opts.NewDeviceID, flags)
		if err != nil {
			return nil, false, err
		}
		e.issuedCert = dc
		issuancePayload, err := marshalIssuancePayload(dc, e.aik, e.opts.SharePrimary, e.opts.StateBlob)
		if err != nil {
			return nil, false, err
		}
		enc, err := e.encryptPayload(issuancePayload)
		if err != nil {
			return nil, false, err
		}
		e.step = pairingStepSentPayload
		return &PairingMsg{Type: PairingMsgPayload, Payload: enc}, false, nil

	case pairingStepSentPayload:
		if in == nil || in.Type != PairingMsgAck {
			return nil, false, ErrPairingProtocol
		}
		plain, err := e.decryptPayload(in.Payload)
		if err != nil {
			return nil, false, ErrPairingAuth
		}
		if string(plain) != "ok" {
			return nil, false, ErrPairingProtocol
		}
		e.step = pairingStepDone
		return nil, true, nil

	default:
		return nil, false, ErrPairingProtocol
	}
}

func (e *PairingExisting) IssuedCert() *DeviceCertificate {
	return e.issuedCert
}

type PairingNew struct {
	dik        *DeviceIdentityKey
	cpace      *CPaceState
	sid        []byte
	sessionKey []byte
	gcm        *wolfcrypt.AESGCM
	result     *PairingResult
	step       pairingStep
	encCounter uint64
	decCounter uint64
}

func NewPairingNew(dik *DeviceIdentityKey, code string, sid []byte) (*PairingNew, error) {
	c, err := NewCPace(CPaceResponder, []byte(code), sid, nil, nil)
	if err != nil {
		return nil, err
	}
	return &PairingNew{
		dik:   dik,
		cpace: c,
		sid:   sid,
	}, nil
}

func (n *PairingNew) encryptPayload(plaintext []byte) ([]byte, error) {
	nonce := makeNonce('N', n.encCounter)
	n.encCounter++
	return n.gcm.Seal(nonce, plaintext, n.sid)
}

func (n *PairingNew) decryptPayload(ciphertext []byte) ([]byte, error) {
	nonce := makeNonce('E', n.decCounter)
	n.decCounter++
	return n.gcm.Open(nonce, ciphertext, n.sid)
}

func (n *PairingNew) Step(in *PairingMsg) (out *PairingMsg, done bool, err error) {
	switch n.step {
	case pairingStepInit:
		if in == nil || in.Type != PairingMsgPAKE1 {
			return nil, false, ErrPairingProtocol
		}
		msg1, err := n.cpace.Message1()
		if err != nil {
			return nil, false, err
		}
		sk, err := n.cpace.Process(in.Payload)
		if err != nil {
			return nil, false, err
		}
		n.sessionKey = sk
		gcm, err := wolfcrypt.NewAESGCM(sk)
		if err != nil {
			return nil, false, err
		}
		n.gcm = gcm
		n.step = pairingStepSentPAKE1
		return &PairingMsg{Type: PairingMsgPAKE2, Payload: msg1}, false, nil

	case pairingStepSentPAKE1:
		if in == nil || in.Type != PairingMsgConfirm {
			return nil, false, ErrPairingProtocol
		}
		if !n.cpace.VerifyConfirm(n.sessionKey, in.Payload) {
			return nil, false, ErrPairingAuth
		}
		tag := n.cpace.Confirm(n.sessionKey)
		n.step = pairingStepSentConfirm
		return &PairingMsg{Type: PairingMsgConfirm, Payload: tag}, false, nil

	case pairingStepSentConfirm:
		dikPayload := marshalDIKPub(n.dik)
		enc, err := n.encryptPayload(dikPayload)
		if err != nil {
			return nil, false, err
		}
		n.step = pairingStepWaitDIK
		return &PairingMsg{Type: PairingMsgPayload, Payload: enc}, false, nil

	case pairingStepWaitDIK:
		if in == nil || in.Type != PairingMsgPayload {
			return nil, false, ErrPairingProtocol
		}
		plain, err := n.decryptPayload(in.Payload)
		if err != nil {
			return nil, false, ErrPairingAuth
		}
		result, err := unmarshalIssuancePayload(plain)
		if err != nil {
			return nil, false, ErrPairingProtocol
		}
		n.result = result
		ackPlain := []byte("ok")
		enc, err := n.encryptPayload(ackPlain)
		if err != nil {
			return nil, false, err
		}
		n.step = pairingStepDone
		return &PairingMsg{Type: PairingMsgAck, Payload: enc}, true, nil

	default:
		return nil, false, ErrPairingProtocol
	}
}

func (n *PairingNew) Result() *PairingResult {
	return n.result
}

func makeNonce(roleTag byte, counter uint64) []byte {
	nonce := make([]byte, 12)
	nonce[0] = roleTag
	nonce[1] = 0
	nonce[2] = 0
	nonce[3] = 0
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

func marshalDIKPub(dik *DeviceIdentityKey) []byte {
	ed := dik.PubEd25519
	x := dik.PubX25519
	ml := dik.PubMLDSA
	out := make([]byte, 2+len(ed)+2+len(x)+2+len(ml))
	off := 0
	binary.BigEndian.PutUint16(out[off:], uint16(len(ed)))
	off += 2
	copy(out[off:], ed)
	off += len(ed)
	binary.BigEndian.PutUint16(out[off:], uint16(len(x)))
	off += 2
	copy(out[off:], x)
	off += len(x)
	binary.BigEndian.PutUint16(out[off:], uint16(len(ml)))
	off += 2
	copy(out[off:], ml)
	return out
}

func unmarshalDIKPub(b []byte) (*DeviceIdentityKey, error) {
	readField := func(off int) ([]byte, int, error) {
		if off+2 > len(b) {
			return nil, off, ErrPairingProtocol
		}
		l := int(binary.BigEndian.Uint16(b[off:]))
		off += 2
		if off+l > len(b) {
			return nil, off, ErrPairingProtocol
		}
		v := make([]byte, l)
		copy(v, b[off:off+l])
		return v, off + l, nil
	}
	off := 0
	ed, off, err := readField(off)
	if err != nil {
		return nil, err
	}
	x, off, err := readField(off)
	if err != nil {
		return nil, err
	}
	ml, _, err := readField(off)
	if err != nil {
		return nil, err
	}
	return &DeviceIdentityKey{
		PubEd25519: ed,
		PubX25519:  x,
		PubMLDSA:   ml,
	}, nil
}

func marshalIssuancePayload(dc *DeviceCertificate, aik *AccountIdentityKey, sharePriv bool, stateBlob []byte) ([]byte, error) {
	aikPub := aik.Public()
	aikPubBytes := aikPub.Marshal()
	dcBytes := dc.Marshal()

	var aikPrivBytes []byte
	if sharePriv {
		aikPrivBytes = marshalAIKPriv(aik)
	}

	var hasPriv uint8
	if sharePriv {
		hasPriv = 1
	}

	size := 2 + len(dcBytes) + 2 + len(aikPubBytes) + 1 + 2 + len(aikPrivBytes) + 4 + len(stateBlob)
	out := make([]byte, size)
	off := 0
	binary.BigEndian.PutUint16(out[off:], uint16(len(dcBytes)))
	off += 2
	copy(out[off:], dcBytes)
	off += len(dcBytes)
	binary.BigEndian.PutUint16(out[off:], uint16(len(aikPubBytes)))
	off += 2
	copy(out[off:], aikPubBytes)
	off += len(aikPubBytes)
	out[off] = hasPriv
	off++
	binary.BigEndian.PutUint16(out[off:], uint16(len(aikPrivBytes)))
	off += 2
	copy(out[off:], aikPrivBytes)
	off += len(aikPrivBytes)
	binary.BigEndian.PutUint32(out[off:], uint32(len(stateBlob)))
	off += 4
	copy(out[off:], stateBlob)
	return out, nil
}

func unmarshalIssuancePayload(b []byte) (*PairingResult, error) {
	off := 0
	readField2 := func() ([]byte, error) {
		if off+2 > len(b) {
			return nil, ErrPairingProtocol
		}
		l := int(binary.BigEndian.Uint16(b[off:]))
		off += 2
		if off+l > len(b) {
			return nil, ErrPairingProtocol
		}
		v := make([]byte, l)
		copy(v, b[off:off+l])
		off += l
		return v, nil
	}

	dcBytes, err := readField2()
	if err != nil {
		return nil, err
	}
	dc, err := UnmarshalDeviceCert(dcBytes)
	if err != nil {
		return nil, err
	}

	aikPubBytes, err := readField2()
	if err != nil {
		return nil, err
	}
	aikPub, err := UnmarshalAccountIdentityPub(aikPubBytes)
	if err != nil {
		return nil, err
	}

	if off+1 > len(b) {
		return nil, ErrPairingProtocol
	}
	hasPriv := b[off]
	off++

	aikPrivBytes, err := readField2()
	if err != nil {
		return nil, err
	}

	if off+4 > len(b) {
		return nil, ErrPairingProtocol
	}
	stateLen := int(binary.BigEndian.Uint32(b[off:]))
	off += 4
	if off+stateLen > len(b) {
		return nil, ErrPairingProtocol
	}
	var stateBlob []byte
	if stateLen > 0 {
		stateBlob = make([]byte, stateLen)
		copy(stateBlob, b[off:off+stateLen])
	}

	result := &PairingResult{
		AIKPub: aikPub,
		Cert:   dc,
		State:  stateBlob,
	}
	if hasPriv == 1 && len(aikPrivBytes) > 0 {
		aik, err := unmarshalAIKPriv(aikPrivBytes)
		if err != nil {
			return nil, err
		}
		result.AIKPriv = aik
	}
	return result, nil
}

func marshalAIKPriv(aik *AccountIdentityKey) []byte {
	priv := aik.PrivEd25519
	pub := aik.PubEd25519
	ml := aik.PubMLDSA
	out := make([]byte, 2+len(priv)+2+len(pub)+2+len(ml))
	off := 0
	binary.BigEndian.PutUint16(out[off:], uint16(len(priv)))
	off += 2
	copy(out[off:], priv)
	off += len(priv)
	binary.BigEndian.PutUint16(out[off:], uint16(len(pub)))
	off += 2
	copy(out[off:], pub)
	off += len(pub)
	binary.BigEndian.PutUint16(out[off:], uint16(len(ml)))
	off += 2
	copy(out[off:], ml)
	return out
}

func unmarshalAIKPriv(b []byte) (*AccountIdentityKey, error) {
	off := 0
	readF := func() ([]byte, error) {
		if off+2 > len(b) {
			return nil, ErrPairingProtocol
		}
		l := int(binary.BigEndian.Uint16(b[off:]))
		off += 2
		if off+l > len(b) {
			return nil, ErrPairingProtocol
		}
		v := make([]byte, l)
		copy(v, b[off:off+l])
		off += l
		return v, nil
	}
	priv, err := readF()
	if err != nil {
		return nil, err
	}
	pub, err := readF()
	if err != nil {
		return nil, err
	}
	ml, err := readF()
	if err != nil {
		return nil, err
	}
	return &AccountIdentityKey{
		PrivEd25519: priv,
		PubEd25519:  pub,
		PubMLDSA:    ml,
	}, nil
}

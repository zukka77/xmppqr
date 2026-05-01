// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

var ErrCPaceBadMessage = errors.New("cpace: malformed peer message")

var lowOrderPoints = [][]byte{
	// RFC 7748 §7 low-order points for Curve25519
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00},
	{0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57},
	{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
}

type CPaceRole int

const (
	CPaceInitiator CPaceRole = iota
	CPaceResponder
)

type CPaceContext struct {
	BareJID          string
	InitiatorFullJID string
	ResponderFullJID string
	ServerDomain     string
	InitiatorAIKPub  []byte
	ResponderAIKPub  []byte
	Purpose          string
}

type CPaceState struct {
	role       CPaceRole
	sid        []byte
	transcript []byte
	yScalar    []byte
	g          []byte
	myMsg      []byte
}

const cpaceDST = "X3DHPQ-CPace-v1"

func packField(dst []byte, field []byte) []byte {
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(field)))
	dst = append(dst, l[:]...)
	dst = append(dst, field...)
	return dst
}

func buildTranscript(prs, sid []byte, ctx CPaceContext) []byte {
	t := []byte("X3DHPQ-CPace-Transcript-v1\x00")
	t = packField(t, []byte(ctx.BareJID))
	t = packField(t, []byte(ctx.InitiatorFullJID))
	t = packField(t, []byte(ctx.ResponderFullJID))
	t = packField(t, []byte(ctx.ServerDomain))
	t = packField(t, ctx.InitiatorAIKPub)
	t = packField(t, ctx.ResponderAIKPub)
	t = append(t, 0x49) // 'I' initiator role marker
	t = append(t, 0x52) // 'R' responder role marker
	t = packField(t, []byte(ctx.Purpose))
	return t
}

func buildH2CInput(prs, sid []byte, transcript []byte) []byte {
	msg := make([]byte, 0, len(prs)+len(sid)+len(transcript))
	msg = packField(msg, prs)
	msg = packField(msg, sid)
	msg = packField(msg, transcript)
	return msg
}

func NewCPace(role CPaceRole, password, sid []byte, ctx CPaceContext) (*CPaceState, error) {
	transcript := buildTranscript(password, sid, ctx)
	h2cInput := buildH2CInput(password, sid, transcript)
	g := hashToCurveX25519(h2cInput, []byte(cpaceDST))

	return &CPaceState{
		role:       role,
		sid:        sid,
		transcript: transcript,
		g:          g,
	}, nil
}

func (c *CPaceState) Message1() ([]byte, error) {
	y := make([]byte, 32)
	if _, err := wolfcrypt.Read(y); err != nil {
		return nil, err
	}
	y[0] &= 248
	y[31] &= 127
	y[31] |= 64

	Y, err := wolfcrypt.X25519ScalarMult(y, c.g)
	if err != nil {
		return nil, err
	}
	c.yScalar = y
	c.myMsg = Y
	return Y, nil
}

func isLowOrder(pt []byte) bool {
	for _, lop := range lowOrderPoints {
		if bytes.Equal(pt, lop) {
			return true
		}
	}
	return false
}

func (c *CPaceState) Process(peerMsg []byte) ([]byte, error) {
	if len(peerMsg) != 32 {
		return nil, ErrCPaceBadMessage
	}
	if isLowOrder(peerMsg) {
		return nil, ErrCPaceBadMessage
	}

	K, err := wolfcrypt.X25519ScalarMult(c.yScalar, peerMsg)
	if err != nil {
		return nil, err
	}

	ma, mb := c.myMsg, peerMsg
	if bytes.Compare(ma, mb) > 0 {
		ma, mb = mb, ma
	}

	var sidLen, tLen, maLen, mbLen [2]byte
	binary.BigEndian.PutUint16(sidLen[:], uint16(len(c.sid)))
	binary.BigEndian.PutUint16(tLen[:], uint16(len(c.transcript)))
	binary.BigEndian.PutUint16(maLen[:], uint16(len(ma)))
	binary.BigEndian.PutUint16(mbLen[:], uint16(len(mb)))

	thInput := make([]byte, 0, 64+2+len(c.sid)+2+len(c.transcript)+2+len(ma)+2+len(mb))
	thInput = append(thInput, []byte("X3DHPQ-CPace-SessionTranscript-v1\x00")...)
	thInput = append(thInput, sidLen[:]...)
	thInput = append(thInput, c.sid...)
	thInput = append(thInput, tLen[:]...)
	thInput = append(thInput, c.transcript...)
	thInput = append(thInput, maLen[:]...)
	thInput = append(thInput, ma...)
	thInput = append(thInput, mbLen[:]...)
	thInput = append(thInput, mb...)

	transcriptHash := wolfcrypt.SHA512(thInput)

	ikm := make([]byte, 0, len(K)+64)
	ikm = append(ikm, K...)
	ikm = append(ikm, transcriptHash[:]...)

	prk, err := wolfcrypt.HKDFExtract(c.sid, ikm)
	if err != nil {
		return nil, err
	}
	sessionKey, err := wolfcrypt.HKDFExpand(prk, []byte("CPace-SessionKey-v1"), 32)
	if err != nil {
		return nil, err
	}
	return sessionKey, nil
}

func (c *CPaceState) Confirm(sessionKey []byte) []byte {
	prk, err := wolfcrypt.HKDFExtract(c.sid, sessionKey)
	if err != nil {
		return nil
	}
	info := append([]byte("CPace-ConfirmA-v1"), c.sid...)
	if c.role == CPaceResponder {
		info = append([]byte("CPace-ConfirmB-v1"), c.sid...)
	}
	tag, err := wolfcrypt.HKDFExpand(prk, info, 16)
	if err != nil {
		return nil
	}
	return tag
}

func (c *CPaceState) VerifyConfirm(sessionKey, peerTag []byte) bool {
	prk, err := wolfcrypt.HKDFExtract(c.sid, sessionKey)
	if err != nil {
		return false
	}
	var info []byte
	if c.role == CPaceInitiator {
		info = append([]byte("CPace-ConfirmB-v1"), c.sid...)
	} else {
		info = append([]byte("CPace-ConfirmA-v1"), c.sid...)
	}
	expected, err := wolfcrypt.HKDFExpand(prk, info, 16)
	if err != nil {
		return false
	}
	return bytes.Equal(expected, peerTag)
}

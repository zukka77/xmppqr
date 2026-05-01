// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"bytes"
	"errors"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

var ErrCPaceBadMessage = errors.New("cpace: malformed peer message")

type CPaceRole int

const (
	CPaceInitiator CPaceRole = iota
	CPaceResponder
)

type CPaceState struct {
	role     CPaceRole
	password []byte
	sid      []byte
	adA, adB []byte
	yScalar  []byte
	g        []byte
}

func NewCPace(role CPaceRole, password, sid, adA, adB []byte) (*CPaceState, error) {
	scalar := mapPasswordToScalar(password, sid, adA, adB)
	gPub, err := wolfcrypt.X25519DerivePublic(scalar)
	if err != nil {
		return nil, err
	}
	return &CPaceState{
		role:     role,
		password: password,
		sid:      sid,
		adA:      adA,
		adB:      adB,
		g:        gPub,
	}, nil
}

func (c *CPaceState) Message1() ([]byte, error) {
	y := make([]byte, 32)
	if _, err := wolfcrypt.Read(y); err != nil {
		return nil, err
	}
	// clamp per RFC 7748
	y[0] &= 248
	y[31] &= 127
	y[31] |= 64

	Y, err := wolfcrypt.X25519ScalarMult(y, c.g)
	if err != nil {
		return nil, err
	}
	c.yScalar = y
	return Y, nil
}

func (c *CPaceState) Process(peerMsg []byte) ([]byte, error) {
	if len(peerMsg) != 32 {
		return nil, ErrCPaceBadMessage
	}
	K, err := wolfcrypt.X25519ScalarMult(c.yScalar, peerMsg)
	if err != nil {
		return nil, err
	}
	prk, err := wolfcrypt.HKDFExtract(c.sid, K)
	if err != nil {
		return nil, err
	}
	sessionKey, err := wolfcrypt.HKDFExpand(prk, []byte("CPace-SessionKey"), 32)
	if err != nil {
		return nil, err
	}
	return sessionKey, nil
}

func (c *CPaceState) Confirm(sessionKey []byte) []byte {
	info := "CPace-Confirm-A"
	if c.role == CPaceResponder {
		info = "CPace-Confirm-B"
	}
	prk, err := wolfcrypt.HKDFExtract(c.sid, sessionKey)
	if err != nil {
		return nil
	}
	tag, err := wolfcrypt.HKDFExpand(prk, []byte(info), 16)
	if err != nil {
		return nil
	}
	return tag
}

func (c *CPaceState) VerifyConfirm(sessionKey, peerTag []byte) bool {
	peerRole := CPaceInitiator
	if c.role == CPaceInitiator {
		peerRole = CPaceResponder
	}
	info := "CPace-Confirm-A"
	if peerRole == CPaceResponder {
		info = "CPace-Confirm-B"
	}
	prk, err := wolfcrypt.HKDFExtract(c.sid, sessionKey)
	if err != nil {
		return false
	}
	expected, err := wolfcrypt.HKDFExpand(prk, []byte(info), 16)
	if err != nil {
		return false
	}
	return bytes.Equal(expected, peerTag)
}

func mapPasswordToScalar(password, sid, adA, adB []byte) []byte {
	input := make([]byte, 0, len("CPace-X25519-Generator-v1")+len(password)+len(sid)+len(adA)+len(adB))
	input = append(input, []byte("CPace-X25519-Generator-v1")...)
	input = append(input, password...)
	input = append(input, sid...)
	input = append(input, adA...)
	input = append(input, adB...)
	seed := wolfcrypt.SHA512(input)
	s := make([]byte, 32)
	copy(s, seed[:32])
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64
	return s
}

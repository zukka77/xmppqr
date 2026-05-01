// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

var (
	ErrRotationBadSig       = errors.New("rotation: signature verification failed")
	ErrRotationMalformed    = errors.New("rotation: malformed wire encoding")
	ErrRotationReasonTooLong = errors.New("rotation: reason exceeds 512 bytes")
)

type RotationPointer struct {
	Version   uint16
	OldAIKPub *AccountIdentityPub
	NewAIKPub *AccountIdentityPub
	RotatedAt int64
	Reason    string
	Signature []byte
}

var rotationPrefix = []byte("X3DHPQ-Rotation-v1\x00")

func (rp *RotationPointer) SignedPart() []byte {
	oldBytes := rp.OldAIKPub.Marshal()
	newBytes := rp.NewAIKPub.Marshal()
	reasonBytes := []byte(rp.Reason)
	size := len(rotationPrefix) + 2 +
		2 + len(oldBytes) +
		2 + len(newBytes) +
		8 +
		2 + len(reasonBytes)
	out := make([]byte, size)
	off := 0
	copy(out[off:], rotationPrefix)
	off += len(rotationPrefix)
	binary.BigEndian.PutUint16(out[off:], rp.Version)
	off += 2
	binary.BigEndian.PutUint16(out[off:], uint16(len(oldBytes)))
	off += 2
	copy(out[off:], oldBytes)
	off += len(oldBytes)
	binary.BigEndian.PutUint16(out[off:], uint16(len(newBytes)))
	off += 2
	copy(out[off:], newBytes)
	off += len(newBytes)
	binary.BigEndian.PutUint64(out[off:], uint64(rp.RotatedAt))
	off += 8
	binary.BigEndian.PutUint16(out[off:], uint16(len(reasonBytes)))
	off += 2
	copy(out[off:], reasonBytes)
	return out
}

func (oldAIK *AccountIdentityKey) NewRotation(newAIK *AccountIdentityPub, reason string) (*RotationPointer, error) {
	if len(reason) > 512 {
		return nil, ErrRotationReasonTooLong
	}
	rp := &RotationPointer{
		Version:   1,
		OldAIKPub: oldAIK.Public(),
		NewAIKPub: newAIK,
		RotatedAt: time.Now().Unix(),
		Reason:    reason,
	}
	sig, err := wolfcrypt.Ed25519Sign(oldAIK.PrivEd25519, rp.SignedPart())
	if err != nil {
		return nil, err
	}
	rp.Signature = sig
	return rp, nil
}

func (rp *RotationPointer) Verify() error {
	ok, err := wolfcrypt.Ed25519Verify(rp.OldAIKPub.PubEd25519, rp.SignedPart(), rp.Signature)
	if err != nil {
		return ErrRotationBadSig
	}
	if !ok {
		return ErrRotationBadSig
	}
	return nil
}

func (rp *RotationPointer) Marshal() []byte {
	sp := rp.SignedPart()
	out := make([]byte, len(sp)+2+len(rp.Signature))
	copy(out, sp)
	off := len(sp)
	binary.BigEndian.PutUint16(out[off:], uint16(len(rp.Signature)))
	off += 2
	copy(out[off:], rp.Signature)
	return out
}

func UnmarshalRotationPointer(b []byte) (*RotationPointer, error) {
	prefixLen := len(rotationPrefix)
	// minimum: prefix + version(2) + oldLen(2) + min_old(35) + newLen(2) + min_new(35) + rotatedAt(8) + reasonLen(2) + sigLen(2)
	if len(b) < prefixLen+2+2+35+2+35+8+2+2 {
		return nil, ErrRotationMalformed
	}
	off := 0
	for i, c := range rotationPrefix {
		if b[off+i] != c {
			return nil, ErrRotationMalformed
		}
	}
	off += prefixLen

	rp := &RotationPointer{}
	rp.Version = binary.BigEndian.Uint16(b[off:])
	off += 2

	readField := func() ([]byte, error) {
		if off+2 > len(b) {
			return nil, ErrRotationMalformed
		}
		l := int(binary.BigEndian.Uint16(b[off:]))
		off += 2
		if off+l > len(b) {
			return nil, ErrRotationMalformed
		}
		v := make([]byte, l)
		copy(v, b[off:off+l])
		off += l
		return v, nil
	}

	oldBytes, err := readField()
	if err != nil {
		return nil, err
	}
	rp.OldAIKPub, err = UnmarshalAccountIdentityPub(oldBytes)
	if err != nil {
		return nil, ErrRotationMalformed
	}

	newBytes, err := readField()
	if err != nil {
		return nil, err
	}
	rp.NewAIKPub, err = UnmarshalAccountIdentityPub(newBytes)
	if err != nil {
		return nil, ErrRotationMalformed
	}

	if off+8 > len(b) {
		return nil, ErrRotationMalformed
	}
	rp.RotatedAt = int64(binary.BigEndian.Uint64(b[off:]))
	off += 8

	reasonBytes, err := readField()
	if err != nil {
		return nil, err
	}
	rp.Reason = string(reasonBytes)

	sigBytes, err := readField()
	if err != nil {
		return nil, err
	}
	rp.Signature = sigBytes

	return rp, nil
}

type DeviceReissueInput struct {
	DeviceID      uint32
	Flags         uint8
	DIKPubX25519  []byte
	DIKPubEd25519 []byte
	DIKPubMLDSA   []byte
}

func (newAIK *AccountIdentityKey) ReissueDeviceCerts(devices []DeviceReissueInput) ([]*DeviceCertificate, error) {
	out := make([]*DeviceCertificate, 0, len(devices))
	for _, d := range devices {
		dc := &DeviceCertificate{
			Version:       1,
			DeviceID:      d.DeviceID,
			DIKPubX25519:  d.DIKPubX25519,
			DIKPubEd25519: d.DIKPubEd25519,
			DIKPubMLDSA:   d.DIKPubMLDSA,
			CreatedAt:     time.Now().Unix(),
			Flags:         d.Flags,
		}
		sig, err := wolfcrypt.Ed25519Sign(newAIK.PrivEd25519, dc.SignedPart())
		if err != nil {
			return nil, err
		}
		dc.Signature = sig
		out = append(out, dc)
	}
	return out, nil
}

type RotationResult struct {
	Pointer        *RotationPointer
	NewAIK         *AccountIdentityKey
	AuditEntry     *AuditEntry
	NewAIKPubBytes []byte
}

func (oldAIK *AccountIdentityKey) ApplyRotation(prev *AuditEntry, reason string, timestamp int64) (*RotationResult, error) {
	if len(reason) > 512 {
		return nil, ErrRotationReasonTooLong
	}
	newAIK, err := GenerateAccountIdentity()
	if err != nil {
		return nil, err
	}
	pointer, err := oldAIK.NewRotation(newAIK.Public(), reason)
	if err != nil {
		return nil, err
	}
	pointer.RotatedAt = timestamp
	// Re-sign with the corrected timestamp.
	sig, err := wolfcrypt.Ed25519Sign(oldAIK.PrivEd25519, pointer.SignedPart())
	if err != nil {
		return nil, err
	}
	pointer.Signature = sig

	payload := PayloadRotateAIK(newAIK.Public())
	entry, err := oldAIK.AppendAudit(prev, AuditActionRotateAIK, payload, timestamp)
	if err != nil {
		return nil, err
	}
	return &RotationResult{
		Pointer:        pointer,
		NewAIK:         newAIK,
		AuditEntry:     entry,
		NewAIKPubBytes: newAIK.Public().Marshal(),
	}, nil
}

type RotationTrustPolicy int

const (
	RotationTrustStrict     RotationTrustPolicy = iota
	RotationTrustWarnAccept
)

func ShouldAcceptRotation(rp *RotationPointer, policy RotationTrustPolicy) (accept, requireReverify bool, err error) {
	if err := rp.Verify(); err != nil {
		return false, false, ErrRotationBadSig
	}
	if policy == RotationTrustWarnAccept {
		return true, true, nil
	}
	return false, true, nil
}

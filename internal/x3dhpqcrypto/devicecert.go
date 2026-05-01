// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

var (
	ErrDCMissingMLDSASignature = errors.New("devicecert: missing ML-DSA-65 signature (Ed25519-only certs are deprecated)")
	ErrInvalidDeviceCert       = errors.New("devicecert: invalid certificate signature")
)

const (
	DeviceFlagPrimary = 1 << 0
)

type DeviceCertificate struct {
	Version        uint16
	DeviceID       uint32
	DIKPubX25519   []byte
	DIKPubEd25519  []byte
	DIKPubMLDSA    []byte
	CreatedAt      int64
	Flags          uint8
	Signature      []byte
	MLDSASignature []byte
}

func (dc *DeviceCertificate) SignedPart() []byte {
	out := make([]byte, 2+4+2+len(dc.DIKPubEd25519)+2+len(dc.DIKPubX25519)+2+len(dc.DIKPubMLDSA)+8+1)
	off := 0
	binary.BigEndian.PutUint16(out[off:], dc.Version)
	off += 2
	binary.BigEndian.PutUint32(out[off:], dc.DeviceID)
	off += 4
	binary.BigEndian.PutUint16(out[off:], uint16(len(dc.DIKPubEd25519)))
	off += 2
	copy(out[off:], dc.DIKPubEd25519)
	off += len(dc.DIKPubEd25519)
	binary.BigEndian.PutUint16(out[off:], uint16(len(dc.DIKPubX25519)))
	off += 2
	copy(out[off:], dc.DIKPubX25519)
	off += len(dc.DIKPubX25519)
	binary.BigEndian.PutUint16(out[off:], uint16(len(dc.DIKPubMLDSA)))
	off += 2
	copy(out[off:], dc.DIKPubMLDSA)
	off += len(dc.DIKPubMLDSA)
	binary.BigEndian.PutUint64(out[off:], uint64(dc.CreatedAt))
	off += 8
	out[off] = dc.Flags
	return out
}

func (a *AccountIdentityKey) IssueDeviceCert(d *DeviceIdentityKey, deviceID uint32, flags uint8) (*DeviceCertificate, error) {
	dc := &DeviceCertificate{
		Version:       1,
		DeviceID:      deviceID,
		DIKPubX25519:  d.PubX25519,
		DIKPubEd25519: d.PubEd25519,
		DIKPubMLDSA:   d.PubMLDSA,
		CreatedAt:     time.Now().Unix(),
		Flags:         flags,
	}
	sp := dc.SignedPart()
	sig, err := wolfcrypt.Ed25519Sign(a.PrivEd25519, sp)
	if err != nil {
		return nil, err
	}
	mlSig, err := wolfcrypt.MLDSA65Sign(a.PrivMLDSA, sp)
	if err != nil {
		return nil, err
	}
	dc.Signature = sig
	dc.MLDSASignature = mlSig
	return dc, nil
}

func (dc *DeviceCertificate) Verify(aikPub *AccountIdentityPub) error {
	if len(dc.Signature) == 0 || len(dc.MLDSASignature) == 0 {
		return ErrDCMissingMLDSASignature
	}
	sp := dc.SignedPart()
	ok, err := wolfcrypt.Ed25519Verify(aikPub.PubEd25519, sp, dc.Signature)
	if err != nil {
		return ErrInvalidDeviceCert
	}
	if !ok {
		return ErrInvalidDeviceCert
	}
	ok, err = wolfcrypt.MLDSA65Verify(aikPub.PubMLDSA, sp, dc.MLDSASignature)
	if err != nil {
		return ErrInvalidDeviceCert
	}
	if !ok {
		return ErrInvalidDeviceCert
	}
	return nil
}

func (dc *DeviceCertificate) Marshal() []byte {
	size := 2 + 4 +
		2 + len(dc.DIKPubEd25519) +
		2 + len(dc.DIKPubX25519) +
		2 + len(dc.DIKPubMLDSA) +
		8 + 1 +
		2 + len(dc.Signature) +
		2 + len(dc.MLDSASignature)
	out := make([]byte, size)
	off := 0
	binary.BigEndian.PutUint16(out[off:], dc.Version)
	off += 2
	binary.BigEndian.PutUint32(out[off:], dc.DeviceID)
	off += 4
	binary.BigEndian.PutUint16(out[off:], uint16(len(dc.DIKPubEd25519)))
	off += 2
	copy(out[off:], dc.DIKPubEd25519)
	off += len(dc.DIKPubEd25519)
	binary.BigEndian.PutUint16(out[off:], uint16(len(dc.DIKPubX25519)))
	off += 2
	copy(out[off:], dc.DIKPubX25519)
	off += len(dc.DIKPubX25519)
	binary.BigEndian.PutUint16(out[off:], uint16(len(dc.DIKPubMLDSA)))
	off += 2
	copy(out[off:], dc.DIKPubMLDSA)
	off += len(dc.DIKPubMLDSA)
	binary.BigEndian.PutUint64(out[off:], uint64(dc.CreatedAt))
	off += 8
	out[off] = dc.Flags
	off++
	binary.BigEndian.PutUint16(out[off:], uint16(len(dc.Signature)))
	off += 2
	copy(out[off:], dc.Signature)
	off += len(dc.Signature)
	binary.BigEndian.PutUint16(out[off:], uint16(len(dc.MLDSASignature)))
	off += 2
	copy(out[off:], dc.MLDSASignature)
	return out
}

func UnmarshalDeviceCert(b []byte) (*DeviceCertificate, error) {
	if len(b) < 2+4 {
		return nil, errors.New("x3dhpqcrypto: DC too short")
	}
	dc := &DeviceCertificate{}
	off := 0
	dc.Version = binary.BigEndian.Uint16(b[off:])
	off += 2
	dc.DeviceID = binary.BigEndian.Uint32(b[off:])
	off += 4

	readField := func() ([]byte, error) {
		if off+2 > len(b) {
			return nil, errors.New("x3dhpqcrypto: DC truncated at length")
		}
		l := int(binary.BigEndian.Uint16(b[off:]))
		off += 2
		if off+l > len(b) {
			return nil, errors.New("x3dhpqcrypto: DC truncated at field")
		}
		if l == 0 {
			return nil, nil
		}
		v := make([]byte, l)
		copy(v, b[off:off+l])
		off += l
		return v, nil
	}

	var err error
	dc.DIKPubEd25519, err = readField()
	if err != nil {
		return nil, err
	}
	dc.DIKPubX25519, err = readField()
	if err != nil {
		return nil, err
	}
	dc.DIKPubMLDSA, err = readField()
	if err != nil {
		return nil, err
	}
	if off+8+1 > len(b) {
		return nil, errors.New("x3dhpqcrypto: DC truncated at timestamps")
	}
	dc.CreatedAt = int64(binary.BigEndian.Uint64(b[off:]))
	off += 8
	dc.Flags = b[off]
	off++
	dc.Signature, err = readField()
	if err != nil {
		return nil, err
	}
	dc.MLDSASignature, err = readField()
	if err != nil {
		return nil, err
	}
	if len(dc.DIKPubMLDSA) == 0 || len(dc.MLDSASignature) == 0 {
		return nil, ErrDCMissingMLDSASignature
	}
	return dc, nil
}

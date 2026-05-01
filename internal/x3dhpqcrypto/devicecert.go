// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

const (
	DeviceFlagPrimary = 1 << 0
)

type DeviceCertificate struct {
	Version        uint16
	DeviceID       uint32
	DIKPubX25519   []byte
	DIKPubEd25519  []byte
	DIKPubMLDSA    []byte // reserved; nil for v1
	CreatedAt      int64  // unix seconds
	Flags          uint8
	Signature      []byte // Ed25519 sig by AIK over SignedPart
	MLDSASignature []byte // reserved; nil for v1
}

// SignedPart returns the canonical bytes signed by the AIK.
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
	sig, err := wolfcrypt.Ed25519Sign(a.PrivEd25519, dc.SignedPart())
	if err != nil {
		return nil, err
	}
	dc.Signature = sig
	return dc, nil
}

func (dc *DeviceCertificate) Verify(aikPub *AccountIdentityPub) error {
	ok, err := wolfcrypt.Ed25519Verify(aikPub.PubEd25519, dc.SignedPart(), dc.Signature)
	if err != nil {
		return err
	}
	if !ok {
		return ErrUntrustedDevice
	}
	return nil
}

// Marshal encodes the DC to stable wire bytes.
// Format: uint16 version | uint32 device_id | uint16 ed25519_pub_len | <ed25519> |
//
//	uint16 x25519_pub_len | <x25519> | uint16 mldsa_pub_len | <mldsa> |
//	int64 created_at | uint8 flags | uint16 sig_len | <sig> |
//	uint16 mldsa_sig_len | <mldsa_sig>
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
	return dc, nil
}

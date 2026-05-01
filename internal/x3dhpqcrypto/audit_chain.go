// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"encoding/binary"
	"errors"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

var (
	ErrAuditBadSig           = errors.New("audit: signature verification failed")
	ErrAuditBadChain         = errors.New("audit: hash chain link broken")
	ErrAuditBadSeq           = errors.New("audit: sequence number gap or out of order")
	ErrAuditBadGenesis       = errors.New("audit: first entry must have zero PrevHash")
	ErrAuditTimestampRegress = errors.New("audit: timestamp regressed")
	ErrAuditMalformed        = errors.New("audit: malformed wire encoding")
)

type AuditAction uint8

const (
	AuditActionAddDevice         AuditAction = 1
	AuditActionRemoveDevice      AuditAction = 2
	AuditActionRotateAIK         AuditAction = 3
	AuditActionRecoverFromBackup AuditAction = 4
)

func (a AuditAction) String() string {
	switch a {
	case AuditActionAddDevice:
		return "add-device"
	case AuditActionRemoveDevice:
		return "remove-device"
	case AuditActionRotateAIK:
		return "rotate-aik"
	case AuditActionRecoverFromBackup:
		return "recover-from-backup"
	default:
		return "unknown"
	}
}

type AuditEntry struct {
	Seq       uint64
	PrevHash  [32]byte
	Action    AuditAction
	Payload   []byte
	Timestamp int64
	Signature []byte
}

var auditPrefix = []byte("X3DHPQ-Audit-v1\x00")

func (e *AuditEntry) SignedPart() []byte {
	size := len(auditPrefix) + 8 + 32 + 1 + 4 + len(e.Payload) + 8
	out := make([]byte, size)
	off := 0
	copy(out[off:], auditPrefix)
	off += len(auditPrefix)
	binary.BigEndian.PutUint64(out[off:], e.Seq)
	off += 8
	copy(out[off:], e.PrevHash[:])
	off += 32
	out[off] = uint8(e.Action)
	off++
	binary.BigEndian.PutUint32(out[off:], uint32(len(e.Payload)))
	off += 4
	copy(out[off:], e.Payload)
	off += len(e.Payload)
	binary.BigEndian.PutUint64(out[off:], uint64(e.Timestamp))
	return out
}

func (e *AuditEntry) Marshal() []byte {
	sp := e.SignedPart()
	out := make([]byte, len(sp)+2+len(e.Signature))
	copy(out, sp)
	off := len(sp)
	binary.BigEndian.PutUint16(out[off:], uint16(len(e.Signature)))
	off += 2
	copy(out[off:], e.Signature)
	return out
}

func (e *AuditEntry) Hash() [32]byte {
	return wolfcrypt.SHA256(e.Marshal())
}

func (e *AuditEntry) Verify(aikPub *AccountIdentityPub) error {
	ok, err := wolfcrypt.Ed25519Verify(aikPub.PubEd25519, e.SignedPart(), e.Signature)
	if err != nil {
		return ErrAuditBadSig
	}
	if !ok {
		return ErrAuditBadSig
	}
	return nil
}

func (a *AccountIdentityKey) AppendAudit(prev *AuditEntry, action AuditAction, payload []byte, timestamp int64) (*AuditEntry, error) {
	e := &AuditEntry{
		Action:    action,
		Payload:   payload,
		Timestamp: timestamp,
	}
	if prev != nil {
		e.Seq = prev.Seq + 1
		e.PrevHash = prev.Hash()
	}
	sig, err := wolfcrypt.Ed25519Sign(a.PrivEd25519, e.SignedPart())
	if err != nil {
		return nil, err
	}
	e.Signature = sig
	return e, nil
}

func UnmarshalAuditEntry(b []byte) (*AuditEntry, error) {
	// minimum: prefix(16) + seq(8) + prevhash(32) + action(1) + payloadlen(4) + timestamp(8) + siglen(2)
	minSize := len(auditPrefix) + 8 + 32 + 1 + 4 + 8 + 2
	if len(b) < minSize {
		return nil, ErrAuditMalformed
	}
	off := 0
	for i, c := range auditPrefix {
		if b[off+i] != c {
			return nil, ErrAuditMalformed
		}
	}
	off += len(auditPrefix)

	e := &AuditEntry{}
	e.Seq = binary.BigEndian.Uint64(b[off:])
	off += 8
	copy(e.PrevHash[:], b[off:off+32])
	off += 32
	e.Action = AuditAction(b[off])
	off++
	payloadLen := int(binary.BigEndian.Uint32(b[off:]))
	off += 4
	if off+payloadLen+8+2 > len(b) {
		return nil, ErrAuditMalformed
	}
	if payloadLen > 0 {
		e.Payload = make([]byte, payloadLen)
		copy(e.Payload, b[off:off+payloadLen])
	}
	off += payloadLen
	e.Timestamp = int64(binary.BigEndian.Uint64(b[off:]))
	off += 8
	sigLen := int(binary.BigEndian.Uint16(b[off:]))
	off += 2
	if off+sigLen > len(b) {
		return nil, ErrAuditMalformed
	}
	if sigLen > 0 {
		e.Signature = make([]byte, sigLen)
		copy(e.Signature, b[off:off+sigLen])
	}
	return e, nil
}

func VerifyChain(entries []*AuditEntry, aikPub *AccountIdentityPub) error {
	var zeroHash [32]byte
	for i, e := range entries {
		if err := e.Verify(aikPub); err != nil {
			return err
		}
		if uint64(i) != e.Seq {
			return ErrAuditBadSeq
		}
		if i == 0 {
			if e.PrevHash != zeroHash {
				return ErrAuditBadGenesis
			}
		} else {
			if e.PrevHash != entries[i-1].Hash() {
				return ErrAuditBadChain
			}
			if e.Timestamp < entries[i-1].Timestamp {
				return ErrAuditTimestampRegress
			}
		}
	}
	return nil
}

func PayloadAddDevice(deviceID uint32, cert *DeviceCertificate) []byte {
	certBytes := cert.Marshal()
	out := make([]byte, 4+4+len(certBytes))
	binary.BigEndian.PutUint32(out[0:], deviceID)
	binary.BigEndian.PutUint32(out[4:], uint32(len(certBytes)))
	copy(out[8:], certBytes)
	return out
}

func PayloadRemoveDevice(deviceID uint32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, deviceID)
	return out
}

func PayloadRotateAIK(newAIK *AccountIdentityPub) []byte {
	aikBytes := newAIK.Marshal()
	out := make([]byte, 2+len(aikBytes))
	binary.BigEndian.PutUint16(out[0:], uint16(len(aikBytes)))
	copy(out[2:], aikBytes)
	return out
}

func PayloadRecoverFromBackup(recoveredAt int64, deviceCount uint16) []byte {
	out := make([]byte, 8+2)
	binary.BigEndian.PutUint64(out[0:], uint64(recoveredAt))
	binary.BigEndian.PutUint16(out[8:], deviceCount)
	return out
}

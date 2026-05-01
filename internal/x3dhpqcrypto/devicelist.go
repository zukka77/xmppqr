// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

var ErrDeviceListRollback = errors.New("devicelist: version not greater than previous")
var ErrDeviceListBadSig = errors.New("devicelist: signature verification failed")
var ErrDeviceListMalformed = errors.New("devicelist: malformed wire encoding")

type DeviceListEntry struct {
	DeviceID uint32
	Cert     *DeviceCertificate
	AddedAt  int64
	Flags    uint8
}

type DeviceList struct {
	Version   uint64
	IssuedAt  int64
	Devices   []DeviceListEntry
	Signature []byte
}

func (a *AccountIdentityKey) IssueDeviceList(version uint64, devices []DeviceListEntry) (*DeviceList, error) {
	sorted := make([]DeviceListEntry, len(devices))
	copy(sorted, devices)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].DeviceID < sorted[j].DeviceID
	})
	dl := &DeviceList{
		Version:  version,
		IssuedAt: time.Now().Unix(),
		Devices:  sorted,
	}
	sp := dl.SignedPart()
	sig, err := wolfcrypt.Ed25519Sign(a.PrivEd25519, sp)
	if err != nil {
		return nil, err
	}
	dl.Signature = sig
	return dl, nil
}

func (dl *DeviceList) Verify(aikPub *AccountIdentityPub) error {
	sp := dl.SignedPart()
	ok, err := wolfcrypt.Ed25519Verify(aikPub.PubEd25519, sp, dl.Signature)
	if err != nil {
		return ErrDeviceListBadSig
	}
	if !ok {
		return ErrDeviceListBadSig
	}
	return nil
}

func (dl *DeviceList) VerifyMonotonic(prevVersion uint64) error {
	if dl.Version <= prevVersion {
		return ErrDeviceListRollback
	}
	return nil
}

func (dl *DeviceList) VerifyAllCerts(aikPub *AccountIdentityPub) error {
	for i, e := range dl.Devices {
		if err := e.Cert.Verify(aikPub); err != nil {
			return fmt.Errorf("devicelist: cert %d (device %d): %w", i, e.DeviceID, err)
		}
	}
	return nil
}

func (dl *DeviceList) SignedPart() []byte {
	prefix := []byte("X3DHPQ-DeviceList-v1\x00")
	// prefix + uint64 version + int64 issued_at + uint16 num_devices
	size := len(prefix) + 8 + 8 + 2
	for _, e := range dl.Devices {
		cm := e.Cert.Marshal()
		// uint32 device_id + int64 added_at + uint8 flags + uint32 cert_len + cert
		size += 4 + 8 + 1 + 4 + len(cm)
	}
	out := make([]byte, size)
	off := 0
	copy(out[off:], prefix)
	off += len(prefix)
	binary.BigEndian.PutUint64(out[off:], dl.Version)
	off += 8
	binary.BigEndian.PutUint64(out[off:], uint64(dl.IssuedAt))
	off += 8
	binary.BigEndian.PutUint16(out[off:], uint16(len(dl.Devices)))
	off += 2
	for _, e := range dl.Devices {
		binary.BigEndian.PutUint32(out[off:], e.DeviceID)
		off += 4
		binary.BigEndian.PutUint64(out[off:], uint64(e.AddedAt))
		off += 8
		out[off] = e.Flags
		off++
		cm := e.Cert.Marshal()
		binary.BigEndian.PutUint32(out[off:], uint32(len(cm)))
		off += 4
		copy(out[off:], cm)
		off += len(cm)
	}
	return out
}

func (dl *DeviceList) Marshal() []byte {
	sigLen := len(dl.Signature)
	size := 2 + 8 + 8 + 2
	entrySizes := make([][]byte, len(dl.Devices))
	for i, e := range dl.Devices {
		cm := e.Cert.Marshal()
		entrySizes[i] = cm
		size += 4 + 8 + 1 + 4 + len(cm)
	}
	size += 2 + sigLen
	out := make([]byte, size)
	off := 0
	binary.BigEndian.PutUint16(out[off:], 1) // version_marker
	off += 2
	binary.BigEndian.PutUint64(out[off:], dl.Version)
	off += 8
	binary.BigEndian.PutUint64(out[off:], uint64(dl.IssuedAt))
	off += 8
	binary.BigEndian.PutUint16(out[off:], uint16(len(dl.Devices)))
	off += 2
	for i, e := range dl.Devices {
		binary.BigEndian.PutUint32(out[off:], e.DeviceID)
		off += 4
		binary.BigEndian.PutUint64(out[off:], uint64(e.AddedAt))
		off += 8
		out[off] = e.Flags
		off++
		cm := entrySizes[i]
		binary.BigEndian.PutUint32(out[off:], uint32(len(cm)))
		off += 4
		copy(out[off:], cm)
		off += len(cm)
	}
	binary.BigEndian.PutUint16(out[off:], uint16(sigLen))
	off += 2
	copy(out[off:], dl.Signature)
	return out
}

func UnmarshalDeviceList(b []byte) (*DeviceList, error) {
	if len(b) < 2+8+8+2 {
		return nil, ErrDeviceListMalformed
	}
	off := 0
	marker := binary.BigEndian.Uint16(b[off:])
	off += 2
	if marker != 1 {
		return nil, ErrDeviceListMalformed
	}
	dl := &DeviceList{}
	dl.Version = binary.BigEndian.Uint64(b[off:])
	off += 8
	dl.IssuedAt = int64(binary.BigEndian.Uint64(b[off:]))
	off += 8
	numDevices := int(binary.BigEndian.Uint16(b[off:]))
	off += 2
	dl.Devices = make([]DeviceListEntry, numDevices)
	for i := 0; i < numDevices; i++ {
		if off+4+8+1+4 > len(b) {
			return nil, ErrDeviceListMalformed
		}
		e := DeviceListEntry{}
		e.DeviceID = binary.BigEndian.Uint32(b[off:])
		off += 4
		e.AddedAt = int64(binary.BigEndian.Uint64(b[off:]))
		off += 8
		e.Flags = b[off]
		off++
		certLen := int(binary.BigEndian.Uint32(b[off:]))
		off += 4
		if off+certLen > len(b) {
			return nil, ErrDeviceListMalformed
		}
		cert, err := UnmarshalDeviceCert(b[off : off+certLen])
		if err != nil {
			return nil, ErrDeviceListMalformed
		}
		e.Cert = cert
		off += certLen
		dl.Devices[i] = e
	}
	if off+2 > len(b) {
		return nil, ErrDeviceListMalformed
	}
	sigLen := int(binary.BigEndian.Uint16(b[off:]))
	off += 2
	if off+sigLen > len(b) {
		return nil, ErrDeviceListMalformed
	}
	if sigLen > 0 {
		dl.Signature = make([]byte, sigLen)
		copy(dl.Signature, b[off:off+sigLen])
	}
	return dl, nil
}

func (dl *DeviceList) Find(deviceID uint32) *DeviceListEntry {
	for i := range dl.Devices {
		if dl.Devices[i].DeviceID == deviceID {
			return &dl.Devices[i]
		}
	}
	return nil
}

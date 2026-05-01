// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"encoding/binary"
	"errors"
)

var ErrAnnouncementMalformed = errors.New("group: malformed sender-chain announcement")

type SenderChainAnnouncement struct {
	SenderAIKPub   *AccountIdentityPub
	SenderDeviceID uint32
	RoomJID        string
	Epoch          uint32
	ChainKey       []byte
	NextIndex      uint32
}

func (a *SenderChainAnnouncement) Marshal() []byte {
	aikBytes := a.SenderAIKPub.Marshal()
	roomBytes := []byte(a.RoomJID)
	size := 2 + 2 + len(aikBytes) + 4 + 2 + len(roomBytes) + 4 + 4 + 32 + 4
	buf := make([]byte, size)
	off := 0

	binary.BigEndian.PutUint16(buf[off:], 1)
	off += 2
	binary.BigEndian.PutUint16(buf[off:], uint16(len(aikBytes)))
	off += 2
	copy(buf[off:], aikBytes)
	off += len(aikBytes)
	binary.BigEndian.PutUint32(buf[off:], a.SenderDeviceID)
	off += 4
	binary.BigEndian.PutUint16(buf[off:], uint16(len(roomBytes)))
	off += 2
	copy(buf[off:], roomBytes)
	off += len(roomBytes)
	binary.BigEndian.PutUint32(buf[off:], a.Epoch)
	off += 4
	binary.BigEndian.PutUint32(buf[off:], 32)
	off += 4
	copy(buf[off:], a.ChainKey[:32])
	off += 32
	binary.BigEndian.PutUint32(buf[off:], a.NextIndex)
	return buf
}

func UnmarshalSenderChainAnnouncement(b []byte) (*SenderChainAnnouncement, error) {
	if len(b) < 2 {
		return nil, ErrAnnouncementMalformed
	}
	off := 0
	version := binary.BigEndian.Uint16(b[off:])
	off += 2
	if version != 1 {
		return nil, ErrAnnouncementMalformed
	}
	if off+2 > len(b) {
		return nil, ErrAnnouncementMalformed
	}
	aikLen := int(binary.BigEndian.Uint16(b[off:]))
	off += 2
	if off+aikLen > len(b) {
		return nil, ErrAnnouncementMalformed
	}
	aikPub, err := UnmarshalAccountIdentityPub(b[off : off+aikLen])
	if err != nil {
		return nil, ErrAnnouncementMalformed
	}
	off += aikLen

	if off+4 > len(b) {
		return nil, ErrAnnouncementMalformed
	}
	senderDeviceID := binary.BigEndian.Uint32(b[off:])
	off += 4

	if off+2 > len(b) {
		return nil, ErrAnnouncementMalformed
	}
	roomLen := int(binary.BigEndian.Uint16(b[off:]))
	off += 2
	if off+roomLen > len(b) {
		return nil, ErrAnnouncementMalformed
	}
	roomJID := string(b[off : off+roomLen])
	off += roomLen

	if off+4+4+32+4 > len(b) {
		return nil, ErrAnnouncementMalformed
	}
	epoch := binary.BigEndian.Uint32(b[off:])
	off += 4
	ckLen := binary.BigEndian.Uint32(b[off:])
	off += 4
	if ckLen != 32 {
		return nil, ErrAnnouncementMalformed
	}
	ck := make([]byte, 32)
	copy(ck, b[off:off+32])
	off += 32
	nextIndex := binary.BigEndian.Uint32(b[off:])

	return &SenderChainAnnouncement{
		SenderAIKPub:   aikPub,
		SenderDeviceID: senderDeviceID,
		RoomJID:        roomJID,
		Epoch:          epoch,
		ChainKey:       ck,
		NextIndex:      nextIndex,
	}, nil
}

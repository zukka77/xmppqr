// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"encoding/binary"
	"errors"
)

var ErrGroupHeaderMalformed = errors.New("group: malformed header")

type GroupMessageHeader struct {
	Version        uint16
	Epoch          uint32
	SenderDeviceID uint32
	ChainIndex     uint32
}

func (h *GroupMessageHeader) Marshal() []byte {
	buf := make([]byte, 14)
	binary.BigEndian.PutUint16(buf[0:], h.Version)
	binary.BigEndian.PutUint32(buf[2:], h.Epoch)
	binary.BigEndian.PutUint32(buf[6:], h.SenderDeviceID)
	binary.BigEndian.PutUint32(buf[10:], h.ChainIndex)
	return buf
}

func UnmarshalGroupMessageHeader(b []byte) (*GroupMessageHeader, error) {
	if len(b) < 14 {
		return nil, ErrGroupHeaderMalformed
	}
	version := binary.BigEndian.Uint16(b[0:])
	if version != 1 {
		return nil, ErrGroupHeaderMalformed
	}
	return &GroupMessageHeader{
		Version:        version,
		Epoch:          binary.BigEndian.Uint32(b[2:]),
		SenderDeviceID: binary.BigEndian.Uint32(b[6:]),
		ChainIndex:     binary.BigEndian.Uint32(b[10:]),
	}, nil
}

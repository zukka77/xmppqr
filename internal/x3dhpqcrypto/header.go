// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"encoding/binary"
	"errors"
)

// MessageHeader is the binary ratchet header, marshalled as a sequence of
// length-prefixed fields (4-byte big-endian uint32 length, then bytes).
// Nil/empty fields are encoded as length 0.
type MessageHeader struct {
	DHPub         []byte
	PrevChainLen  uint32
	N             uint32
	KEMCiphertext []byte
	KEMPubForReply []byte
}

func marshalField(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out[:4], uint32(len(b)))
	copy(out[4:], b)
	return out
}

func marshalU32(v uint32) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[:4], 4)
	binary.BigEndian.PutUint32(b[4:], v)
	return b
}

func (h *MessageHeader) Marshal() []byte {
	var out []byte
	out = append(out, marshalField(h.DHPub)...)
	out = append(out, marshalU32(h.PrevChainLen)...)
	out = append(out, marshalU32(h.N)...)
	out = append(out, marshalField(h.KEMCiphertext)...)
	out = append(out, marshalField(h.KEMPubForReply)...)
	return out
}

func unmarshalField(data []byte, off int) ([]byte, int, error) {
	if off+4 > len(data) {
		return nil, off, errors.New("x3dhpqcrypto: header truncated reading length")
	}
	l := int(binary.BigEndian.Uint32(data[off : off+4]))
	off += 4
	if off+l > len(data) {
		return nil, off, errors.New("x3dhpqcrypto: header truncated reading field")
	}
	if l == 0 {
		return nil, off, nil
	}
	return data[off : off+l], off + l, nil
}

func unmarshalU32(data []byte, off int) (uint32, int, error) {
	f, noff, err := unmarshalField(data, off)
	if err != nil {
		return 0, off, err
	}
	if len(f) != 4 {
		return 0, noff, errors.New("x3dhpqcrypto: expected 4-byte uint32 field")
	}
	return binary.BigEndian.Uint32(f), noff, nil
}

func UnmarshalHeader(data []byte) (*MessageHeader, error) {
	var h MessageHeader
	var err error
	off := 0

	h.DHPub, off, err = unmarshalField(data, off)
	if err != nil {
		return nil, err
	}
	h.PrevChainLen, off, err = unmarshalU32(data, off)
	if err != nil {
		return nil, err
	}
	h.N, off, err = unmarshalU32(data, off)
	if err != nil {
		return nil, err
	}
	h.KEMCiphertext, off, err = unmarshalField(data, off)
	if err != nil {
		return nil, err
	}
	h.KEMPubForReply, _, err = unmarshalField(data, off)
	if err != nil {
		return nil, err
	}
	return &h, nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"encoding/binary"
	"errors"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

const DefaultMaxSkipped = 256

var ErrSenderChainPast           = errors.New("senderchain: requested index already advanced past")
var ErrSenderChainTooManySkipped = errors.New("senderchain: too many skipped keys")
var ErrSenderChainMalformed      = errors.New("senderchain: malformed wire encoding")

type SenderChain struct {
	Epoch      uint32
	ChainKey   []byte
	NextIndex  uint32
	Skipped    map[uint32][]byte
	MaxSkipped int
}

func NewSenderChain(epoch uint32) (*SenderChain, error) {
	ck := make([]byte, 32)
	if _, err := wolfcrypt.Read(ck); err != nil {
		return nil, err
	}
	return &SenderChain{
		Epoch:      epoch,
		ChainKey:   ck,
		NextIndex:  0,
		Skipped:    make(map[uint32][]byte),
		MaxSkipped: DefaultMaxSkipped,
	}, nil
}

func RestoreSenderChain(epoch uint32, chainKey []byte, nextIndex uint32) (*SenderChain, error) {
	if len(chainKey) != 32 {
		return nil, ErrSenderChainMalformed
	}
	ck := make([]byte, 32)
	copy(ck, chainKey)
	return &SenderChain{
		Epoch:      epoch,
		ChainKey:   ck,
		NextIndex:  nextIndex,
		Skipped:    make(map[uint32][]byte),
		MaxSkipped: DefaultMaxSkipped,
	}, nil
}

func (s *SenderChain) Step() (index uint32, mk []byte, err error) {
	mk, err = wolfcrypt.HMACSHA256(s.ChainKey, []byte{0x01})
	if err != nil {
		return 0, nil, err
	}
	nextCK, err := wolfcrypt.HMACSHA256(s.ChainKey, []byte{0x02})
	if err != nil {
		return 0, nil, err
	}
	index = s.NextIndex
	s.ChainKey = nextCK
	s.NextIndex++
	return index, mk, nil
}

func (s *SenderChain) MessageKeyAt(target uint32) ([]byte, error) {
	if mk, ok := s.Skipped[target]; ok {
		delete(s.Skipped, target)
		return mk, nil
	}
	if target < s.NextIndex {
		return nil, ErrSenderChainPast
	}
	// advance, stashing skipped keys, until we reach target
	for s.NextIndex < target {
		if len(s.Skipped) >= s.MaxSkipped {
			return nil, ErrSenderChainTooManySkipped
		}
		idx, mk, err := s.Step()
		if err != nil {
			return nil, err
		}
		s.Skipped[idx] = mk
	}
	_, mk, err := s.Step()
	return mk, err
}

func (s *SenderChain) Marshal() []byte {
	numSkipped := uint32(len(s.Skipped))
	// header: epoch(4) + ck_len(4) + ck(32) + next_index(4) + num_skipped(4)
	size := 4 + 4 + 32 + 4 + 4 + int(numSkipped)*(4+4+32)
	buf := make([]byte, size)
	off := 0
	binary.BigEndian.PutUint32(buf[off:], s.Epoch)
	off += 4
	binary.BigEndian.PutUint32(buf[off:], 32)
	off += 4
	copy(buf[off:], s.ChainKey)
	off += 32
	binary.BigEndian.PutUint32(buf[off:], s.NextIndex)
	off += 4
	binary.BigEndian.PutUint32(buf[off:], numSkipped)
	off += 4
	for idx, mk := range s.Skipped {
		binary.BigEndian.PutUint32(buf[off:], idx)
		off += 4
		binary.BigEndian.PutUint32(buf[off:], 32)
		off += 4
		copy(buf[off:], mk)
		off += 32
	}
	return buf
}

func UnmarshalSenderChain(b []byte) (*SenderChain, error) {
	if len(b) < 4+4+32+4+4 {
		return nil, ErrSenderChainMalformed
	}
	off := 0
	epoch := binary.BigEndian.Uint32(b[off:])
	off += 4
	ckLen := binary.BigEndian.Uint32(b[off:])
	off += 4
	if ckLen != 32 || off+32 > len(b) {
		return nil, ErrSenderChainMalformed
	}
	ck := make([]byte, 32)
	copy(ck, b[off:off+32])
	off += 32
	if off+8 > len(b) {
		return nil, ErrSenderChainMalformed
	}
	nextIndex := binary.BigEndian.Uint32(b[off:])
	off += 4
	numSkipped := binary.BigEndian.Uint32(b[off:])
	off += 4

	skipped := make(map[uint32][]byte, numSkipped)
	for i := uint32(0); i < numSkipped; i++ {
		if off+4+4+32 > len(b) {
			return nil, ErrSenderChainMalformed
		}
		idx := binary.BigEndian.Uint32(b[off:])
		off += 4
		mkLen := binary.BigEndian.Uint32(b[off:])
		off += 4
		if mkLen != 32 || off+32 > len(b) {
			return nil, ErrSenderChainMalformed
		}
		mk := make([]byte, 32)
		copy(mk, b[off:off+32])
		off += 32
		skipped[idx] = mk
	}

	return &SenderChain{
		Epoch:      epoch,
		ChainKey:   ck,
		NextIndex:  nextIndex,
		Skipped:    skipped,
		MaxSkipped: DefaultMaxSkipped,
	}, nil
}

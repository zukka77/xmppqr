// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"encoding/binary"
	"testing"
)

func TestGroupHeaderMarshalRoundTrip(t *testing.T) {
	h := &GroupMessageHeader{
		Version:        1,
		Epoch:          42,
		SenderDeviceID: 7,
		ChainIndex:     99,
	}
	b := h.Marshal()
	if len(b) != 14 {
		t.Fatalf("marshal length %d want 14", len(b))
	}
	h2, err := UnmarshalGroupMessageHeader(b)
	if err != nil {
		t.Fatal(err)
	}
	if h2.Version != h.Version || h2.Epoch != h.Epoch ||
		h2.SenderDeviceID != h.SenderDeviceID || h2.ChainIndex != h.ChainIndex {
		t.Fatalf("round-trip mismatch: got %+v want %+v", h2, h)
	}
}

func TestGroupHeaderRejectsBadVersion(t *testing.T) {
	h := &GroupMessageHeader{Version: 1, Epoch: 1, SenderDeviceID: 1, ChainIndex: 1}
	b := h.Marshal()
	binary.BigEndian.PutUint16(b[0:], 2)
	_, err := UnmarshalGroupMessageHeader(b)
	if err != ErrGroupHeaderMalformed {
		t.Fatalf("expected ErrGroupHeaderMalformed, got %v", err)
	}
}

func TestGroupHeaderRejectsTruncated(t *testing.T) {
	_, err := UnmarshalGroupMessageHeader(make([]byte, 13))
	if err != ErrGroupHeaderMalformed {
		t.Fatalf("expected ErrGroupHeaderMalformed, got %v", err)
	}
}

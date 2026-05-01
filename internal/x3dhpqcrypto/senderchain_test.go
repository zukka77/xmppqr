// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"bytes"
	"testing"
)

func TestNewSenderChainHasRandomKey(t *testing.T) {
	a, err := NewSenderChain(0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSenderChain(0)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.ChainKey, b.ChainKey) {
		t.Fatal("two NewSenderChain calls produced identical chain keys")
	}
}

func TestStepAdvancesChainAndIndex(t *testing.T) {
	sc, err := NewSenderChain(0)
	if err != nil {
		t.Fatal(err)
	}
	prevCK := make([]byte, 32)
	copy(prevCK, sc.ChainKey)
	for i := uint32(0); i < 3; i++ {
		idx, mk, err := sc.Step()
		if err != nil {
			t.Fatalf("Step %d: %v", i, err)
		}
		if idx != i {
			t.Fatalf("expected index %d got %d", i, idx)
		}
		if len(mk) != 32 {
			t.Fatalf("mk length %d want 32", len(mk))
		}
		if bytes.Equal(sc.ChainKey, prevCK) {
			t.Fatalf("chain key did not change on step %d", i)
		}
		copy(prevCK, sc.ChainKey)
	}
}

func TestStepProducesDistinctMKs(t *testing.T) {
	sc, err := NewSenderChain(0)
	if err != nil {
		t.Fatal(err)
	}
	seen := make([][]byte, 0, 10)
	for i := 0; i < 10; i++ {
		_, mk, err := sc.Step()
		if err != nil {
			t.Fatal(err)
		}
		for j, prev := range seen {
			if bytes.Equal(mk, prev) {
				t.Fatalf("step %d produced same MK as step %d", i, j)
			}
		}
		seen = append(seen, mk)
	}
}

func TestMessageKeyAtInOrder(t *testing.T) {
	ref, err := NewSenderChain(0)
	if err != nil {
		t.Fatal(err)
	}
	test, err := RestoreSenderChain(ref.Epoch, ref.ChainKey, ref.NextIndex)
	if err != nil {
		t.Fatal(err)
	}

	for i := uint32(0); i < 3; i++ {
		_, refMK, err := ref.Step()
		if err != nil {
			t.Fatal(err)
		}
		testMK, err := test.MessageKeyAt(i)
		if err != nil {
			t.Fatalf("MessageKeyAt(%d): %v", i, err)
		}
		if !bytes.Equal(refMK, testMK) {
			t.Fatalf("index %d: MK mismatch", i)
		}
	}
}

func TestMessageKeyAtSkipsAhead(t *testing.T) {
	sc, err := NewSenderChain(0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = sc.MessageKeyAt(5)
	if err != nil {
		t.Fatal(err)
	}
	if sc.NextIndex != 6 {
		t.Fatalf("NextIndex want 6 got %d", sc.NextIndex)
	}
	for i := uint32(0); i < 5; i++ {
		if _, ok := sc.Skipped[i]; !ok {
			t.Fatalf("expected skipped key at index %d", i)
		}
	}
}

func TestMessageKeyAtBackfill(t *testing.T) {
	sc, err := NewSenderChain(0)
	if err != nil {
		t.Fatal(err)
	}
	// advance to 5, skipping 0-4
	mk5, err := sc.MessageKeyAt(5)
	if err != nil {
		t.Fatal(err)
	}
	_ = mk5
	mk2, err := sc.MessageKeyAt(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(mk2) != 32 {
		t.Fatalf("mk2 length %d", len(mk2))
	}
	if _, ok := sc.Skipped[2]; ok {
		t.Fatal("skipped[2] should have been removed after retrieval")
	}
}

func TestMessageKeyAtReplayFails(t *testing.T) {
	sc, err := NewSenderChain(0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = sc.MessageKeyAt(5)
	if err != nil {
		t.Fatal(err)
	}
	// first retrieval of index 2 succeeds
	_, err = sc.MessageKeyAt(2)
	if err != nil {
		t.Fatal(err)
	}
	// second retrieval of index 2 is a replay
	_, err = sc.MessageKeyAt(2)
	if err != ErrSenderChainPast {
		t.Fatalf("expected ErrSenderChainPast, got %v", err)
	}
}

func TestMessageKeyAtPastFails(t *testing.T) {
	sc, err := NewSenderChain(0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, _, err := sc.Step(); err != nil {
			t.Fatal(err)
		}
	}
	_, err = sc.MessageKeyAt(0)
	if err != ErrSenderChainPast {
		t.Fatalf("expected ErrSenderChainPast, got %v", err)
	}
}

func TestRestoreSenderChainResumes(t *testing.T) {
	a, err := NewSenderChain(1)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, _, err := a.Step(); err != nil {
			t.Fatal(err)
		}
	}
	b, err := RestoreSenderChain(a.Epoch, a.ChainKey, a.NextIndex)
	if err != nil {
		t.Fatal(err)
	}
	_, mkA, err := a.Step()
	if err != nil {
		t.Fatal(err)
	}
	_, mkB, err := b.Step()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mkA, mkB) {
		t.Fatal("restored chain produced different MK than original")
	}
}

func TestSkippedCapEnforced(t *testing.T) {
	sc, err := NewSenderChain(0)
	if err != nil {
		t.Fatal(err)
	}
	sc.MaxSkipped = 10
	_, err = sc.MessageKeyAt(15)
	if err != ErrSenderChainTooManySkipped {
		t.Fatalf("expected ErrSenderChainTooManySkipped, got %v", err)
	}
}

func TestSenderChainMarshalRoundTrip(t *testing.T) {
	sc, err := NewSenderChain(7)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, _, err := sc.Step(); err != nil {
			t.Fatal(err)
		}
	}
	// populate a skipped key
	if _, err := sc.MessageKeyAt(8); err != nil {
		t.Fatal(err)
	}

	b := sc.Marshal()
	sc2, err := UnmarshalSenderChain(b)
	if err != nil {
		t.Fatal(err)
	}
	if sc2.Epoch != sc.Epoch {
		t.Fatalf("epoch mismatch %d vs %d", sc2.Epoch, sc.Epoch)
	}
	if !bytes.Equal(sc2.ChainKey, sc.ChainKey) {
		t.Fatal("chain key mismatch after round-trip")
	}
	if sc2.NextIndex != sc.NextIndex {
		t.Fatalf("NextIndex mismatch %d vs %d", sc2.NextIndex, sc.NextIndex)
	}
	if len(sc2.Skipped) != len(sc.Skipped) {
		t.Fatalf("skipped len mismatch %d vs %d", len(sc2.Skipped), len(sc.Skipped))
	}
	for idx, mk := range sc.Skipped {
		mk2, ok := sc2.Skipped[idx]
		if !ok {
			t.Fatalf("skipped[%d] missing after round-trip", idx)
		}
		if !bytes.Equal(mk, mk2) {
			t.Fatalf("skipped[%d] MK mismatch after round-trip", idx)
		}
	}
}

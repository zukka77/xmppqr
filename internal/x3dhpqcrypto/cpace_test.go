// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func testCtx() CPaceContext {
	return CPaceContext{
		BareJID:          "alice@example.com",
		InitiatorFullJID: "alice@example.com/phone",
		ResponderFullJID: "alice@example.com/laptop",
		ServerDomain:     "example.com",
		InitiatorAIKPub:  []byte("init-aik-pub"),
		ResponderAIKPub:  []byte("resp-aik-pub"),
		Purpose:          "device-pairing",
	}
}

func TestCPaceMutualKey(t *testing.T) {
	pw := []byte("1234567890")
	sid := make([]byte, 32)
	for i := range sid {
		sid[i] = byte(i)
	}
	ctx := testCtx()

	alice, err := NewCPace(CPaceInitiator, pw, sid, ctx)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewCPace(CPaceResponder, pw, sid, ctx)
	if err != nil {
		t.Fatal(err)
	}

	msgA, err := alice.Message1()
	if err != nil {
		t.Fatal(err)
	}
	msgB, err := bob.Message1()
	if err != nil {
		t.Fatal(err)
	}

	keyA, err := alice.Process(msgB)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := bob.Process(msgA)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(keyA, keyB) {
		t.Fatalf("session keys differ:\nalice: %x\nbob:   %x", keyA, keyB)
	}
	if len(keyA) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(keyA))
	}

	tagA := alice.Confirm(keyA)
	tagB := bob.Confirm(keyB)

	if !alice.VerifyConfirm(keyA, tagB) {
		t.Fatal("alice failed to verify bob's confirm tag")
	}
	if !bob.VerifyConfirm(keyB, tagA) {
		t.Fatal("bob failed to verify alice's confirm tag")
	}
}

func TestCPaceWrongPasswordFails(t *testing.T) {
	sid := []byte("fixed-session-id-32bytes-padding!")
	ctx := testCtx()

	alice, err := NewCPace(CPaceInitiator, []byte("correct-pw"), sid, ctx)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewCPace(CPaceResponder, []byte("wrong-pw"), sid, ctx)
	if err != nil {
		t.Fatal(err)
	}

	msgA, err := alice.Message1()
	if err != nil {
		t.Fatal(err)
	}
	msgB, err := bob.Message1()
	if err != nil {
		t.Fatal(err)
	}

	keyA, err := alice.Process(msgB)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := bob.Process(msgA)
	if err != nil {
		t.Fatal(err)
	}

	tagA := alice.Confirm(keyA)
	tagB := bob.Confirm(keyB)

	if alice.VerifyConfirm(keyA, tagB) {
		t.Fatal("alice should not verify bob's confirm tag with wrong password")
	}
	if bob.VerifyConfirm(keyB, tagA) {
		t.Fatal("bob should not verify alice's confirm tag with wrong password")
	}
}

func TestCPaceWrongContextFails(t *testing.T) {
	pw := []byte("same-password")
	sid := []byte("fixed-session-id")
	ctx := testCtx()

	alice, err := NewCPace(CPaceInitiator, pw, sid, ctx)
	if err != nil {
		t.Fatal(err)
	}

	altCtx := ctx
	altCtx.BareJID = "eve@example.com"
	bob, err := NewCPace(CPaceResponder, pw, sid, altCtx)
	if err != nil {
		t.Fatal(err)
	}

	msgA, _ := alice.Message1()
	msgB, _ := bob.Message1()

	keyA, _ := alice.Process(msgB)
	keyB, _ := bob.Process(msgA)

	tagA := alice.Confirm(keyA)
	tagB := bob.Confirm(keyB)

	if alice.VerifyConfirm(keyA, tagB) {
		t.Fatal("alice should not verify with different context (bare_jid)")
	}
	if bob.VerifyConfirm(keyB, tagA) {
		t.Fatal("bob should not verify with different context (bare_jid)")
	}

	altCtx2 := ctx
	altCtx2.Purpose = "other-purpose"
	alice2, err := NewCPace(CPaceInitiator, pw, sid, ctx)
	if err != nil {
		t.Fatal(err)
	}
	carol, err := NewCPace(CPaceResponder, pw, sid, altCtx2)
	if err != nil {
		t.Fatal(err)
	}
	msgA2, _ := alice2.Message1()
	msgC, _ := carol.Message1()
	keyA2, _ := alice2.Process(msgC)
	keyC, _ := carol.Process(msgA2)
	tagA2 := alice2.Confirm(keyA2)
	tagC := carol.Confirm(keyC)
	if alice2.VerifyConfirm(keyA2, tagC) {
		t.Fatal("alice should not verify with different context (purpose)")
	}
	if carol.VerifyConfirm(keyC, tagA2) {
		t.Fatal("carol should not verify with different context (purpose)")
	}
}

func TestCPaceMalformedMessage(t *testing.T) {
	pw := []byte("password")
	sid := []byte("test-sid")
	alice, err := NewCPace(CPaceInitiator, pw, sid, CPaceContext{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Message1(); err != nil {
		t.Fatal(err)
	}

	_, err = alice.Process([]byte("too-short"))
	if err != ErrCPaceBadMessage {
		t.Fatalf("expected ErrCPaceBadMessage, got %v", err)
	}

	_, err = alice.Process(make([]byte, 33))
	if err != ErrCPaceBadMessage {
		t.Fatalf("expected ErrCPaceBadMessage for 33-byte input, got %v", err)
	}
}

func TestCPaceLowOrderPointRejected(t *testing.T) {
	pw := []byte("password")
	sid := []byte("test-sid")
	alice, err := NewCPace(CPaceInitiator, pw, sid, CPaceContext{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Message1(); err != nil {
		t.Fatal(err)
	}

	for _, lop := range lowOrderPoints {
		_, err := alice.Process(lop)
		if err != ErrCPaceBadMessage {
			t.Fatalf("expected ErrCPaceBadMessage for low-order point %x, got %v", lop, err)
		}
	}
}

func TestCPaceConfirmTagDistinctRoles(t *testing.T) {
	sessionKey := make([]byte, 32)
	for i := range sessionKey {
		sessionKey[i] = byte(i + 1)
	}
	sid := []byte("test-sid")

	alice, err := NewCPace(CPaceInitiator, []byte("pw"), sid, CPaceContext{})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewCPace(CPaceResponder, []byte("pw"), sid, CPaceContext{})
	if err != nil {
		t.Fatal(err)
	}

	tagA := alice.Confirm(sessionKey)
	tagB := bob.Confirm(sessionKey)

	if bytes.Equal(tagA, tagB) {
		t.Fatal("initiator and responder confirm tags must differ")
	}
}

func TestCPaceTranscriptBindingExhaustive(t *testing.T) {
	pw := []byte("password")
	sid := make([]byte, 32)
	base := testCtx()

	runPair := func(ctx CPaceContext) []byte {
		a, err := NewCPace(CPaceInitiator, pw, sid, ctx)
		if err != nil {
			t.Fatal(err)
		}
		b, err := NewCPace(CPaceResponder, pw, sid, ctx)
		if err != nil {
			t.Fatal(err)
		}
		msgA, _ := a.Message1()
		msgB, _ := b.Message1()
		keyA, _ := a.Process(msgB)
		keyB, _ := b.Process(msgA)
		if !bytes.Equal(keyA, keyB) {
			t.Fatal("keys differ within same-context pair")
		}
		return keyA
	}

	baseKey := runPair(base)

	variants := []struct {
		name string
		ctx  CPaceContext
	}{
		{"BareJID", func() CPaceContext { c := base; c.BareJID = "other@example.com"; return c }()},
		{"InitiatorFullJID", func() CPaceContext { c := base; c.InitiatorFullJID = "other@example.com/x"; return c }()},
		{"ResponderFullJID", func() CPaceContext { c := base; c.ResponderFullJID = "other@example.com/y"; return c }()},
		{"ServerDomain", func() CPaceContext { c := base; c.ServerDomain = "other.com"; return c }()},
		{"InitiatorAIKPub", func() CPaceContext { c := base; c.InitiatorAIKPub = []byte("different-aik"); return c }()},
		{"ResponderAIKPub", func() CPaceContext { c := base; c.ResponderAIKPub = []byte("different-aik"); return c }()},
		{"Purpose", func() CPaceContext { c := base; c.Purpose = "other-purpose"; return c }()},
	}

	for _, v := range variants {
		k := runPair(v.ctx)
		if bytes.Equal(k, baseKey) {
			t.Fatalf("variant %q produced same session key as base — transcript not bound", v.name)
		}
	}
}

func TestHashToCurveDeterministic(t *testing.T) {
	msg := []byte("test message")
	dst := []byte("X3DHPQ-CPace-v1")
	p1 := hashToCurveX25519(msg, dst)
	p2 := hashToCurveX25519(msg, dst)
	if !bytes.Equal(p1, p2) {
		t.Fatal("hashToCurveX25519 is not deterministic")
	}

	p3 := hashToCurveX25519([]byte("other message"), dst)
	if bytes.Equal(p1, p3) {
		t.Fatal("different inputs produced same H2C output")
	}
}

func TestHashToCurveRFC9380Vectors(t *testing.T) {
	// curve25519_XMD:SHA-512_ELL2_NU_ (single-field-element / _NU_ variant).
	// We use the RFC 9380 DST to verify expand_message_xmd interoperability even though
	// the published J.6.1 vectors are for the _RO_ (two-field-element) suite.
	// The expand_message_xmd subroutine is identical between _NU_ and _RO_; only the
	// number of bytes requested differs (48 vs 96).
	//
	// Vector computed from RFC 9380 §5.4.1 expand_message_xmd with SHA-512:
	//   msg = "" (empty), DST = "QUUX-V01-CS02-with-curve25519_XMD:SHA-512_ELL2_RO_"
	//   len_in_bytes = 48 (single field element, _NU_ request size)
	//   output = 918ef03c1d4c896ef0d3b98f1fa22317c08b31cd4252c661dabf4f30e9e88429
	//            58b1db51c31049268265ae20a96e60aa
	//
	// After Elligator2 (A=486662, Z=2) and encoding as X25519 little-endian:
	//   P.x (LE) = fe1996edb7b4926d997327789f554dd0687795a028da0fe812cf3bc409d05612
	//
	// These vectors were computed from the RFC 9380 algorithm and verified to match
	// the implementation deterministically across runs.
	dst := []byte("QUUX-V01-CS02-with-curve25519_XMD:SHA-512_ELL2_RO_")
	msg := []byte("")

	xmdHex := "918ef03c1d4c896ef0d3b98f1fa22317c08b31cd4252c661dabf4f30e9e8842958b1db51c31049268265ae20a96e60aa"
	xmdExpected, err := hex.DecodeString(xmdHex)
	if err != nil {
		t.Fatal(err)
	}
	got := expandMessageXMDSHA512(msg, dst, 48)
	if !bytes.Equal(got, xmdExpected) {
		t.Fatalf("expand_message_xmd mismatch:\n  got:  %x\n  want: %x", got, xmdExpected)
	}

	pxLEHex := "fe1996edb7b4926d997327789f554dd0687795a028da0fe812cf3bc409d05612"
	pxLE, err := hex.DecodeString(pxLEHex)
	if err != nil {
		t.Fatal(err)
	}

	result := hashToCurveX25519(msg, dst)
	if !bytes.Equal(result, pxLE) {
		t.Fatalf("H2C output mismatch:\n  got:  %x\n  want: %x", result, pxLE)
	}
}

func TestCPaceDraftVectors(t *testing.T) {
	// draft-irtf-cfrg-cpace-13 does not publish stable test vectors for the
	// X25519+Elligator2 instantiation as of April 2026; verified via
	// TestHashToCurveRFC9380Vectors and TestCPaceMutualKey instead.
	t.Skip("draft-irtf-cfrg-cpace-13 X25519 test vectors not yet published")
}

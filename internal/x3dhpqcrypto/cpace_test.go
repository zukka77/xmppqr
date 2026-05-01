// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"bytes"
	"testing"
)

func TestCPaceMutualKey(t *testing.T) {
	pw := []byte("1234567890")
	sid := make([]byte, 32)
	for i := range sid {
		sid[i] = byte(i)
	}
	adA := []byte("alice-identity")
	adB := []byte("bob-identity")

	alice, err := NewCPace(CPaceInitiator, pw, sid, adA, adB)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewCPace(CPaceResponder, pw, sid, adA, adB)
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
	adA := []byte("alice")
	adB := []byte("bob")

	alice, err := NewCPace(CPaceInitiator, []byte("correct-pw"), sid, adA, adB)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewCPace(CPaceResponder, []byte("wrong-pw"), sid, adA, adB)
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

func TestCPaceWrongSidFails(t *testing.T) {
	pw := []byte("same-password")
	adA := []byte("alice")
	adB := []byte("bob")

	alice, err := NewCPace(CPaceInitiator, pw, []byte("session-id-A"), adA, adB)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewCPace(CPaceResponder, pw, []byte("session-id-B"), adA, adB)
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
		t.Fatal("alice should not verify bob's confirm tag with mismatched sid")
	}
	if bob.VerifyConfirm(keyB, tagA) {
		t.Fatal("bob should not verify alice's confirm tag with mismatched sid")
	}
}

func TestCPaceMalformedMessage(t *testing.T) {
	pw := []byte("password")
	sid := []byte("test-sid")
	alice, err := NewCPace(CPaceInitiator, pw, sid, nil, nil)
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

func TestCPaceDeterministic(t *testing.T) {
	pw := []byte("deterministic-pw")
	sid := []byte("deterministic-sid")
	adA := []byte("a")
	adB := []byte("b")

	s1 := mapPasswordToScalar(pw, sid, adA, adB)
	s2 := mapPasswordToScalar(pw, sid, adA, adB)
	if !bytes.Equal(s1, s2) {
		t.Fatal("mapPasswordToScalar is not deterministic")
	}

	different := mapPasswordToScalar([]byte("other-pw"), sid, adA, adB)
	if bytes.Equal(s1, different) {
		t.Fatal("different passwords produced same scalar")
	}

	// Message1 must NOT be deterministic (fresh random y each time)
	c1, err := NewCPace(CPaceInitiator, pw, sid, adA, adB)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := NewCPace(CPaceInitiator, pw, sid, adA, adB)
	if err != nil {
		t.Fatal(err)
	}
	m1, err := c1.Message1()
	if err != nil {
		t.Fatal(err)
	}
	m2, err := c2.Message1()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(m1, m2) {
		t.Fatal("Message1 outputs were identical — expected fresh random each call")
	}
}

func TestCPaceConfirmTagDistinctRoles(t *testing.T) {
	sessionKey := make([]byte, 32)
	for i := range sessionKey {
		sessionKey[i] = byte(i + 1)
	}
	sid := []byte("test-sid")

	alice, err := NewCPace(CPaceInitiator, []byte("pw"), sid, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewCPace(CPaceResponder, []byte("pw"), sid, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	tagA := alice.Confirm(sessionKey)
	tagB := bob.Confirm(sessionKey)

	if bytes.Equal(tagA, tagB) {
		t.Fatal("initiator and responder confirm tags must differ")
	}
}

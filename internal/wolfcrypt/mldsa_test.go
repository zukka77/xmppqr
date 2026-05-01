// SPDX-License-Identifier: AGPL-3.0-or-later
package wolfcrypt

import "testing"

func TestMLDSA65KeygenSizes(t *testing.T) {
	pub, priv, err := GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != MLDSA65PubSize {
		t.Fatalf("pub size %d != %d", len(pub), MLDSA65PubSize)
	}
	if len(priv) != MLDSA65PrivSize {
		t.Fatalf("priv size %d != %d", len(priv), MLDSA65PrivSize)
	}
}

func TestMLDSA65SignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello world")
	sig, err := MLDSA65Sign(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := MLDSA65Verify(pub, msg, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected valid signature")
	}
}

func TestMLDSA65VerifyTampered(t *testing.T) {
	pub, priv, err := GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := MLDSA65Sign(priv, []byte("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 0xff
	ok, err := MLDSA65Verify(pub, []byte("hello world"), sig)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected invalid signature")
	}
}

func TestMLDSA65VerifyTamperedMsg(t *testing.T) {
	pub, priv, err := GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := MLDSA65Sign(priv, []byte("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := MLDSA65Verify(pub, []byte("hello worlt"), sig)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected invalid signature for tampered message")
	}
}

func TestMLDSA65VerifyWrongKey(t *testing.T) {
	_, privA, err := GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	pubB, _, err := GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := MLDSA65Sign(privA, []byte("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := MLDSA65Verify(pubB, []byte("hello world"), sig)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected invalid signature with wrong key")
	}
}

func TestMLDSA65SigSize(t *testing.T) {
	_, priv, err := GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := MLDSA65Sign(priv, []byte("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != MLDSA65SigSize {
		t.Fatalf("sig size %d != %d", len(sig), MLDSA65SigSize)
	}
}

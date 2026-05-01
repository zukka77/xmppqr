// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"bytes"
	"testing"
)

func TestGenerateAccountIdentity(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if len(aik.PubEd25519) == 0 {
		t.Fatal("expected non-empty Ed25519 pub")
	}
}

func TestAccountFingerprintDeterminism(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pub := aik.Public()
	m1 := pub.Marshal()
	m2 := pub.Marshal()
	if !bytes.Equal(m1, m2) {
		t.Fatal("Marshal not deterministic")
	}
	f1 := pub.Fingerprint()
	f2 := pub.Fingerprint()
	if f1 != f2 {
		t.Fatalf("Fingerprint not deterministic: %q vs %q", f1, f2)
	}
}

func TestAccountFingerprintDifferent(t *testing.T) {
	aik1, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	aik2, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if aik1.Public().Fingerprint() == aik2.Public().Fingerprint() {
		t.Fatal("distinct AIKs produced identical fingerprints")
	}
}

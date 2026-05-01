// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestSealOpenRoundTrip(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := SealAIKAllowWeak(aik, []byte("correcthorse"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenAIK(blob, []byte("correcthorse"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.PrivEd25519, aik.PrivEd25519) {
		t.Fatal("PrivEd25519 mismatch after round-trip")
	}
	if !bytes.Equal(got.PubEd25519, aik.PubEd25519) {
		t.Fatal("PubEd25519 mismatch after round-trip")
	}
}

func TestOpenWrongPassphraseFails(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := SealAIKAllowWeak(aik, []byte("abcdefgh"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenAIK(blob, []byte("abcdefgi"))
	if err != ErrRecoveryBadPassphrase {
		t.Fatalf("expected ErrRecoveryBadPassphrase, got %v", err)
	}
}

func TestOpenTamperedCiphertextFails(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := SealAIKAllowWeak(aik, []byte("abcdefgh"))
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the ciphertext (last $ separated field).
	parts := strings.SplitN(blob, "$", 5)
	ctBytes, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(ctBytes) == 0 {
		t.Fatal("failed to decode ciphertext for tampering")
	}
	ctBytes[0] ^= 0xFF
	parts[4] = base64.RawStdEncoding.EncodeToString(ctBytes)
	tampered := strings.Join(parts, "$")

	_, err = OpenAIK(tampered, []byte("abcdefgh"))
	if err != ErrRecoveryBadPassphrase {
		t.Fatalf("expected ErrRecoveryBadPassphrase, got %v", err)
	}
}

func TestOpenTamperedHeaderFails(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := SealAIKAllowWeak(aik, []byte("abcdefgh"))
	if err != nil {
		t.Fatal(err)
	}
	// Change N=131072 to N=65536 in the header (meets minimum, but changes AAD).
	tampered := strings.Replace(blob, "N=131072", "N=65536", 1)
	_, err = OpenAIK(tampered, []byte("abcdefgh"))
	if err != ErrRecoveryBadPassphrase {
		t.Fatalf("expected ErrRecoveryBadPassphrase, got %v", err)
	}
}

func TestOpenInsecureParamsRejected(t *testing.T) {
	// Craft a blob with N=1024 (below minimum); we don't need valid ciphertext.
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	ct := make([]byte, 32) // fake
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	nonceB64 := base64.RawStdEncoding.EncodeToString(nonce)
	ctB64 := base64.RawStdEncoding.EncodeToString(ct)
	blob := "x3dhpqv1$N=1024,r=8,p=1$" + saltB64 + "$" + nonceB64 + "$" + ctB64
	_, err := OpenAIK(blob, []byte("pw"))
	if err != ErrRecoveryParamsInsecure {
		t.Fatalf("expected ErrRecoveryParamsInsecure, got %v", err)
	}
}

func TestPaperKeyRoundTrip(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := SealAIKAllowWeak(aik, []byte("correcthorse"))
	if err != nil {
		t.Fatal(err)
	}
	paper, err := PaperKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := PaperKeyDecode(paper)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenAIK(decoded, []byte("correcthorse"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.PrivEd25519, aik.PrivEd25519) {
		t.Fatal("PrivEd25519 mismatch after paper-key round-trip")
	}
	if !bytes.Equal(got.PubEd25519, aik.PubEd25519) {
		t.Fatal("PubEd25519 mismatch after paper-key round-trip")
	}
}

func TestPaperKeyMalformed(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := SealAIKAllowWeak(aik, []byte("abcdefgh"))
	if err != nil {
		t.Fatal(err)
	}
	paper, err := PaperKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	// Drop all but the first two lines.
	lines := strings.Split(strings.TrimSpace(paper), "\n")
	truncated := strings.Join(lines[:2], "\n")
	_, err = PaperKeyDecode(truncated)
	if err != ErrRecoveryMalformed {
		t.Fatalf("expected ErrRecoveryMalformed, got %v", err)
	}
}

func TestSealDifferentSaltsEachTime(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	b1, err := SealAIKAllowWeak(aik, []byte("abcdefgh"))
	if err != nil {
		t.Fatal(err)
	}
	b2, err := SealAIKAllowWeak(aik, []byte("abcdefgh"))
	if err != nil {
		t.Fatal(err)
	}
	if b1 == b2 {
		t.Fatal("two seals with same passphrase produced identical blobs (salt not random)")
	}
}

func TestOpenMalformedBlob(t *testing.T) {
	cases := []string{
		"not-a-blob",
		"x3dhpqv1$",
		"x3dhpqv1$N=131072,r=8,p=1$$$",
	}
	for _, c := range cases {
		_, err := OpenAIK(c, []byte("pw"))
		if err != ErrRecoveryMalformed && err != ErrRecoveryParamsInsecure {
			t.Errorf("OpenAIK(%q): expected ErrRecoveryMalformed or ErrRecoveryParamsInsecure, got %v", c, err)
		}
	}
}

func TestEstimatePassphraseRanges(t *testing.T) {
	cases := []struct {
		input    string
		expected PassphraseStrength
	}{
		{"", PassphraseInvalid},
		{"abcdefg", PassphraseInvalid},
		{"abcdefgh", PassphraseWeak},
		{"abcdefghij12", PassphraseWeak},
		{"Abcdef12345!", PassphraseAcceptable},
		{"CorrectHorseBatteryStaple1!", PassphraseStrong},
		{"aaaaaaaaaaaaaaaaaaaa", PassphraseWeak},
		{"1234567890abcdef!", PassphraseAcceptable},
	}
	for _, c := range cases {
		got := EstimatePassphrase([]byte(c.input))
		if got != c.expected {
			t.Errorf("EstimatePassphrase(%q) = %s, want %s", c.input, got, c.expected)
		}
	}
}

func TestSealRejectsWeak(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, err = SealAIK(aik, []byte("weak"))
	if err != ErrRecoveryWeakPassphrase {
		t.Fatalf("expected ErrRecoveryWeakPassphrase, got %v", err)
	}
}

func TestSealStrongPassphraseSucceeds(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, err = SealAIK(aik, []byte("Strong-Passphrase-2026!"))
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestSealAllowWeakAcceptsWeak(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, err = SealAIKAllowWeak(aik, []byte("Abcdef12!"))
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestSealRejectsInvalid(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, err = SealAIK(aik, []byte(""))
	if err != ErrRecoveryWeakPassphrase {
		t.Fatalf("SealAIK: expected ErrRecoveryWeakPassphrase, got %v", err)
	}
	_, err = SealAIKAllowWeak(aik, []byte(""))
	if err != ErrRecoveryWeakPassphrase {
		t.Fatalf("SealAIKAllowWeak: expected ErrRecoveryWeakPassphrase, got %v", err)
	}
}

func TestOpenAIKAndRecordEmitsAuditEntry(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("Strong-Passphrase-2026!")
	blob, err := SealAIK(aik, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	opts := RecoverOptions{
		PrevAuditEntry: nil,
		DeviceCount:    1,
		Timestamp:      time.Now().Unix(),
	}
	recoveredAIK, entry, err := OpenAIKAndRecord(blob, passphrase, opts)
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil {
		t.Fatal("expected audit entry, got nil")
	}
	if entry.Action != AuditActionRecoverFromBackup {
		t.Fatalf("expected AuditActionRecoverFromBackup, got %s", entry.Action)
	}
	if err := entry.Verify(recoveredAIK.Public()); err != nil {
		t.Fatalf("audit entry verification failed: %v", err)
	}
	if !bytes.Equal(recoveredAIK.PubEd25519, aik.PubEd25519) {
		t.Fatal("recovered AIK pub key mismatch")
	}
}

func TestOpenAIKAndRecordWrongPassphraseFails(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := SealAIK(aik, []byte("Strong-Passphrase-2026!"))
	if err != nil {
		t.Fatal(err)
	}
	opts := RecoverOptions{DeviceCount: 1, Timestamp: time.Now().Unix()}
	recoveredAIK, entry, err := OpenAIKAndRecord(blob, []byte("wrong-passphrase"), opts)
	if err != ErrRecoveryBadPassphrase {
		t.Fatalf("expected ErrRecoveryBadPassphrase, got %v", err)
	}
	if recoveredAIK != nil || entry != nil {
		t.Fatal("expected nil AIK and entry on failure")
	}
}

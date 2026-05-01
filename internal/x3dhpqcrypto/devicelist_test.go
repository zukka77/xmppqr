// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func makeDC(t *testing.T, aik *AccountIdentityKey, deviceID uint32, flags uint8) *DeviceCertificate {
	t.Helper()
	dik, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatalf("GenerateDeviceIdentity: %v", err)
	}
	dc, err := aik.IssueDeviceCert(dik, deviceID, flags)
	if err != nil {
		t.Fatalf("IssueDeviceCert: %v", err)
	}
	return dc
}

func makeEntries(t *testing.T, aik *AccountIdentityKey, ids []uint32) []DeviceListEntry {
	t.Helper()
	entries := make([]DeviceListEntry, len(ids))
	for i, id := range ids {
		entries[i] = DeviceListEntry{
			DeviceID: id,
			Cert:     makeDC(t, aik, id, 0),
			AddedAt:  time.Now().Unix(),
			Flags:    0,
		}
	}
	return entries
}

func TestIssueAndVerifyDeviceList(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	entries := makeEntries(t, aik, []uint32{1, 2})
	dl, err := aik.IssueDeviceList(1, entries)
	if err != nil {
		t.Fatalf("IssueDeviceList: %v", err)
	}
	if err := dl.Verify(aik.Public()); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestDeviceListVerifyWrongAIKFails(t *testing.T) {
	aik, _ := GenerateAccountIdentity()
	other, _ := GenerateAccountIdentity()
	entries := makeEntries(t, aik, []uint32{1})
	dl, err := aik.IssueDeviceList(1, entries)
	if err != nil {
		t.Fatal(err)
	}
	err = dl.Verify(other.Public())
	if !errors.Is(err, ErrDeviceListBadSig) {
		t.Fatalf("expected ErrDeviceListBadSig, got %v", err)
	}
}

func TestDeviceListVerifyTamperedFails(t *testing.T) {
	aik, _ := GenerateAccountIdentity()
	entries := makeEntries(t, aik, []uint32{1, 2})
	dl, err := aik.IssueDeviceList(1, entries)
	if err != nil {
		t.Fatal(err)
	}
	dl.Devices[0].DeviceID ^= 0xFF
	err = dl.Verify(aik.Public())
	if !errors.Is(err, ErrDeviceListBadSig) {
		t.Fatalf("expected ErrDeviceListBadSig after tamper, got %v", err)
	}
}

func TestVerifyMonotonicAccepts(t *testing.T) {
	aik, _ := GenerateAccountIdentity()
	entries := makeEntries(t, aik, []uint32{1})
	dl, _ := aik.IssueDeviceList(2, entries)
	if err := dl.VerifyMonotonic(1); err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
}

func TestVerifyMonotonicRejectsEqual(t *testing.T) {
	aik, _ := GenerateAccountIdentity()
	entries := makeEntries(t, aik, []uint32{1})
	dl, _ := aik.IssueDeviceList(1, entries)
	if err := dl.VerifyMonotonic(1); !errors.Is(err, ErrDeviceListRollback) {
		t.Fatalf("expected ErrDeviceListRollback, got %v", err)
	}
}

func TestVerifyMonotonicRejectsLower(t *testing.T) {
	aik, _ := GenerateAccountIdentity()
	entries := makeEntries(t, aik, []uint32{1})
	dl, _ := aik.IssueDeviceList(1, entries)
	if err := dl.VerifyMonotonic(2); !errors.Is(err, ErrDeviceListRollback) {
		t.Fatalf("expected ErrDeviceListRollback, got %v", err)
	}
}

func TestVerifyAllCerts(t *testing.T) {
	aik, _ := GenerateAccountIdentity()
	entries := makeEntries(t, aik, []uint32{1, 2})
	dl, _ := aik.IssueDeviceList(1, entries)
	if err := dl.VerifyAllCerts(aik.Public()); err != nil {
		t.Fatalf("VerifyAllCerts: %v", err)
	}
}

func TestVerifyAllCertsCatchesBadCert(t *testing.T) {
	aik, _ := GenerateAccountIdentity()
	unrelated, _ := GenerateAccountIdentity()
	entries := makeEntries(t, aik, []uint32{1, 2})
	entries[1].Cert = makeDC(t, unrelated, 2, 0)
	dl, _ := aik.IssueDeviceList(1, entries)
	err := dl.VerifyAllCerts(aik.Public())
	if err == nil {
		t.Fatal("expected error from bad cert, got nil")
	}
}

func TestDeviceListMarshalRoundTrip(t *testing.T) {
	aik, _ := GenerateAccountIdentity()
	entries := makeEntries(t, aik, []uint32{10, 20})
	dl, err := aik.IssueDeviceList(5, entries)
	if err != nil {
		t.Fatal(err)
	}
	b := dl.Marshal()
	dl2, err := UnmarshalDeviceList(b)
	if err != nil {
		t.Fatalf("UnmarshalDeviceList: %v", err)
	}
	if err := dl2.Verify(aik.Public()); err != nil {
		t.Fatalf("Verify after round-trip: %v", err)
	}
	if err := dl2.VerifyAllCerts(aik.Public()); err != nil {
		t.Fatalf("VerifyAllCerts after round-trip: %v", err)
	}
	if dl2.Version != dl.Version || dl2.IssuedAt != dl.IssuedAt {
		t.Fatalf("metadata mismatch after round-trip")
	}
	if !bytes.Equal(dl2.Signature, dl.Signature) {
		t.Fatalf("signature mismatch after round-trip")
	}
}

func TestSortedByDeviceID(t *testing.T) {
	aik, _ := GenerateAccountIdentity()
	entries := makeEntries(t, aik, []uint32{3, 1, 2})
	dl, err := aik.IssueDeviceList(1, entries)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(dl.Devices); i++ {
		if dl.Devices[i].DeviceID <= dl.Devices[i-1].DeviceID {
			t.Fatalf("devices not sorted at index %d", i)
		}
	}
	sp1 := dl.SignedPart()
	// issue again with same entries to confirm determinism
	dl2, _ := aik.IssueDeviceList(1, entries)
	dl2.IssuedAt = dl.IssuedAt
	sp2 := dl2.SignedPart()
	if !bytes.Equal(sp1, sp2) {
		t.Fatalf("SignedPart not deterministic")
	}
}

func TestFind(t *testing.T) {
	aik, _ := GenerateAccountIdentity()
	entries := makeEntries(t, aik, []uint32{7, 42})
	dl, _ := aik.IssueDeviceList(1, entries)
	e := dl.Find(42)
	if e == nil {
		t.Fatal("Find(42) returned nil")
	}
	if e.DeviceID != 42 {
		t.Fatalf("Find returned wrong entry: %d", e.DeviceID)
	}
	if dl.Find(999) != nil {
		t.Fatal("Find(999) should return nil")
	}
}

func TestDeviceListVerifyMissingMLDSARejected(t *testing.T) {
	aik, _ := GenerateAccountIdentity()
	entries := makeEntries(t, aik, []uint32{1})
	dl, err := aik.IssueDeviceList(1, entries)
	if err != nil {
		t.Fatal(err)
	}
	dl.MLDSASignature = nil
	err = dl.Verify(aik.Public())
	if !errors.Is(err, ErrDeviceListMissingMLDSASignature) {
		t.Fatalf("expected ErrDeviceListMissingMLDSASignature, got %v", err)
	}
}

func TestDeviceListVerifyTamperedMLDSARejected(t *testing.T) {
	aik, _ := GenerateAccountIdentity()
	entries := makeEntries(t, aik, []uint32{1})
	dl, err := aik.IssueDeviceList(1, entries)
	if err != nil {
		t.Fatal(err)
	}
	dl.MLDSASignature[0] ^= 0xFF
	err = dl.Verify(aik.Public())
	if err == nil {
		t.Fatal("expected error for tampered ML-DSA signature")
	}
}

func TestDeviceListUnmarshalLegacyRejected(t *testing.T) {
	aik, _ := GenerateAccountIdentity()
	entries := makeEntries(t, aik, []uint32{1})
	dl, err := aik.IssueDeviceList(1, entries)
	if err != nil {
		t.Fatal(err)
	}
	good := dl.Marshal()
	// Zero out the mldsa_sig_len field: it sits right after the ed25519 sig bytes.
	// Find the position: everything up to and including the ed25519 sig, then 2 bytes for mldsa len.
	// We'll craft the wire by appending mldsa_sig_len=0 ourselves.
	// The easiest approach: marshal normally, then build a legacy buffer where mldsa_sig_len=0.
	_ = good
	// Build legacy manually: same content but truncate after ed25519 sig and append uint16(0).
	normal := dl.Marshal()
	// Find the offset after mldsa sig = len(normal) - 2 - len(mldsa sig).
	// Reconstruct: strip mldsa_sig_len+mldsa_sig from end, then append 0x00 0x00.
	mlSigLen := len(dl.MLDSASignature)
	truncated := normal[:len(normal)-mlSigLen]
	// truncated ends with uint16(mlSigLen) — replace those 2 bytes with 0x00 0x00.
	legacy := make([]byte, len(truncated))
	copy(legacy, truncated)
	legacy[len(legacy)-2] = 0
	legacy[len(legacy)-1] = 0

	_, err = UnmarshalDeviceList(legacy)
	if !errors.Is(err, ErrDeviceListMissingMLDSASignature) {
		t.Fatalf("expected ErrDeviceListMissingMLDSASignature for legacy wire, got %v", err)
	}
}

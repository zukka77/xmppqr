// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"bytes"
	"errors"
	"testing"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

func TestIssueAndVerifyDC(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dik, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dc, err := aik.IssueDeviceCert(dik, 42, DeviceFlagPrimary)
	if err != nil {
		t.Fatal(err)
	}
	if err := dc.Verify(aik.Public()); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func TestVerifyWrongAIKFails(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	otherAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dik, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dc, err := aik.IssueDeviceCert(dik, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := dc.Verify(otherAIK.Public()); err == nil {
		t.Fatal("expected verify to fail against wrong AIK")
	}
}

func TestVerifyTamperedDCFails(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dik, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dc, err := aik.IssueDeviceCert(dik, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	dc.DIKPubEd25519[0] ^= 0xFF
	if err := dc.Verify(aik.Public()); err == nil {
		t.Fatal("expected verify to fail on tampered DIKPubEd25519")
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dik, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dc, err := aik.IssueDeviceCert(dik, 99, DeviceFlagPrimary)
	if err != nil {
		t.Fatal(err)
	}

	encoded := dc.Marshal()
	dc2, err := UnmarshalDeviceCert(encoded)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if dc2.Version != dc.Version {
		t.Errorf("Version mismatch: %d vs %d", dc2.Version, dc.Version)
	}
	if dc2.DeviceID != dc.DeviceID {
		t.Errorf("DeviceID mismatch: %d vs %d", dc2.DeviceID, dc.DeviceID)
	}
	if !bytes.Equal(dc2.DIKPubEd25519, dc.DIKPubEd25519) {
		t.Error("DIKPubEd25519 mismatch")
	}
	if !bytes.Equal(dc2.DIKPubX25519, dc.DIKPubX25519) {
		t.Error("DIKPubX25519 mismatch")
	}
	if dc2.CreatedAt != dc.CreatedAt {
		t.Errorf("CreatedAt mismatch: %d vs %d", dc2.CreatedAt, dc.CreatedAt)
	}
	if dc2.Flags != dc.Flags {
		t.Errorf("Flags mismatch: %d vs %d", dc2.Flags, dc.Flags)
	}
	if !bytes.Equal(dc2.Signature, dc.Signature) {
		t.Error("Signature mismatch")
	}

	if err := dc2.Verify(aik.Public()); err != nil {
		t.Fatalf("verify after round-trip: %v", err)
	}
}

func TestIssueAndVerifyHybridDC(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dik, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dc, err := aik.IssueDeviceCert(dik, 7, DeviceFlagPrimary)
	if err != nil {
		t.Fatal(err)
	}
	if len(dc.Signature) == 0 {
		t.Fatal("Ed25519 signature missing")
	}
	if len(dc.MLDSASignature) == 0 {
		t.Fatal("ML-DSA-65 signature missing")
	}
	sp := dc.SignedPart()
	edOK, err := wolfcrypt.Ed25519Verify(aik.PubEd25519, sp, dc.Signature)
	if err != nil || !edOK {
		t.Fatalf("Ed25519 path failed: %v", err)
	}
	mlOK, err := wolfcrypt.MLDSA65Verify(aik.PubMLDSA, sp, dc.MLDSASignature)
	if err != nil || !mlOK {
		t.Fatalf("ML-DSA-65 path failed: %v", err)
	}
	if err := dc.Verify(aik.Public()); err != nil {
		t.Fatalf("hybrid Verify failed: %v", err)
	}
}

func TestVerifyMissingMLDSARejected(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dik, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dc, err := aik.IssueDeviceCert(dik, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	dc.MLDSASignature = nil
	if err := dc.Verify(aik.Public()); !errors.Is(err, ErrDCMissingMLDSASignature) {
		t.Fatalf("expected ErrDCMissingMLDSASignature, got %v", err)
	}
}

func TestVerifyMissingEd25519Rejected(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dik, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dc, err := aik.IssueDeviceCert(dik, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	dc.Signature = nil
	if err := dc.Verify(aik.Public()); err == nil {
		t.Fatal("expected error with missing Ed25519 signature")
	}
}

func TestVerifyMLDSAMismatchRejected(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dik, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dc, err := aik.IssueDeviceCert(dik, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	dc.MLDSASignature[0] ^= 0xFF
	if err := dc.Verify(aik.Public()); !errors.Is(err, ErrInvalidDeviceCert) {
		t.Fatalf("expected ErrInvalidDeviceCert, got %v", err)
	}
}

func TestUnmarshalRejectsLegacyV1(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dik, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dc, err := aik.IssueDeviceCert(dik, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	dc.DIKPubMLDSA = nil
	dc.MLDSASignature = nil
	wire := dc.Marshal()
	_, err = UnmarshalDeviceCert(wire)
	if !errors.Is(err, ErrDCMissingMLDSASignature) {
		t.Fatalf("expected ErrDCMissingMLDSASignature on legacy wire, got %v", err)
	}
}

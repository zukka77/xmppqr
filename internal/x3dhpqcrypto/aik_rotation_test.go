// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

func TestNewRotationVerifies(t *testing.T) {
	oldAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	newAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rp, err := oldAIK.NewRotation(newAIK.Public(), "test rotation")
	if err != nil {
		t.Fatal(err)
	}
	if err := rp.Verify(); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
}

func TestRotationWrongSignerFails(t *testing.T) {
	oldAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	newAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	thirdParty, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rp, err := oldAIK.NewRotation(newAIK.Public(), "test")
	if err != nil {
		t.Fatal(err)
	}
	badSig, err := wolfcrypt.Ed25519Sign(thirdParty.PrivEd25519, rp.SignedPart())
	if err != nil {
		t.Fatal(err)
	}
	rp.Signature = badSig
	if err := rp.Verify(); err != ErrRotationBadSig {
		t.Fatalf("expected ErrRotationBadSig, got %v", err)
	}
}

func TestRotationMarshalRoundTrip(t *testing.T) {
	oldAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	newAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rp, err := oldAIK.NewRotation(newAIK.Public(), "roundtrip test")
	if err != nil {
		t.Fatal(err)
	}
	wire := rp.Marshal()
	rp2, err := UnmarshalRotationPointer(wire)
	if err != nil {
		t.Fatalf("UnmarshalRotationPointer: %v", err)
	}
	if err := rp2.Verify(); err != nil {
		t.Fatalf("Verify after round-trip: %v", err)
	}
}

func TestRotationReasonTooLong(t *testing.T) {
	oldAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	newAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	longReason := strings.Repeat("x", 600)
	_, err = oldAIK.NewRotation(newAIK.Public(), longReason)
	if err != ErrRotationReasonTooLong {
		t.Fatalf("expected ErrRotationReasonTooLong, got %v", err)
	}
}

func TestApplyRotationProducesValidEntry(t *testing.T) {
	oldAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Now().Unix()
	result, err := oldAIK.ApplyRotation(nil, "suspected compromise", ts)
	if err != nil {
		t.Fatal(err)
	}
	if err := result.AuditEntry.Verify(oldAIK.Public()); err != nil {
		t.Fatalf("AuditEntry.Verify: %v", err)
	}
	if result.AuditEntry.Action != AuditActionRotateAIK {
		t.Fatalf("expected AuditActionRotateAIK, got %v", result.AuditEntry.Action)
	}
	if result.NewAIK.Public().Equal(oldAIK.Public()) {
		t.Fatal("new AIK pub must differ from old")
	}
}

func TestReissueDeviceCertsBindsToNewAIK(t *testing.T) {
	oldAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dik1, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dik2, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dc1, err := oldAIK.IssueDeviceCert(dik1, 1, DeviceFlagPrimary)
	if err != nil {
		t.Fatal(err)
	}
	dc2, err := oldAIK.IssueDeviceCert(dik2, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = dc1
	_ = dc2

	ts := time.Now().Unix()
	result, err := oldAIK.ApplyRotation(nil, "test reissue", ts)
	if err != nil {
		t.Fatal(err)
	}
	newAIK := result.NewAIK

	inputs := []DeviceReissueInput{
		{DeviceID: 1, Flags: DeviceFlagPrimary, DIKPubX25519: dik1.PubX25519, DIKPubEd25519: dik1.PubEd25519},
		{DeviceID: 2, Flags: 0, DIKPubX25519: dik2.PubX25519, DIKPubEd25519: dik2.PubEd25519},
	}
	newDCs, err := newAIK.ReissueDeviceCerts(inputs)
	if err != nil {
		t.Fatal(err)
	}
	if len(newDCs) != 2 {
		t.Fatalf("expected 2 DCs, got %d", len(newDCs))
	}
	for i, dc := range newDCs {
		if err := dc.Verify(newAIK.Public()); err != nil {
			t.Errorf("DC %d Verify(newAIK) failed: %v", i, err)
		}
		if err := dc.Verify(oldAIK.Public()); err == nil {
			t.Errorf("DC %d Verify(oldAIK) should have failed", i)
		}
	}
}

func TestShouldAcceptRotationWarnAccept(t *testing.T) {
	oldAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	newAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rp, err := oldAIK.NewRotation(newAIK.Public(), "warn-accept test")
	if err != nil {
		t.Fatal(err)
	}
	accept, requireReverify, err := ShouldAcceptRotation(rp, RotationTrustWarnAccept)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !accept {
		t.Fatal("expected accept=true")
	}
	if !requireReverify {
		t.Fatal("expected requireReverify=true")
	}
}

func TestShouldAcceptRotationStrict(t *testing.T) {
	oldAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	newAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rp, err := oldAIK.NewRotation(newAIK.Public(), "strict test")
	if err != nil {
		t.Fatal(err)
	}
	accept, requireReverify, err := ShouldAcceptRotation(rp, RotationTrustStrict)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if accept {
		t.Fatal("expected accept=false under strict policy")
	}
	if !requireReverify {
		t.Fatal("expected requireReverify=true")
	}
}

func TestDefaultPolicyIsStrict(t *testing.T) {
	oldAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	newAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rp, err := oldAIK.NewRotation(newAIK.Public(), "default policy test")
	if err != nil {
		t.Fatal(err)
	}
	accept, requireReverify, err := ShouldAcceptRotation(rp, RotationTrustPolicy(0))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if accept {
		t.Fatal("zero value policy must refuse (Strict)")
	}
	if !requireReverify {
		t.Fatal("expected requireReverify=true")
	}
}

func TestRotationVerifyMissingMLDSARejected(t *testing.T) {
	oldAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	newAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rp, err := oldAIK.NewRotation(newAIK.Public(), "missing mldsa test")
	if err != nil {
		t.Fatal(err)
	}
	rp.MLDSASignature = nil
	if got := rp.Verify(); !errors.Is(got, ErrRotationMissingMLDSASignature) {
		t.Fatalf("expected ErrRotationMissingMLDSASignature, got %v", got)
	}
}

func TestShouldAcceptRotationBadSig(t *testing.T) {
	oldAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	newAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	thirdParty, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rp, err := oldAIK.NewRotation(newAIK.Public(), "bad sig test")
	if err != nil {
		t.Fatal(err)
	}
	badSig, err := wolfcrypt.Ed25519Sign(thirdParty.PrivEd25519, rp.SignedPart())
	if err != nil {
		t.Fatal(err)
	}
	rp.Signature = badSig

	for _, policy := range []RotationTrustPolicy{RotationTrustWarnAccept, RotationTrustStrict} {
		accept, requireReverify, err := ShouldAcceptRotation(rp, policy)
		if err != ErrRotationBadSig {
			t.Errorf("policy %v: expected ErrRotationBadSig, got %v", policy, err)
		}
		if accept {
			t.Errorf("policy %v: expected accept=false", policy)
		}
		if requireReverify {
			t.Errorf("policy %v: expected requireReverify=false", policy)
		}
	}
}

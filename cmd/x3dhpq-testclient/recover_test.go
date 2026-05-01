// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"errors"
	"testing"

	"github.com/danielinux/xmppqr/internal/x3dhpqcrypto"
)

func TestRecoverRuns(t *testing.T) {
	if err := runRecover(); err != nil {
		t.Fatalf("runRecover: %v", err)
	}
}

func TestRecoverBackupRoundTrip(t *testing.T) {
	aik, err := x3dhpqcrypto.GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pass := []byte("test-passphrase")
	sealed, err := x3dhpqcrypto.SealAIKAllowWeak(aik, pass)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := x3dhpqcrypto.OpenAIK(sealed, pass)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.PubEd25519, aik.PubEd25519) {
		t.Fatal("PubEd25519 mismatch after seal/open")
	}
}

func TestRecoverWrongPassphrase(t *testing.T) {
	aik, err := x3dhpqcrypto.GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := x3dhpqcrypto.SealAIKAllowWeak(aik, []byte("abcdefgh"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = x3dhpqcrypto.OpenAIK(sealed, []byte("abcdefgi"))
	if !errors.Is(err, x3dhpqcrypto.ErrRecoveryBadPassphrase) {
		t.Fatalf("expected ErrRecoveryBadPassphrase, got %v", err)
	}
}

func TestRecoverPaperKeyRoundTrip(t *testing.T) {
	aik, err := x3dhpqcrypto.GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pass := []byte("paper-key-test")
	sealed, err := x3dhpqcrypto.SealAIKAllowWeak(aik, pass)
	if err != nil {
		t.Fatal(err)
	}
	paper, err := x3dhpqcrypto.PaperKey(sealed)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := x3dhpqcrypto.PaperKeyDecode(paper)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := x3dhpqcrypto.OpenAIK(decoded, pass)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.PubEd25519, aik.PubEd25519) {
		t.Fatal("PubEd25519 mismatch after paper-key round-trip")
	}
}

func TestRecoverRotationFlow(t *testing.T) {
	oldAIK, err := x3dhpqcrypto.GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rr, err := oldAIK.ApplyRotation(nil, "test rotation", 1000000)
	if err != nil {
		t.Fatal(err)
	}
	if err := rr.Pointer.Verify(); err != nil {
		t.Fatalf("rotation pointer verify: %v", err)
	}
	if bytes.Equal(oldAIK.PubEd25519, rr.NewAIK.PubEd25519) {
		t.Fatal("new AIK should differ from old AIK")
	}
}

func TestRecoverDeviceReissueUnderNewAIK(t *testing.T) {
	oldAIK, err := x3dhpqcrypto.GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}

	dik1, err := x3dhpqcrypto.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dik2, err := x3dhpqcrypto.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}

	oldDC1, err := oldAIK.IssueDeviceCert(dik1, 1, x3dhpqcrypto.DeviceFlagPrimary)
	if err != nil {
		t.Fatal(err)
	}
	oldDC2, err := oldAIK.IssueDeviceCert(dik2, 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	rr, err := oldAIK.ApplyRotation(nil, "device reissue test", 2000000)
	if err != nil {
		t.Fatal(err)
	}

	newDCs, err := rr.NewAIK.ReissueDeviceCerts([]x3dhpqcrypto.DeviceReissueInput{
		{DeviceID: 1, Flags: x3dhpqcrypto.DeviceFlagPrimary, DIKPubX25519: oldDC1.DIKPubX25519, DIKPubEd25519: oldDC1.DIKPubEd25519},
		{DeviceID: 2, Flags: 0, DIKPubX25519: oldDC2.DIKPubX25519, DIKPubEd25519: oldDC2.DIKPubEd25519},
	})
	if err != nil {
		t.Fatal(err)
	}

	for i, dc := range newDCs {
		if err := dc.Verify(rr.NewAIK.Public()); err != nil {
			t.Fatalf("new DC%d should verify under new AIK: %v", i+1, err)
		}
		if err := dc.Verify(oldAIK.Public()); err == nil {
			t.Fatalf("new DC%d should NOT verify under old AIK", i+1)
		}
	}
}

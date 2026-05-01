// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/danielinux/xmppqr/internal/x3dhpqcrypto"
)

func runRecover() error {
	fmt.Println("=== Phase 1: encrypted backup round-trip ===")

	origAIK, err := x3dhpqcrypto.GenerateAccountIdentity()
	if err != nil {
		return fmt.Errorf("generate AIK: %w", err)
	}
	origFP := origAIK.Public().Fingerprint()
	fmt.Printf("  AIK_orig fp: %s\n", origFP)

	passphrase := []byte("correct-horse-battery-staple")
	sealed, err := x3dhpqcrypto.SealAIK(origAIK, passphrase)
	if err != nil {
		return fmt.Errorf("SealAIK: %w", err)
	}
	show := sealed
	if len(show) > 80 {
		show = show[:80]
	}
	fmt.Printf("  Sealed (showing first 80 chars):\n    %s\n", show)

	reopened, err := x3dhpqcrypto.OpenAIK(sealed, passphrase)
	if err != nil {
		return fmt.Errorf("OpenAIK correct passphrase: %w", err)
	}
	if !bytes.Equal(reopened.PubEd25519, origAIK.PubEd25519) {
		return fmt.Errorf("re-opened AIK fp mismatch")
	}
	fmt.Printf("  Re-opened with correct passphrase ✓ — fp matches original\n")

	_, err = x3dhpqcrypto.OpenAIK(sealed, []byte("wrong-passphrase"))
	if !errors.Is(err, x3dhpqcrypto.ErrRecoveryBadPassphrase) {
		return fmt.Errorf("expected ErrRecoveryBadPassphrase, got %v", err)
	}
	fmt.Printf("  Open with wrong passphrase → ErrRecoveryBadPassphrase ✓\n")

	fmt.Println("\n=== Phase 2: paper key round-trip ===")

	paper, err := x3dhpqcrypto.PaperKey(sealed)
	if err != nil {
		return fmt.Errorf("PaperKey: %w", err)
	}
	show2 := paper
	if len(show2) > 40 {
		show2 = show2[:40]
	}
	fmt.Printf("  Paper-key (first 40 chars): %s\n", show2)

	decoded, err := x3dhpqcrypto.PaperKeyDecode(paper)
	if err != nil {
		return fmt.Errorf("PaperKeyDecode: %w", err)
	}
	fmt.Printf("  Paper-key decoded back to sealed blob ✓\n")

	decodedAIK, err := x3dhpqcrypto.OpenAIK(decoded, passphrase)
	if err != nil {
		return fmt.Errorf("OpenAIK from decoded paper: %w", err)
	}
	if !bytes.Equal(decodedAIK.PubEd25519, origAIK.PubEd25519) {
		return fmt.Errorf("decoded AIK mismatch")
	}
	fmt.Printf("  Decoded blob opens with same passphrase ✓\n")

	fmt.Println("\n=== Phase 3: AIK rotation ===")

	oldAIK, err := x3dhpqcrypto.GenerateAccountIdentity()
	if err != nil {
		return fmt.Errorf("generate old AIK: %w", err)
	}
	oldFP := oldAIK.Public().Fingerprint()
	fmt.Printf("  Old AIK: %s\n", oldFP)
	fmt.Printf("  Rotating ...\n")

	ts := time.Now().Unix()
	rr, err := oldAIK.ApplyRotation(nil, "primary device replaced", ts)
	if err != nil {
		return fmt.Errorf("ApplyRotation: %w", err)
	}

	newFP := rr.NewAIK.Public().Fingerprint()
	fmt.Printf("  New AIK: %s\n", newFP)

	if err := rr.Pointer.Verify(); err != nil {
		return fmt.Errorf("rotation pointer verify: %w", err)
	}
	fmt.Printf("  Rotation pointer signed by OLD AIK ✓\n")

	if err := rr.AuditEntry.Verify(oldAIK.Public()); err != nil {
		return fmt.Errorf("audit entry verify: %w", err)
	}
	fmt.Printf("  AuditEntry verifies under OLD AIK ✓\n")
	fmt.Printf("  Action: %s\n", rr.AuditEntry.Action)
	fmt.Printf("  Reason: %q\n", rr.Pointer.Reason)

	fmt.Println("\n=== Phase 4: re-issue device certs under new AIK ===")

	oldDev1, err := oldAIK.IssueDeviceCert(&x3dhpqcrypto.DeviceIdentityKey{
		PubX25519:  mustGenX25519Pub(),
		PubEd25519: mustGenEd25519Pub(),
	}, 1, x3dhpqcrypto.DeviceFlagPrimary)
	if err != nil {
		return fmt.Errorf("IssueDeviceCert dev1: %w", err)
	}
	oldDev2, err := oldAIK.IssueDeviceCert(&x3dhpqcrypto.DeviceIdentityKey{
		PubX25519:  mustGenX25519Pub(),
		PubEd25519: mustGenEd25519Pub(),
	}, 2, 0)
	if err != nil {
		return fmt.Errorf("IssueDeviceCert dev2: %w", err)
	}

	if err := oldDev1.Verify(oldAIK.Public()); err != nil {
		return fmt.Errorf("old DC1 verify under old AIK: %w", err)
	}
	if err := oldDev2.Verify(oldAIK.Public()); err != nil {
		return fmt.Errorf("old DC2 verify under old AIK: %w", err)
	}
	fmt.Printf("  Old DCs (2 devices) verified under OLD AIK ✓\n")

	newDCs, err := rr.NewAIK.ReissueDeviceCerts([]x3dhpqcrypto.DeviceReissueInput{
		{DeviceID: 1, Flags: x3dhpqcrypto.DeviceFlagPrimary, DIKPubX25519: oldDev1.DIKPubX25519, DIKPubEd25519: oldDev1.DIKPubEd25519},
		{DeviceID: 2, Flags: 0, DIKPubX25519: oldDev2.DIKPubX25519, DIKPubEd25519: oldDev2.DIKPubEd25519},
	})
	if err != nil {
		return fmt.Errorf("ReissueDeviceCerts: %w", err)
	}

	fmt.Printf("  New DCs from ReissueDeviceCerts:\n")
	labels := []string{"primary", "secondary"}
	for i, dc := range newDCs {
		if err := dc.Verify(rr.NewAIK.Public()); err != nil {
			return fmt.Errorf("new DC%d verify under new AIK: %w", i+1, err)
		}
		fmt.Printf("    DeviceID %d (%s)   → DC verified under NEW AIK ✓\n", dc.DeviceID, labels[i])
	}

	for i, dc := range newDCs {
		if err := dc.Verify(oldAIK.Public()); err == nil {
			return fmt.Errorf("new DC%d should NOT verify under old AIK", i+1)
		}
	}
	fmt.Printf("  Old DCs verified under NEW AIK → FAIL ✓ (expected — different signer)\n")

	fmt.Println("\n=== Phase 5: trust policy ===")

	rp, err := oldAIK.NewRotation(rr.NewAIK.Public(), "trust policy test")
	if err != nil {
		return fmt.Errorf("NewRotation for trust test: %w", err)
	}

	accept, requireReverify, err := x3dhpqcrypto.ShouldAcceptRotation(rp, x3dhpqcrypto.RotationTrustWarnAccept)
	if err != nil {
		return fmt.Errorf("WarnAccept: %w", err)
	}
	if !accept || !requireReverify {
		return fmt.Errorf("WarnAccept: expected accept=true requireReverify=true, got %v %v", accept, requireReverify)
	}
	fmt.Printf("  WarnAccept: rotation accepted, requireReverify=true ✓\n")

	accept2, requireReverify2, err := x3dhpqcrypto.ShouldAcceptRotation(rp, x3dhpqcrypto.RotationTrustStrict)
	if err != nil {
		return fmt.Errorf("Strict: %w", err)
	}
	if accept2 || !requireReverify2 {
		return fmt.Errorf("Strict: expected accept=false requireReverify=true, got %v %v", accept2, requireReverify2)
	}
	fmt.Printf("  Strict:     rotation refused, requireReverify=true ✓\n")

	tampered := *rp
	sig := make([]byte, len(rp.Signature))
	copy(sig, rp.Signature)
	sig[0] ^= 0xFF
	tampered.Signature = sig

	_, _, err1 := x3dhpqcrypto.ShouldAcceptRotation(&tampered, x3dhpqcrypto.RotationTrustWarnAccept)
	_, _, err2 := x3dhpqcrypto.ShouldAcceptRotation(&tampered, x3dhpqcrypto.RotationTrustStrict)
	if err1 == nil || err2 == nil {
		return fmt.Errorf("tampered signature should fail both policies; got %v %v", err1, err2)
	}
	fmt.Printf("  Tampered signature: refused under both policies ✓\n")

	fmt.Println("\nrecover: OK — backup, paper-key, rotation, re-cert, trust policy verified")
	return nil
}

func mustGenX25519Pub() []byte {
	dev, err := x3dhpqcrypto.GenerateDeviceIdentity()
	if err != nil {
		panic(err)
	}
	return dev.PubX25519
}

func mustGenEd25519Pub() []byte {
	dev, err := x3dhpqcrypto.GenerateDeviceIdentity()
	if err != nil {
		panic(err)
	}
	return dev.PubEd25519
}

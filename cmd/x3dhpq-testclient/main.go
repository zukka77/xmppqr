// SPDX-License-Identifier: AGPL-3.0-or-later
// Command x3dhpq-testclient is a CLI for testing the X3DHPQ Triple Ratchet.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/danielinux/xmppqr/internal/x3dhpq"
	"github.com/danielinux/xmppqr/internal/x3dhpqcrypto"
	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

func main() {
	cmd := "selftest"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "info":
		runInfo()
	case "selftest":
		if err := runSelfTest(); err != nil {
			fmt.Fprintf(os.Stderr, "selftest failed: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q; usage: x3dhpq-testclient [selftest|info]\n", cmd)
		os.Exit(1)
	}
}

func runInfo() {
	fmt.Println("wolfSSL crypto backend: wolfCrypt")
	fmt.Println("KEM: ML-KEM-768 (FIPS 203)")
	fmt.Println("Signature: Ed25519")
	fmt.Println("Namespaces:")
	fmt.Println("  Root:      ", x3dhpq.NSRoot)
	fmt.Println("  Bundle:    ", x3dhpq.NSBundle)
	fmt.Println("  DeviceList:", x3dhpq.NSDeviceList)
	fmt.Println("  Envelope:  ", x3dhpq.NSEnvelope)
}

func runSelfTest() error {
	// 1. Generate identities.
	aliceID, err := x3dhpqcrypto.GenerateIdentity()
	if err != nil {
		return fmt.Errorf("alice identity: %w", err)
	}
	bobID, err := x3dhpqcrypto.GenerateIdentity()
	if err != nil {
		return fmt.Errorf("bob identity: %w", err)
	}

	// 2. Bob publishes bundle.
	bobBundle, err := x3dhpqcrypto.NewBundle(bobID, 1, 1)
	if err != nil {
		return fmt.Errorf("bob bundle: %w", err)
	}
	bobPub := bobBundle.PublicView()

	// 3. Alice runs InitiateSession.
	ephPub, ephPriv, err := wolfcrypt.GenerateX25519()
	if err != nil {
		return fmt.Errorf("alice ephem: %w", err)
	}
	aliceRK, aliceAD, kemCT, _, err := x3dhpqcrypto.InitiateSession(
		aliceID, ephPriv, ephPub, bobPub,
		bobPub.OPKs[0].ID,
		bobPub.KEMPreKeys[0].ID,
	)
	if err != nil {
		return fmt.Errorf("InitiateSession: %w", err)
	}

	// 4. Bob runs RespondSession.
	bobRK, bobAD, err := x3dhpqcrypto.RespondSession(
		bobID,
		bobBundle.SignedPreKey.PrivX25519,
		bobBundle.OneTimePreKeys[0].PrivX25519,
		aliceID.PubX25519,
		ephPub,
		bobBundle.KEMPreKeys[0].PrivMLKEM,
		kemCT,
	)
	if err != nil {
		return fmt.Errorf("RespondSession: %w", err)
	}
	if string(aliceRK) != string(bobRK) {
		return fmt.Errorf("root keys mismatch")
	}

	// Build ratchet states.
	bobRecvDH := x3dhpqcrypto.PrivPub{
		Priv: bobBundle.SignedPreKey.PrivX25519,
		Pub:  bobBundle.SignedPreKey.PubX25519,
	}
	bobState, err := x3dhpqcrypto.NewReceivingState(bobRK, bobAD, bobRecvDH)
	if err != nil {
		return fmt.Errorf("bob recv state: %w", err)
	}
	aliceState, err := x3dhpqcrypto.NewSendingState(aliceRK, aliceAD, bobBundle.SignedPreKey.PubX25519)
	if err != nil {
		return fmt.Errorf("alice send state: %w", err)
	}

	// Equip Alice with a KEM keypair to advertise.
	akPub, akPriv, err := wolfcrypt.GenerateMLKEM768()
	if err != nil {
		return fmt.Errorf("alice KEM keygen: %w", err)
	}
	aliceState.KEMRecvPub = akPub
	aliceState.KEMRecvPriv = akPriv

	// Equip Bob with KEM keypair.
	bkPub, bkPriv, err := wolfcrypt.GenerateMLKEM768()
	if err != nil {
		return fmt.Errorf("bob KEM keygen: %w", err)
	}
	bobState.KEMRecvPub = bkPub
	bobState.KEMRecvPriv = bkPriv

	// Alice→Bob: 5 messages.
	totalBytes := 0
	now := time.Now()
	for i := 0; i < 5; i++ {
		msg := fmt.Sprintf("Alice→Bob message %d", i+1)
		hdr, ct, err := aliceState.EncryptMessage([]byte(msg), now)
		if err != nil {
			return fmt.Errorf("alice encrypt[%d]: %w", i, err)
		}
		totalBytes += len(hdr.Marshal()) + len(ct)
		pt, err := bobState.DecryptMessage(hdr, ct)
		if err != nil {
			return fmt.Errorf("bob decrypt[%d]: %w", i, err)
		}
		if string(pt) != msg {
			return fmt.Errorf("plaintext mismatch[%d]: got %q", i, pt)
		}
	}

	// Bob→Alice: 5 replies. Alice needs a receive state.
	// RemoteDHPub is Alice's last known DH pub (Bob's SPK), so Bob's new DHPub triggers ratchet.
	aliceRecv := &x3dhpqcrypto.State{
		RK:                 aliceState.RK,
		SendingDH:          aliceState.SendingDH,
		RemoteDHPub:        aliceState.RemoteDHPub,
		AD:                 aliceState.AD,
		MessageKeys:        make(map[x3dhpqcrypto.SkipKey][]byte),
		LastCheckpointTime: now,
	}
	// Give Bob Alice's KEM pub to send checkpoints to.
	bobState.KEMSendPub = akPub

	for i := 0; i < 5; i++ {
		msg := fmt.Sprintf("Bob→Alice reply %d", i+1)
		hdr, ct, err := bobState.EncryptMessage([]byte(msg), now)
		if err != nil {
			return fmt.Errorf("bob encrypt[%d]: %w", i, err)
		}
		totalBytes += len(hdr.Marshal()) + len(ct)
		pt, err := aliceRecv.DecryptMessage(hdr, ct)
		if err != nil {
			return fmt.Errorf("alice decrypt reply[%d]: %w", i, err)
		}
		if string(pt) != msg {
			return fmt.Errorf("reply plaintext mismatch[%d]: got %q", i, pt)
		}
	}

	fmt.Printf("selftest: OK — 10 messages exchanged, %d bytes total\n", totalBytes)
	return nil
}

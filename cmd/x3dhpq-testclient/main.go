// SPDX-License-Identifier: AGPL-3.0-or-later
// Command x3dhpq-testclient is a CLI for testing the X3DHPQ Triple Ratchet.
package main

import (
	"bytes"
	"errors"
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

type Account struct {
	AIK *x3dhpqcrypto.AccountIdentityKey
}

type Device struct {
	Account *Account
	DIK     *x3dhpqcrypto.DeviceIdentityKey
	Cert    *x3dhpqcrypto.DeviceCertificate
	Bundle  *x3dhpqcrypto.Bundle
}

func newAccount() (*Account, error) {
	aik, err := x3dhpqcrypto.GenerateAccountIdentity()
	if err != nil {
		return nil, err
	}
	return &Account{AIK: aik}, nil
}

func (a *Account) addDevice(deviceID uint32, primary bool, kemPreKeys, otpks int) (*Device, error) {
	dik, err := x3dhpqcrypto.GenerateDeviceIdentity()
	if err != nil {
		return nil, err
	}
	flags := uint8(0)
	if primary {
		flags = x3dhpqcrypto.DeviceFlagPrimary
	}
	dc, err := a.AIK.IssueDeviceCert(dik, deviceID, flags)
	if err != nil {
		return nil, err
	}
	bundle, err := x3dhpqcrypto.NewBundle(dik, dc, kemPreKeys, otpks)
	if err != nil {
		return nil, err
	}
	bundle.AccountIdentity = a.AIK
	return &Device{Account: a, DIK: dik, Cert: dc, Bundle: bundle}, nil
}

// exchangeMessages encrypts n messages from sender to receiver and n back,
// asserting all round-trip correctly. Returns total bytes exchanged.
func exchangeMessages(sender, receiver *x3dhpqcrypto.State, n int) (int, error) {
	now := time.Now()
	total := 0

	hdrs := make([]*x3dhpqcrypto.MessageHeader, n)
	cts := make([][]byte, n)
	msgs := make([]string, n)
	for i := 0; i < n; i++ {
		msgs[i] = fmt.Sprintf("msg-fwd-%d", i)
		hdr, ct, err := sender.EncryptMessage([]byte(msgs[i]), now)
		if err != nil {
			return total, fmt.Errorf("encrypt fwd[%d]: %w", i, err)
		}
		hdrs[i] = hdr
		cts[i] = ct
		total += len(hdr.Marshal()) + len(ct)
	}
	for i := 0; i < n; i++ {
		pt, err := receiver.DecryptMessage(hdrs[i], cts[i])
		if err != nil {
			return total, fmt.Errorf("decrypt fwd[%d]: %w", i, err)
		}
		if string(pt) != msgs[i] {
			return total, fmt.Errorf("fwd plaintext mismatch[%d]: got %q want %q", i, pt, msgs[i])
		}
	}

	recvReply := &x3dhpqcrypto.State{
		RK:                 sender.RK,
		SendingDH:          sender.SendingDH,
		RemoteDHPub:        sender.RemoteDHPub,
		AD:                 sender.AD,
		MessageKeys:        make(map[x3dhpqcrypto.SkipKey][]byte),
		LastCheckpointTime: now,
	}

	replyHdrs := make([]*x3dhpqcrypto.MessageHeader, n)
	replyCTs := make([][]byte, n)
	replyMsgs := make([]string, n)
	for i := 0; i < n; i++ {
		replyMsgs[i] = fmt.Sprintf("msg-rev-%d", i)
		hdr, ct, err := receiver.EncryptMessage([]byte(replyMsgs[i]), now)
		if err != nil {
			return total, fmt.Errorf("encrypt rev[%d]: %w", i, err)
		}
		replyHdrs[i] = hdr
		replyCTs[i] = ct
		total += len(hdr.Marshal()) + len(ct)
	}
	for i := 0; i < n; i++ {
		pt, err := recvReply.DecryptMessage(replyHdrs[i], replyCTs[i])
		if err != nil {
			return total, fmt.Errorf("decrypt rev[%d]: %w", i, err)
		}
		if string(pt) != replyMsgs[i] {
			return total, fmt.Errorf("rev plaintext mismatch[%d]: got %q want %q", i, pt, replyMsgs[i])
		}
	}
	return total, nil
}

// openSession initiates from sender to recipient, returns (senderState, recipientState, error).
// peerAIK is the AIK the sender uses to verify the recipient's DC.
func openSession(senderDIK *x3dhpqcrypto.DeviceIdentityKey, recipientBundle *x3dhpqcrypto.Bundle, peerAIK *x3dhpqcrypto.AccountIdentityPub, senderDC *x3dhpqcrypto.DeviceCertificate, senderAIK *x3dhpqcrypto.AccountIdentityPub) (*x3dhpqcrypto.State, *x3dhpqcrypto.State, error) {
	pub := recipientBundle.PublicView()

	ephPub, ephPriv, err := wolfcrypt.GenerateX25519()
	if err != nil {
		return nil, nil, fmt.Errorf("ephem keygen: %w", err)
	}

	opkID := uint32(0)
	if len(pub.OPKs) > 0 {
		opkID = pub.OPKs[0].ID
	}
	kemID := pub.KEMPreKeys[0].ID

	senderRK, senderAD, kemCT, opkUsed, err := x3dhpqcrypto.InitiateSession(
		senderDIK, ephPriv, ephPub, pub, peerAIK, opkID, kemID,
	)
	if err != nil {
		return nil, nil, err
	}

	var opkPriv []byte
	if opkUsed && len(recipientBundle.OneTimePreKeys) > 0 {
		opkPriv = recipientBundle.OneTimePreKeys[0].PrivX25519
	}

	recipientRK, recipientAD, err := x3dhpqcrypto.RespondSession(
		recipientBundle.DeviceIdentity,
		recipientBundle.SignedPreKey.PrivX25519,
		opkPriv,
		senderDC,
		senderAIK,
		ephPub,
		recipientBundle.KEMPreKeys[0].PrivMLKEM,
		kemCT,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("RespondSession: %w", err)
	}

	if !bytes.Equal(senderRK, recipientRK) {
		return nil, nil, fmt.Errorf("root keys mismatch")
	}

	recvDH := x3dhpqcrypto.PrivPub{
		Priv: recipientBundle.SignedPreKey.PrivX25519,
		Pub:  recipientBundle.SignedPreKey.PubX25519,
	}
	recipientState, err := x3dhpqcrypto.NewReceivingState(recipientRK, recipientAD, recvDH)
	if err != nil {
		return nil, nil, fmt.Errorf("NewReceivingState: %w", err)
	}
	senderState, err := x3dhpqcrypto.NewSendingState(senderRK, senderAD, recipientBundle.SignedPreKey.PubX25519)
	if err != nil {
		return nil, nil, fmt.Errorf("NewSendingState: %w", err)
	}

	akPub, akPriv, err := wolfcrypt.GenerateMLKEM768()
	if err != nil {
		return nil, nil, fmt.Errorf("sender KEM keygen: %w", err)
	}
	senderState.KEMRecvPub = akPub
	senderState.KEMRecvPriv = akPriv

	bkPub, bkPriv, err := wolfcrypt.GenerateMLKEM768()
	if err != nil {
		return nil, nil, fmt.Errorf("recipient KEM keygen: %w", err)
	}
	recipientState.KEMRecvPub = bkPub
	recipientState.KEMRecvPriv = bkPriv

	return senderState, recipientState, nil
}

func runSelfTest() error {
	aliceAcct, err := newAccount()
	if err != nil {
		return fmt.Errorf("alice account: %w", err)
	}
	aliceA1, err := aliceAcct.addDevice(1, true, 4, 4)
	if err != nil {
		return fmt.Errorf("alice A1: %w", err)
	}
	if err := aliceA1.Cert.Verify(aliceAcct.AIK.Public()); err != nil {
		return fmt.Errorf("DC_A1 verify: %w", err)
	}
	aliceA2, err := aliceAcct.addDevice(2, false, 4, 4)
	if err != nil {
		return fmt.Errorf("alice A2: %w", err)
	}
	if err := aliceA2.Cert.Verify(aliceAcct.AIK.Public()); err != nil {
		return fmt.Errorf("DC_A2 verify: %w", err)
	}

	fmt.Printf("ALICE account:\n")
	fmt.Printf("  AIK_A (fingerprint: %s)\n", aliceAcct.AIK.Public().Fingerprint())
	fmt.Printf("  Device A1 (primary, id 1) — DC verified ✓\n")
	fmt.Printf("  Device A2 (secondary, id 2) — DC verified ✓\n")

	bobAcct, err := newAccount()
	if err != nil {
		return fmt.Errorf("bob account: %w", err)
	}
	bobB1, err := bobAcct.addDevice(1, true, 4, 4)
	if err != nil {
		return fmt.Errorf("bob B1: %w", err)
	}
	if err := bobB1.Cert.Verify(bobAcct.AIK.Public()); err != nil {
		return fmt.Errorf("DC_B1 verify: %w", err)
	}

	fmt.Printf("\nBOB account:\n")
	fmt.Printf("  AIK_B (fingerprint: %s)\n", bobAcct.AIK.Public().Fingerprint())
	fmt.Printf("  Device B1 (primary, id 1) — DC verified ✓\n")

	totalMsgs := 0
	totalBytes := 0

	fmt.Printf("\nPhase 1: Bob → Alice's primary (DC_A1)\n")
	bobSend1, aliceRecv1, err := openSession(bobB1.DIK, aliceA1.Bundle, aliceAcct.AIK.Public(), bobB1.Cert, bobAcct.AIK.Public())
	if err != nil {
		return fmt.Errorf("phase 1 openSession: %w", err)
	}
	fmt.Printf("  InitiateSession verified DC_A1 against pinned AIK_A ✓\n")
	n, err := exchangeMessages(bobSend1, aliceRecv1, 5)
	if err != nil {
		return fmt.Errorf("phase 1 exchange: %w", err)
	}
	totalMsgs += 10
	totalBytes += n
	fmt.Printf("  Exchanged 5 messages each way, all decrypted successfully\n")

	fmt.Printf("\nPhase 2: Bob → Alice's secondary (DC_A2)\n")
	bobSend2, aliceRecv2, err := openSession(bobB1.DIK, aliceA2.Bundle, aliceAcct.AIK.Public(), bobB1.Cert, bobAcct.AIK.Public())
	if err != nil {
		return fmt.Errorf("phase 2 openSession: %w", err)
	}
	fmt.Printf("  InitiateSession verified DC_A2 against pinned AIK_A ✓\n")
	n, err = exchangeMessages(bobSend2, aliceRecv2, 5)
	if err != nil {
		return fmt.Errorf("phase 2 exchange: %w", err)
	}
	totalMsgs += 10
	totalBytes += n
	fmt.Printf("  Exchanged 5 messages each way, all decrypted successfully\n")

	fmt.Printf("\nPhase 3: Rogue device rejection\n")
	rogueAcct, err := newAccount()
	if err != nil {
		return fmt.Errorf("rogue AIK: %w", err)
	}
	rogueDev, err := rogueAcct.addDevice(99, false, 4, 0)
	if err != nil {
		return fmt.Errorf("rogue device: %w", err)
	}
	roguePub := rogueDev.Bundle.PublicView()
	ephPub, ephPriv, err := wolfcrypt.GenerateX25519()
	if err != nil {
		return fmt.Errorf("rogue ephem: %w", err)
	}
	fmt.Printf("  Rogue bundle: DC signed by AIK_X (unrelated)\n")
	_, _, _, _, err = x3dhpqcrypto.InitiateSession(
		bobB1.DIK, ephPriv, ephPub, roguePub,
		aliceAcct.AIK.Public(),
		0,
		roguePub.KEMPreKeys[0].ID,
	)
	if !errors.Is(err, x3dhpqcrypto.ErrUntrustedDevice) {
		return fmt.Errorf("phase 3: expected ErrUntrustedDevice, got %v", err)
	}
	fmt.Printf("  Bob's InitiateSession returned ErrUntrustedDevice ✓\n")

	fmt.Printf("\nPhase 4: Tampered DC rejection\n")
	tamperedDC := *aliceA1.Cert
	tamperedPub := make([]byte, len(tamperedDC.DIKPubEd25519))
	copy(tamperedPub, tamperedDC.DIKPubEd25519)
	tamperedPub[0] ^= 0xFF
	tamperedDC.DIKPubEd25519 = tamperedPub
	fmt.Printf("  DC_A1 modified post-signing (DIKPubEd25519 byte flipped)\n")
	if err := tamperedDC.Verify(aliceAcct.AIK.Public()); err == nil {
		return fmt.Errorf("phase 4: expected Verify to fail on tampered DC")
	}
	fmt.Printf("  DC.Verify(AIKPub_A) returned error ✓\n")

	fmt.Printf("\nselftest: OK — %d messages exchanged across 2 sessions, %d bytes total\n", totalMsgs, totalBytes)
	return nil
}

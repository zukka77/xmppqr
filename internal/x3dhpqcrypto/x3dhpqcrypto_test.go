// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"bytes"
	"testing"
	"time"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

// issueTestDC is a helper that generates an AIK, issues a DC for dik, and returns both.
func issueTestDC(t *testing.T, dik *DeviceIdentityKey) (*AccountIdentityKey, *DeviceCertificate) {
	t.Helper()
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dc, err := aik.IssueDeviceCert(dik, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	return aik, dc
}

func TestIdentityRoundTrip(t *testing.T) {
	id, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello identity")
	sig, err := wolfcrypt.Ed25519Sign(id.PrivEd25519, msg)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := wolfcrypt.Ed25519Verify(id.PubEd25519, msg, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("signature verification failed")
	}
}

func TestBundleRoundTrip(t *testing.T) {
	id, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	aik, dc := issueTestDC(t, id)
	b, err := NewBundle(id, dc, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	b.AccountIdentity = aik
	pub := b.PublicView()

	ok, err := wolfcrypt.Ed25519Verify(pub.IdentityPubEd25519, spkSignInput(pub.SPKPub, pub.SPKID), pub.SPKSig)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("SPK signature invalid")
	}
	if len(pub.KEMPreKeys) != 2 {
		t.Fatalf("expected 2 KEM prekeys, got %d", len(pub.KEMPreKeys))
	}
	if len(pub.OPKs) != 3 {
		t.Fatalf("expected 3 OPKs, got %d", len(pub.OPKs))
	}
}

func TestX3DH_PQ_Symmetric(t *testing.T) {
	aliceAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bobAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	aliceDIK, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bobDIK, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	aliceDC, err := aliceAIK.IssueDeviceCert(aliceDIK, 1, DeviceFlagPrimary)
	if err != nil {
		t.Fatal(err)
	}
	bobDC, err := bobAIK.IssueDeviceCert(bobDIK, 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	bobBundle, err := NewBundle(bobDIK, bobDC, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	bobBundle.AccountIdentity = bobAIK
	bobPub := bobBundle.PublicView()

	ephPub, ephPriv, err := wolfcrypt.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}

	aliceRK, _, kemCT, opkUsed, err := InitiateSession(aliceDIK, ephPriv, ephPub, bobPub, bobAIK.Public(), bobPub.OPKs[0].ID, bobPub.KEMPreKeys[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !opkUsed {
		t.Fatal("expected OPK to be used")
	}

	var opkPriv []byte
	if opkUsed {
		opkPriv = bobBundle.OneTimePreKeys[0].PrivX25519
	}

	bobRK, _, err := RespondSession(
		bobDIK,
		bobBundle.SignedPreKey.PrivX25519,
		opkPriv,
		aliceDC,
		aliceAIK.Public(),
		ephPub,
		bobBundle.KEMPreKeys[0].PrivMLKEM,
		kemCT,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(aliceRK, bobRK) {
		t.Fatal("root keys do not match")
	}
}

func TestX3DH_PQ_UntrustedDeviceRejected(t *testing.T) {
	realAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	otherAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bobDIK, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	// DC signed by otherAIK (not realAIK that alice has pinned)
	bobDC, err := otherAIK.IssueDeviceCert(bobDIK, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	bobBundle, err := NewBundle(bobDIK, bobDC, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	bobBundle.AccountIdentity = otherAIK
	bobPub := bobBundle.PublicView()

	aliceDIK, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ephPub, ephPriv, err := wolfcrypt.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, _, err = InitiateSession(aliceDIK, ephPriv, ephPub, bobPub, realAIK.Public(), 0, bobPub.KEMPreKeys[0].ID)
	if err != ErrUntrustedDevice {
		t.Fatalf("expected ErrUntrustedDevice, got %v", err)
	}
}

func setupX3DH(t *testing.T) (aliceRK, bobRK, aliceAD, bobAD []byte, aliceEphPub []byte, bobBundle *Bundle) {
	t.Helper()
	aliceDIK, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	aliceAIK, aliceDC := issueTestDC(t, aliceDIK)
	bobDIK, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bobAIK, bobDC := issueTestDC(t, bobDIK)
	bobBundle, err = NewBundle(bobDIK, bobDC, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	bobBundle.AccountIdentity = bobAIK
	bobPub := bobBundle.PublicView()

	ephPub, ephPriv, err := wolfcrypt.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	aliceEphPub = ephPub

	aliceRK, aliceAD, _, _, err = InitiateSession(aliceDIK, ephPriv, ephPub, bobPub, bobAIK.Public(), 0, bobPub.KEMPreKeys[0].ID)
	if err != nil {
		t.Fatal(err)
	}

	// Need kemCT from a separate call for bob to use.
	_, _, kemCT, _, err := InitiateSession(aliceDIK, ephPriv, ephPub, bobPub, bobAIK.Public(), 0, bobPub.KEMPreKeys[0].ID)
	if err != nil {
		t.Fatal(err)
	}

	bobRK, bobAD, err = RespondSession(
		bobDIK,
		bobBundle.SignedPreKey.PrivX25519,
		nil,
		aliceDC,
		aliceAIK.Public(),
		ephPub,
		bobBundle.KEMPreKeys[0].PrivMLKEM,
		kemCT,
	)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func buildSession(t *testing.T) (aliceSend *State, bobRecv *State, aliceKEMPub []byte, bobKEMPriv []byte) {
	t.Helper()
	aliceDIK, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	aliceAIK, aliceDC := issueTestDC(t, aliceDIK)
	bobDIK, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bobAIK, bobDC := issueTestDC(t, bobDIK)
	bobBundle, err := NewBundle(bobDIK, bobDC, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	bobBundle.AccountIdentity = bobAIK
	bobPub := bobBundle.PublicView()

	ephPub, ephPriv, err := wolfcrypt.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}

	aliceRK, aliceAD, kemCT, _, err := InitiateSession(aliceDIK, ephPriv, ephPub, bobPub, bobAIK.Public(), 0, bobPub.KEMPreKeys[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	bobRK, bobAD, err := RespondSession(
		bobDIK,
		bobBundle.SignedPreKey.PrivX25519,
		nil,
		aliceDC,
		aliceAIK.Public(),
		ephPub,
		bobBundle.KEMPreKeys[0].PrivMLKEM,
		kemCT,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aliceRK, bobRK) {
		t.Fatal("root keys mismatch in buildSession")
	}

	bobRecvDH := PrivPub{Priv: bobBundle.SignedPreKey.PrivX25519, Pub: bobBundle.SignedPreKey.PubX25519}
	bobRecv, err = NewReceivingState(bobRK, bobAD, bobRecvDH)
	if err != nil {
		t.Fatal(err)
	}

	aliceSend, err = NewSendingState(aliceRK, aliceAD, bobBundle.SignedPreKey.PubX25519)
	if err != nil {
		t.Fatal(err)
	}

	kPub, kPriv, err := wolfcrypt.GenerateMLKEM768()
	if err != nil {
		t.Fatal(err)
	}
	aliceSend.KEMRecvPub = kPub
	aliceSend.KEMRecvPriv = kPriv

	bkPub, bkPriv, err := wolfcrypt.GenerateMLKEM768()
	if err != nil {
		t.Fatal(err)
	}
	bobRecv.KEMRecvPub = bkPub
	bobRecv.KEMRecvPriv = bkPriv
	aliceKEMPub = kPub
	bobKEMPriv = bkPriv

	return aliceSend, bobRecv, aliceKEMPub, bobKEMPriv
}

func TestRatchetSimpleExchange(t *testing.T) {
	alice, bob, _, _ := buildSession(t)

	hdr, ct, err := alice.EncryptMessage([]byte("hello bob"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pt, err := bob.DecryptMessage(hdr, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hello bob" {
		t.Fatalf("got %q", pt)
	}
}

func TestRatchetBidirectional(t *testing.T) {
	alice, bob, _, _ := buildSession(t)

	headers := make([]*MessageHeader, 5)
	cts := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		hdr, ct, err := alice.EncryptMessage([]byte("A→B"), time.Now())
		if err != nil {
			t.Fatalf("encrypt A→B[%d]: %v", i, err)
		}
		headers[i] = hdr
		cts[i] = ct
	}
	for i := 0; i < 5; i++ {
		pt, err := bob.DecryptMessage(headers[i], cts[i])
		if err != nil {
			t.Fatalf("decrypt A→B[%d]: %v", i, err)
		}
		if string(pt) != "A→B" {
			t.Fatalf("wrong plaintext [%d]: %q", i, pt)
		}
	}

	aliceRecv := &State{
		RK:                 alice.RK,
		SendingDH:          alice.SendingDH,
		RemoteDHPub:        alice.RemoteDHPub,
		AD:                 alice.AD,
		MessageKeys:        make(map[skipKey][]byte),
		LastCheckpointTime: time.Now(),
	}

	for i := 0; i < 5; i++ {
		hdr, ct, err := bob.EncryptMessage([]byte("B→A"), time.Now())
		if err != nil {
			t.Fatalf("encrypt B→A[%d]: %v", i, err)
		}
		pt, err := aliceRecv.DecryptMessage(hdr, ct)
		if err != nil {
			t.Fatalf("decrypt B→A[%d]: %v", i, err)
		}
		if string(pt) != "B→A" {
			t.Fatalf("wrong plaintext B→A[%d]: %q", i, pt)
		}
	}
}

func TestRatchetOutOfOrder(t *testing.T) {
	alice, bob, _, _ := buildSession(t)

	msgs := []string{"first", "second", "third"}
	headers := make([]*MessageHeader, len(msgs))
	cts := make([][]byte, len(msgs))
	for i, m := range msgs {
		hdr, ct, err := alice.EncryptMessage([]byte(m), time.Now())
		if err != nil {
			t.Fatalf("encrypt[%d]: %v", i, err)
		}
		headers[i] = hdr
		cts[i] = ct
	}

	for i := len(msgs) - 1; i >= 0; i-- {
		pt, err := bob.DecryptMessage(headers[i], cts[i])
		if err != nil {
			t.Fatalf("decrypt[%d]: %v", i, err)
		}
		if string(pt) != msgs[i] {
			t.Fatalf("wrong plaintext[%d]: got %q want %q", i, pt, msgs[i])
		}
	}
}

func TestKEMCheckpoint(t *testing.T) {
	alice, bob, _, _ := buildSession(t)

	bkPub, bkPriv, err := wolfcrypt.GenerateMLKEM768()
	if err != nil {
		t.Fatal(err)
	}
	alice.KEMSendPub = bkPub
	bob.KEMRecvPriv = bkPriv

	var checkpointIdx int = -1
	for i := 0; i <= kemCheckpointK; i++ {
		hdr, ct, err := alice.EncryptMessage([]byte("msg"), time.Now())
		if err != nil {
			t.Fatalf("encrypt[%d]: %v", i, err)
		}
		if hdr.KEMCiphertext != nil && checkpointIdx == -1 {
			checkpointIdx = i
		}
		_, err = bob.DecryptMessage(hdr, ct)
		if err != nil {
			t.Fatalf("decrypt[%d]: %v", i, err)
		}
	}
	if checkpointIdx == -1 {
		t.Fatal("no KEM checkpoint triggered in K+1 messages")
	}
	if checkpointIdx > kemCheckpointK {
		t.Fatalf("checkpoint triggered too late at message %d (K=%d)", checkpointIdx, kemCheckpointK)
	}
}

func TestTamperedCiphertextRejected(t *testing.T) {
	alice, bob, _, _ := buildSession(t)

	hdr, ct, err := alice.EncryptMessage([]byte("secret"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ct[0] ^= 0xFF
	_, err = bob.DecryptMessage(hdr, ct)
	if err == nil {
		t.Fatal("expected decryption failure on tampered ciphertext")
	}
}

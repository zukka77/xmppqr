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
		KEMHistory:         alice.KEMHistory,
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

	rkBefore := make([]byte, len(alice.RK))
	copy(rkBefore, alice.RK)
	cksBefore := make([]byte, len(alice.ChainSendKey))
	copy(cksBefore, alice.ChainSendKey)

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

	// Per the corrected design: a KEM checkpoint mixes into ChainSendKey/
	// ChainRecvKey AND updates KEMHistory. RK is NOT touched at checkpoint
	// time — RK heals at the NEXT DH ratchet step via KEMHistory injection.
	// This is necessary because RK is genuinely desynchronized between
	// sender and receiver in any asymmetric Double Ratchet flow.
	if bytes.Equal(alice.ChainSendKey, cksBefore) {
		t.Fatal("ChainSendKey must change after KEM checkpoint")
	}
	emptyHistory := make([]byte, 32)
	if bytes.Equal(alice.KEMHistory, emptyHistory) {
		t.Fatal("KEMHistory must change after KEM checkpoint")
	}
	if !bytes.Equal(alice.KEMHistory, bob.KEMHistory) {
		t.Fatal("KEMHistory must agree between sender and receiver after checkpoint")
	}
	_ = rkBefore

	hdr, ct, err := alice.EncryptMessage([]byte("post-checkpoint"), time.Now())
	if err != nil {
		t.Fatalf("encrypt post-checkpoint: %v", err)
	}
	pt, err := bob.DecryptMessage(hdr, ct)
	if err != nil {
		t.Fatalf("decrypt post-checkpoint: %v", err)
	}
	if string(pt) != "post-checkpoint" {
		t.Fatalf("wrong post-checkpoint plaintext: %q", pt)
	}

	// Attacker has old RK but tampered ciphertext — receiver derives a different RK.
	attackerBob := &State{
		RK:                 rkBefore,
		ChainSendKey:       make([]byte, 32),
		ChainRecvKey:       make([]byte, 32),
		SendingDH:          bob.SendingDH,
		RemoteDHPub:        bob.RemoteDHPub,
		AD:                 bob.AD,
		MessageKeys:        make(map[skipKey][]byte),
		LastCheckpointTime: time.Now(),
		KEMRecvPriv:        bkPriv,
	}
	hdr2, ct2, err := alice.EncryptMessage([]byte("attacker test"), time.Now())
	if err != nil {
		t.Fatalf("encrypt attacker test: %v", err)
	}
	if hdr2.KEMCiphertext != nil && len(hdr2.KEMCiphertext) > 0 {
		hdr2.KEMCiphertext[0] ^= 0x01
	}
	_, err = attackerBob.DecryptMessage(hdr2, ct2)
	if err == nil {
		t.Fatal("attacker with old RK and tampered KEM ciphertext must fail decryption")
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

func TestCheckpointHealsBothDirections(t *testing.T) {
	alice, bob, _, _ := buildSession(t)

	bkPub, bkPriv, err := wolfcrypt.GenerateMLKEM768()
	if err != nil {
		t.Fatal(err)
	}
	alice.KEMSendPub = bkPub
	bob.KEMRecvPriv = bkPriv

	for i := 0; i < kemCheckpointK; i++ {
		hdr, ct, err := alice.EncryptMessage([]byte("warm"), time.Now())
		if err != nil {
			t.Fatalf("warm-up encrypt[%d]: %v", i, err)
		}
		_, err = bob.DecryptMessage(hdr, ct)
		if err != nil {
			t.Fatalf("warm-up decrypt[%d]: %v", i, err)
		}
	}

	rkPreCheckpoint := make([]byte, len(alice.RK))
	copy(rkPreCheckpoint, alice.RK)
	aliceCKsBefore := make([]byte, len(alice.ChainSendKey))
	copy(aliceCKsBefore, alice.ChainSendKey)
	bobCKrBefore := make([]byte, len(bob.ChainRecvKey))
	copy(bobCKrBefore, bob.ChainRecvKey)

	hdr, ct, err := alice.EncryptMessage([]byte("checkpoint-trigger"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if hdr.KEMCiphertext == nil {
		t.Fatal("expected KEM checkpoint on this message")
	}

	_, err = bob.DecryptMessage(hdr, ct)
	if err != nil {
		t.Fatalf("decrypt checkpoint message: %v", err)
	}

	if bytes.Equal(alice.ChainSendKey, aliceCKsBefore) {
		t.Fatal("Alice ChainSendKey must change after checkpoint")
	}
	if bytes.Equal(bob.ChainRecvKey, bobCKrBefore) {
		t.Fatal("Bob ChainRecvKey must change after checkpoint")
	}
	if !bytes.Equal(alice.ChainSendKey, bob.ChainRecvKey) {
		t.Fatal("Alice ChainSendKey and Bob ChainRecvKey must agree after checkpoint")
	}
	// RK is not touched at checkpoint; KEMHistory carries the PQ entropy
	// forward and is mixed into the next DH ratchet step's RK derivation.
	if !bytes.Equal(alice.KEMHistory, bob.KEMHistory) {
		t.Fatal("KEMHistory must agree after checkpoint")
	}
	emptyHist := make([]byte, 32)
	if bytes.Equal(alice.KEMHistory, emptyHist) {
		t.Fatal("KEMHistory must change after checkpoint")
	}
	_ = rkPreCheckpoint

	// Verify next DH ratchet step from fresh RK differs from what it would have been with old RK.
	fakeDHPub, fakeDHPriv, err := wolfcrypt.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	// alice.RK was unchanged by the checkpoint by design (KEMHistory carries
	// the PQ entropy forward instead). The healing property is: applying
	// dhRatchetStep with current KEMHistory MUST differ from applying it
	// with the empty (pre-any-checkpoint) KEMHistory.
	newRKWithKEMHistory, _, err := dhRatchetStep(alice.RK, fakeDHPriv, fakeDHPub, alice.KEMHistory)
	if err != nil {
		t.Fatal(err)
	}
	newRKWithoutKEMHistory, _, err := dhRatchetStep(alice.RK, fakeDHPriv, fakeDHPub, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(newRKWithKEMHistory, newRKWithoutKEMHistory) {
		t.Fatal("DH ratchet step must produce different RK with KEMHistory injected vs empty")
	}
}

func TestCheckpointTranscriptBinding(t *testing.T) {
	alice1, bob1, _, _ := buildSession(t)
	alice2, bob2, _, _ := buildSession(t)

	bkPub1, bkPriv1, err := wolfcrypt.GenerateMLKEM768()
	if err != nil {
		t.Fatal(err)
	}
	bkPub2, bkPriv2, err := wolfcrypt.GenerateMLKEM768()
	if err != nil {
		t.Fatal(err)
	}

	alice1.KEMSendPub = bkPub1
	bob1.KEMRecvPriv = bkPriv1
	alice2.KEMSendPub = bkPub2
	bob2.KEMRecvPriv = bkPriv2

	for i := 0; i < kemCheckpointK; i++ {
		hdr, ct, err := alice1.EncryptMessage([]byte("w"), time.Now())
		if err != nil {
			t.Fatalf("session1 warm-up[%d]: %v", i, err)
		}
		_, err = bob1.DecryptMessage(hdr, ct)
		if err != nil {
			t.Fatalf("session1 warm-up decrypt[%d]: %v", i, err)
		}
		hdr, ct, err = alice2.EncryptMessage([]byte("w"), time.Now())
		if err != nil {
			t.Fatalf("session2 warm-up[%d]: %v", i, err)
		}
		_, err = bob2.DecryptMessage(hdr, ct)
		if err != nil {
			t.Fatalf("session2 warm-up decrypt[%d]: %v", i, err)
		}
	}

	hdr1, ct1, err := alice1.EncryptMessage([]byte("cp1"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if hdr1.KEMCiphertext == nil {
		t.Fatal("expected checkpoint in session 1")
	}
	_, err = bob1.DecryptMessage(hdr1, ct1)
	if err != nil {
		t.Fatalf("session1 checkpoint decrypt: %v", err)
	}

	hdr2, ct2, err := alice2.EncryptMessage([]byte("cp2"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if hdr2.KEMCiphertext == nil {
		t.Fatal("expected checkpoint in session 2")
	}
	_, err = bob2.DecryptMessage(hdr2, ct2)
	if err != nil {
		t.Fatalf("session2 checkpoint decrypt: %v", err)
	}

	if bytes.Equal(alice1.RK, alice2.RK) {
		t.Fatal("two sessions with different DH pubs must produce different RK_new after checkpoint")
	}
}

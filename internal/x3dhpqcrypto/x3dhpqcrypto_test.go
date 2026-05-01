// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"testing"
	"time"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

func TestIdentityRoundTrip(t *testing.T) {
	id, err := GenerateIdentity()
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
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewBundle(id, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	pub := b.PublicView()

	// Verify SPK signature.
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
	aliceID, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bobID, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bobBundle, err := NewBundle(bobID, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	bobPub := bobBundle.PublicView()

	// Alice generates ephemeral key.
	ephPub, ephPriv, err := wolfcrypt.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}

	aliceRK, aliceAD, kemCT, opkUsed, err := InitiateSession(aliceID, ephPriv, ephPub, bobPub, bobPub.OPKs[0].ID, bobPub.KEMPreKeys[0].ID)
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

	bobRK, bobAD, err := RespondSession(
		bobID,
		bobBundle.SignedPreKey.PrivX25519,
		opkPriv,
		aliceID.PubX25519,
		ephPub,
		bobBundle.KEMPreKeys[0].PrivMLKEM,
		kemCT,
	)
	if err != nil {
		t.Fatal(err)
	}

	if string(aliceRK) != string(bobRK) {
		t.Fatal("root keys do not match")
	}
	// AD: alice builds IK_A||IK_B, bob builds IK_A||IK_B (peer||mine).
	_ = aliceAD
	_ = bobAD
}

func setupX3DH(t *testing.T) (aliceRK, bobRK, aliceAD, bobAD []byte, aliceEphPub []byte, bobBundle *Bundle) {
	t.Helper()
	aliceID, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bobID, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bobBundle, err = NewBundle(bobID, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	bobPub := bobBundle.PublicView()

	ephPub, ephPriv, err := wolfcrypt.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	aliceEphPub = ephPub

	aliceRK, aliceAD, _, _, err = InitiateSession(aliceID, ephPriv, ephPub, bobPub, 0, bobPub.KEMPreKeys[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	bobRK, bobAD, err = RespondSession(
		bobID,
		bobBundle.SignedPreKey.PrivX25519,
		nil,
		aliceID.PubX25519,
		ephPub,
		bobBundle.KEMPreKeys[0].PrivMLKEM,
		func() []byte {
			_, kemCT, _, _, _ := InitiateSession(aliceID, ephPriv, ephPub, bobPub, 0, bobPub.KEMPreKeys[0].ID)
			return kemCT
		}(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return
}

// buildSession builds a symmetric pair of ratchet states without the setupX3DH
// helper complexity. Returns (aliceSend, bobRecv) and shared rootKey/ad.
func buildSession(t *testing.T) (aliceSend *State, bobRecv *State, aliceKEMPub []byte, bobKEMPriv []byte) {
	t.Helper()
	aliceID, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bobID, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bobBundle, err := NewBundle(bobID, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	bobPub := bobBundle.PublicView()

	ephPub, ephPriv, err := wolfcrypt.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}

	aliceRK, aliceAD, kemCT, _, err := InitiateSession(aliceID, ephPriv, ephPub, bobPub, 0, bobPub.KEMPreKeys[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	bobRK, bobAD, err := RespondSession(
		bobID,
		bobBundle.SignedPreKey.PrivX25519,
		nil,
		aliceID.PubX25519,
		ephPub,
		bobBundle.KEMPreKeys[0].PrivMLKEM,
		kemCT,
	)
	if err != nil {
		t.Fatal(err)
	}
	if string(aliceRK) != string(bobRK) {
		t.Fatal("root keys mismatch in buildSession")
	}

	// Alice sends, Bob receives.
	// Bob's receiving state uses bobRK and his SPK DH pair.
	bobRecvDH := PrivPub{Priv: bobBundle.SignedPreKey.PrivX25519, Pub: bobBundle.SignedPreKey.PubX25519}
	bobRecv, err = NewReceivingState(bobRK, bobAD, bobRecvDH)
	if err != nil {
		t.Fatal(err)
	}

	// Alice's sending state: peer DH = Bob's SPK pub.
	aliceSend, err = NewSendingState(aliceRK, aliceAD, bobBundle.SignedPreKey.PubX25519)
	if err != nil {
		t.Fatal(err)
	}

	// Generate KEM keypair for Alice to advertise; Bob will need it for checkpoints.
	kPub, kPriv, err := wolfcrypt.GenerateMLKEM768()
	if err != nil {
		t.Fatal(err)
	}
	aliceSend.KEMRecvPub = kPub
	aliceSend.KEMRecvPriv = kPriv

	// Bob needs a KEM pub to send checkpoints to Alice.
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

	// After Bob decrypts a message he can build a send state back to Alice.
	// We'll do 5 A→B then 5 B→A turns.

	// A→B x5
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

	// Now Bob replies using the ratchet state he has after decryption.
	// Alice's receive state: her RK is post-send-ratchet, her SendingDH is the same
	// fresh keypair she used for sending.  RemoteDHPub is set to the SPK (her last
	// known DH pub before Bob's new keypair), so Bob's new DHPub triggers a recv ratchet.
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

	// Deliver in reverse.
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

	// Give alice a KEM pub to encapsulate to (bob's KEM pub).
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
	// Flip a byte in the ciphertext body.
	ct[0] ^= 0xFF
	_, err = bob.DecryptMessage(hdr, ct)
	if err == nil {
		t.Fatal("expected decryption failure on tampered ciphertext")
	}
}

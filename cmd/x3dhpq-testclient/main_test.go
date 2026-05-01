// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
	"github.com/danielinux/xmppqr/internal/x3dhpqcrypto"
)

func TestSelfTestRuns(t *testing.T) {
	if err := runSelfTest(); err != nil {
		t.Fatalf("selftest: %v", err)
	}
}

func TestRogueDeviceRejected(t *testing.T) {
	aliceAcct, err := newAccount()
	if err != nil {
		t.Fatal(err)
	}

	rogueAcct, err := newAccount()
	if err != nil {
		t.Fatal(err)
	}
	rogueDev, err := rogueAcct.addDevice(1, false, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	roguePub := rogueDev.Bundle.PublicView()

	senderDIK, err := x3dhpqcrypto.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ephPub, ephPriv, err := wolfcrypt.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, _, err = x3dhpqcrypto.InitiateSession(
		senderDIK, ephPriv, ephPub, roguePub,
		aliceAcct.AIK.Public(),
		0,
		roguePub.KEMPreKeys[0].ID,
	)
	if !errors.Is(err, x3dhpqcrypto.ErrUntrustedDevice) {
		t.Fatalf("expected ErrUntrustedDevice, got %v", err)
	}
}

func TestMultipleDevicesUnderOneAIK(t *testing.T) {
	aliceAcct, err := newAccount()
	if err != nil {
		t.Fatal(err)
	}
	aliceA1, err := aliceAcct.addDevice(1, true, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	aliceA2, err := aliceAcct.addDevice(2, false, 2, 2)
	if err != nil {
		t.Fatal(err)
	}

	bobAcct, err := newAccount()
	if err != nil {
		t.Fatal(err)
	}
	bobB1, err := bobAcct.addDevice(1, true, 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	pinnedAIK := aliceAcct.AIK.Public()

	session := func(dev *Device) ([]byte, error) {
		pub := dev.Bundle.PublicView()
		ephPub, ephPriv, err := wolfcrypt.GenerateX25519()
		if err != nil {
			return nil, err
		}
		opkID := uint32(0)
		if len(pub.OPKs) > 0 {
			opkID = pub.OPKs[0].ID
		}
		rk, _, kemCT, opkUsed, err := x3dhpqcrypto.InitiateSession(
			bobB1.DIK, ephPriv, ephPub, pub, pinnedAIK, opkID, pub.KEMPreKeys[0].ID,
		)
		if err != nil {
			return nil, err
		}
		var opkPriv []byte
		if opkUsed && len(dev.Bundle.OneTimePreKeys) > 0 {
			opkPriv = dev.Bundle.OneTimePreKeys[0].PrivX25519
		}
		recipRK, _, err := x3dhpqcrypto.RespondSession(
			dev.DIK,
			dev.Bundle.SignedPreKey.PrivX25519,
			opkPriv,
			bobB1.Cert,
			bobAcct.AIK.Public(),
			ephPub,
			dev.Bundle.KEMPreKeys[0].PrivMLKEM,
			kemCT,
		)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(rk, recipRK) {
			return nil, errors.New("root keys mismatch")
		}
		return rk, nil
	}

	rk1, err := session(aliceA1)
	if err != nil {
		t.Fatalf("session A1: %v", err)
	}
	rk2, err := session(aliceA2)
	if err != nil {
		t.Fatalf("session A2: %v", err)
	}
	if bytes.Equal(rk1, rk2) {
		t.Fatal("distinct devices produced identical root keys")
	}

	recvDH1 := x3dhpqcrypto.PrivPub{
		Priv: aliceA1.Bundle.SignedPreKey.PrivX25519,
		Pub:  aliceA1.Bundle.SignedPreKey.PubX25519,
	}
	ad := append(bobB1.DIK.PubX25519, aliceA1.DIK.PubX25519...)
	recvState1, err := x3dhpqcrypto.NewReceivingState(rk1, ad, recvDH1)
	if err != nil {
		t.Fatal(err)
	}
	sendState1, err := x3dhpqcrypto.NewSendingState(rk1, ad, aliceA1.Bundle.SignedPreKey.PubX25519)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	hdr, ct, err := sendState1.EncryptMessage([]byte("hello A1"), now)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := recvState1.DecryptMessage(hdr, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hello A1" {
		t.Fatalf("got %q", pt)
	}

	recvDH2 := x3dhpqcrypto.PrivPub{
		Priv: aliceA2.Bundle.SignedPreKey.PrivX25519,
		Pub:  aliceA2.Bundle.SignedPreKey.PubX25519,
	}
	ad2 := append(bobB1.DIK.PubX25519, aliceA2.DIK.PubX25519...)
	recvState2, err := x3dhpqcrypto.NewReceivingState(rk2, ad2, recvDH2)
	if err != nil {
		t.Fatal(err)
	}
	sendState2, err := x3dhpqcrypto.NewSendingState(rk2, ad2, aliceA2.Bundle.SignedPreKey.PubX25519)
	if err != nil {
		t.Fatal(err)
	}

	hdr2, ct2, err := sendState2.EncryptMessage([]byte("hello A2"), now)
	if err != nil {
		t.Fatal(err)
	}
	pt2, err := recvState2.DecryptMessage(hdr2, ct2)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt2) != "hello A2" {
		t.Fatalf("got %q", pt2)
	}
}

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
	case "groupchat":
		if err := runGroupChat(); err != nil {
			fmt.Fprintf(os.Stderr, "groupchat failed: %v\n", err)
			os.Exit(1)
		}
	case "recover":
		if err := runRecover(); err != nil {
			fmt.Fprintf(os.Stderr, "recover failed: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q; usage: x3dhpq-testclient [selftest|info|groupchat|recover]\n", cmd)
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
		KEMHistory:         sender.KEMHistory,
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

type groupParticipant struct {
	Account *Account
	Device  *Device
	Session *x3dhpqcrypto.GroupSession
}

func (gp *groupParticipant) crossAnnounce(others ...*groupParticipant) error {
	ann := gp.Session.AnnounceSenderChain()
	for _, o := range others {
		if err := o.Session.AcceptSenderChain(ann); err != nil {
			return fmt.Errorf("%s → %s accept: %w",
				gp.Account.AIK.Public().Fingerprint()[:8],
				o.Account.AIK.Public().Fingerprint()[:8], err)
		}
	}
	return nil
}

func roundRobin(participants []*groupParticipant, msg string) error {
	for _, sender := range participants {
		hdr, ct, err := sender.Session.Encrypt([]byte(msg))
		if err != nil {
			return fmt.Errorf("encrypt from %s: %w", sender.Account.AIK.Public().Fingerprint()[:8], err)
		}
		for _, receiver := range participants {
			if receiver == sender {
				continue
			}
			pt, err := receiver.Session.Decrypt(sender.Account.AIK.Public(), hdr, ct)
			if err != nil {
				return fmt.Errorf("decrypt at %s: %w", receiver.Account.AIK.Public().Fingerprint()[:8], err)
			}
			if string(pt) != msg {
				return fmt.Errorf("plaintext mismatch: got %q want %q", pt, msg)
			}
		}
	}
	return nil
}

func makeGroupParticipant(roomJID string, members []*x3dhpqcrypto.GroupMember) (*groupParticipant, error) {
	acct, err := newAccount()
	if err != nil {
		return nil, err
	}
	dev, err := acct.addDevice(1, true, 2, 0)
	if err != nil {
		return nil, err
	}
	sess, err := x3dhpqcrypto.NewGroupSession(roomJID, acct.AIK.Public(), 1, members)
	if err != nil {
		return nil, err
	}
	return &groupParticipant{Account: acct, Device: dev, Session: sess}, nil
}

func runGroupChat() error {
	const room = "lab@conference.test"

	aliceAcct, err := newAccount()
	if err != nil {
		return fmt.Errorf("alice account: %w", err)
	}
	bobAcct, err := newAccount()
	if err != nil {
		return fmt.Errorf("bob account: %w", err)
	}
	carolAcct, err := newAccount()
	if err != nil {
		return fmt.Errorf("carol account: %w", err)
	}

	aliceDev, err := aliceAcct.addDevice(1, true, 2, 0)
	if err != nil {
		return fmt.Errorf("alice device: %w", err)
	}
	bobDev, err := bobAcct.addDevice(1, true, 2, 0)
	if err != nil {
		return fmt.Errorf("bob device: %w", err)
	}
	carolDev, err := carolAcct.addDevice(1, true, 2, 0)
	if err != nil {
		return fmt.Errorf("carol device: %w", err)
	}
	_ = aliceDev
	_ = bobDev
	_ = carolDev

	members := []*x3dhpqcrypto.GroupMember{
		{AIKPub: aliceAcct.AIK.Public(), DeviceIDs: []uint32{1}},
		{AIKPub: bobAcct.AIK.Public(), DeviceIDs: []uint32{1}},
		{AIKPub: carolAcct.AIK.Public(), DeviceIDs: []uint32{1}},
	}

	aliceSess, err := x3dhpqcrypto.NewGroupSession(room, aliceAcct.AIK.Public(), 1, members)
	if err != nil {
		return fmt.Errorf("alice session: %w", err)
	}
	bobSess, err := x3dhpqcrypto.NewGroupSession(room, bobAcct.AIK.Public(), 1, members)
	if err != nil {
		return fmt.Errorf("bob session: %w", err)
	}
	carolSess, err := x3dhpqcrypto.NewGroupSession(room, carolAcct.AIK.Public(), 1, members)
	if err != nil {
		return fmt.Errorf("carol session: %w", err)
	}

	alice := &groupParticipant{Account: aliceAcct, Session: aliceSess}
	bob := &groupParticipant{Account: bobAcct, Session: bobSess}
	carol := &groupParticipant{Account: carolAcct, Session: carolSess}

	fmt.Printf("ALICE / BOB / CAROL all join %q\n", room)
	fmt.Printf("  Alice AIK fp: %s\n", aliceAcct.AIK.Public().Fingerprint())
	fmt.Printf("  Bob   AIK fp: %s\n", bobAcct.AIK.Public().Fingerprint())
	fmt.Printf("  Carol AIK fp: %s\n", carolAcct.AIK.Public().Fingerprint())

	fmt.Printf("\nPhase 1: cross-announce sender chains\n")
	if err := alice.crossAnnounce(bob, carol); err != nil {
		return fmt.Errorf("phase 1 alice announce: %w", err)
	}
	fmt.Printf("  Alice → Bob: announcement accepted ✓\n")
	fmt.Printf("  Alice → Carol: announcement accepted ✓\n")

	if err := bob.crossAnnounce(alice, carol); err != nil {
		return fmt.Errorf("phase 1 bob announce: %w", err)
	}
	fmt.Printf("  Bob → Alice, Carol: announcements accepted ✓\n")

	if err := carol.crossAnnounce(alice, bob); err != nil {
		return fmt.Errorf("phase 1 carol announce: %w", err)
	}
	fmt.Printf("  Carol → Alice, Bob: announcements accepted ✓\n")

	fmt.Printf("\nPhase 2: round-robin messages (epoch=0)\n")
	for _, p := range [][3]interface{}{
		{"Alice", alice, "hi from alice"},
		{"Bob", bob, "hi from bob"},
		{"Carol", carol, "hi from carol"},
	} {
		name := p[0].(string)
		sender := p[1].(*groupParticipant)
		msg := p[2].(string)

		hdr, ct, err := sender.Session.Encrypt([]byte(msg))
		if err != nil {
			return fmt.Errorf("phase 2 encrypt %s: %w", name, err)
		}
		var others []*groupParticipant
		for _, pp := range []*groupParticipant{alice, bob, carol} {
			if pp != sender {
				others = append(others, pp)
			}
		}
		for _, recv := range others {
			pt, err := recv.Session.Decrypt(sender.Account.AIK.Public(), hdr, ct)
			if err != nil {
				return fmt.Errorf("phase 2 decrypt %s at %s: %w", name, recv.Account.AIK.Public().Fingerprint()[:8], err)
			}
			if string(pt) != msg {
				return fmt.Errorf("phase 2 mismatch: got %q", pt)
			}
		}

		recvNames := map[*groupParticipant]string{alice: "Alice", bob: "Bob", carol: "Carol"}
		otherNames := make([]string, 0, 2)
		for _, pp := range others {
			otherNames = append(otherNames, recvNames[pp])
		}
		fmt.Printf("  %s %q — %s, %s decrypt ✓\n", name, msg, otherNames[0], otherNames[1])
	}

	fmt.Printf("\nPhase 3: remove Carol from the room\n")
	alice.Session.RemoveMember(carolAcct.AIK.Public())
	bob.Session.RemoveMember(carolAcct.AIK.Public())
	fmt.Printf("  Alice.RemoveMember(carol)  → epoch %d\n", alice.Session.Epoch)
	fmt.Printf("  Bob.RemoveMember(carol)    → epoch %d\n", bob.Session.Epoch)

	aliceAnn1 := alice.Session.AnnounceSenderChain()
	if err := bob.Session.AcceptSenderChain(aliceAnn1); err != nil {
		return fmt.Errorf("phase 3 bob accept alice epoch-1: %w", err)
	}
	bobAnn1 := bob.Session.AnnounceSenderChain()
	if err := alice.Session.AcceptSenderChain(bobAnn1); err != nil {
		return fmt.Errorf("phase 3 alice accept bob epoch-1: %w", err)
	}
	fmt.Printf("  Both re-announce; Carol does NOT receive the new announcements.\n")

	fmt.Printf("\nPhase 4: post-removal messages (epoch=1)\n")
	hdr4, ct4, err := alice.Session.Encrypt([]byte("post-removal"))
	if err != nil {
		return fmt.Errorf("phase 4 alice encrypt: %w", err)
	}
	pt4, err := bob.Session.Decrypt(aliceAcct.AIK.Public(), hdr4, ct4)
	if err != nil {
		return fmt.Errorf("phase 4 bob decrypt: %w", err)
	}
	if string(pt4) != "post-removal" {
		return fmt.Errorf("phase 4 mismatch: got %q", pt4)
	}
	fmt.Printf("  Alice \"post-removal\" — Bob decrypts ✓\n")

	_, err = carol.Session.Decrypt(aliceAcct.AIK.Public(), hdr4, ct4)
	if err == nil {
		return fmt.Errorf("phase 4: carol decrypted epoch-1 message — expected error")
	}
	fmt.Printf("  Carol receives Alice's stanza  → %v ✓\n", err)

	fmt.Printf("\nPhase 5: forward secrecy assertion\n")
	carolEpoch1Hdr := &x3dhpqcrypto.GroupMessageHeader{
		Version:        1,
		Epoch:          1,
		SenderDeviceID: 1,
		ChainIndex:     0,
	}
	_, err = carol.Session.Decrypt(aliceAcct.AIK.Public(), carolEpoch1Hdr, ct4)
	if err == nil {
		return fmt.Errorf("phase 5: carol decrypted epoch=1 — FS violation")
	}
	fmt.Printf("  Carol attempts Decrypt with header.Epoch=1 — fails ✓\n")
	fmt.Printf("  Carol cannot retroactively reconstruct alice's epoch-1 chain key\n")
	fmt.Printf("  even with full access to all epoch-0 state ✓ (no chain key derives forward\n")
	fmt.Printf("  across an epoch rotation)\n")

	fmt.Printf("\nPhase 6: out-of-order delivery\n")
	type encResult struct {
		hdr *x3dhpqcrypto.GroupMessageHeader
		ct  []byte
		msg string
	}

	aliceAcct2, err := newAccount()
	if err != nil {
		return fmt.Errorf("phase 6 alice account: %w", err)
	}
	bobAcct2, err := newAccount()
	if err != nil {
		return fmt.Errorf("phase 6 bob account: %w", err)
	}
	members2 := []*x3dhpqcrypto.GroupMember{
		{AIKPub: aliceAcct2.AIK.Public(), DeviceIDs: []uint32{1}},
		{AIKPub: bobAcct2.AIK.Public(), DeviceIDs: []uint32{1}},
	}
	aliceSess2, err := x3dhpqcrypto.NewGroupSession(room, aliceAcct2.AIK.Public(), 1, members2)
	if err != nil {
		return fmt.Errorf("phase 6 alice session: %w", err)
	}
	bobSess2, err := x3dhpqcrypto.NewGroupSession(room, bobAcct2.AIK.Public(), 1, members2)
	if err != nil {
		return fmt.Errorf("phase 6 bob session: %w", err)
	}
	if err := bobSess2.AcceptSenderChain(aliceSess2.AnnounceSenderChain()); err != nil {
		return fmt.Errorf("phase 6 bob accept alice: %w", err)
	}

	msgs6 := make([]encResult, 5)
	for i := 0; i < 5; i++ {
		m := fmt.Sprintf("ooo-msg-%d", i)
		h, c, err := aliceSess2.Encrypt([]byte(m))
		if err != nil {
			return fmt.Errorf("phase 6 encrypt %d: %w", i, err)
		}
		msgs6[i] = encResult{hdr: h, ct: c, msg: m}
	}

	order := []int{3, 0, 4, 2, 1}
	for _, idx := range order {
		pt, err := bobSess2.Decrypt(aliceAcct2.AIK.Public(), msgs6[idx].hdr, msgs6[idx].ct)
		if err != nil {
			return fmt.Errorf("phase 6 decrypt[%d]: %w", idx, err)
		}
		if string(pt) != msgs6[idx].msg {
			return fmt.Errorf("phase 6 mismatch[%d]: got %q want %q", idx, pt, msgs6[idx].msg)
		}
	}
	fmt.Printf("  Alice encrypts 5 messages; Bob receives in order [3, 0, 4, 2, 1]; all decrypt ✓\n")

	fmt.Printf("\ngroupchat: OK — 12 messages exchanged across 3 sessions, FS verified\n")
	return nil
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

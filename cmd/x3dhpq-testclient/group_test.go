// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/danielinux/xmppqr/internal/x3dhpqcrypto"
)

func TestGroupChatRuns(t *testing.T) {
	if err := runGroupChat(); err != nil {
		t.Fatalf("groupchat: %v", err)
	}
}

func TestGroupRemovedMemberRejected(t *testing.T) {
	const room = "test@conference.test"

	aliceAcct, err := newAccount()
	if err != nil {
		t.Fatal(err)
	}
	bobAcct, err := newAccount()
	if err != nil {
		t.Fatal(err)
	}
	carolAcct, err := newAccount()
	if err != nil {
		t.Fatal(err)
	}

	members := []*x3dhpqcrypto.GroupMember{
		{AIKPub: aliceAcct.AIK.Public(), DeviceIDs: []uint32{1}},
		{AIKPub: bobAcct.AIK.Public(), DeviceIDs: []uint32{1}},
		{AIKPub: carolAcct.AIK.Public(), DeviceIDs: []uint32{1}},
	}

	aliceSess, err := x3dhpqcrypto.NewGroupSession(room, aliceAcct.AIK.Public(), 1, members)
	if err != nil {
		t.Fatal(err)
	}
	bobSess, err := x3dhpqcrypto.NewGroupSession(room, bobAcct.AIK.Public(), 1, members)
	if err != nil {
		t.Fatal(err)
	}
	carolSess, err := x3dhpqcrypto.NewGroupSession(room, carolAcct.AIK.Public(), 1, members)
	if err != nil {
		t.Fatal(err)
	}

	aliceAnn := aliceSess.AnnounceSenderChain()
	if err := bobSess.AcceptSenderChain(aliceAnn); err != nil {
		t.Fatal(err)
	}
	if err := carolSess.AcceptSenderChain(aliceAnn); err != nil {
		t.Fatal(err)
	}
	bobAnn := bobSess.AnnounceSenderChain()
	if err := aliceSess.AcceptSenderChain(bobAnn); err != nil {
		t.Fatal(err)
	}
	if err := carolSess.AcceptSenderChain(bobAnn); err != nil {
		t.Fatal(err)
	}
	carolAnn := carolSess.AnnounceSenderChain()
	if err := aliceSess.AcceptSenderChain(carolAnn); err != nil {
		t.Fatal(err)
	}
	if err := bobSess.AcceptSenderChain(carolAnn); err != nil {
		t.Fatal(err)
	}

	aliceSess.RemoveMember(carolAcct.AIK.Public())

	aliceAnn1 := aliceSess.AnnounceSenderChain()
	bobSess.RemoveMember(carolAcct.AIK.Public())
	if err := bobSess.AcceptSenderChain(aliceAnn1); err != nil {
		t.Fatal(err)
	}

	hdr, ct, err := aliceSess.Encrypt([]byte("secret after removal"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = carolSess.Decrypt(aliceAcct.AIK.Public(), hdr, ct)
	if !errors.Is(err, x3dhpqcrypto.ErrUnknownSender) {
		t.Fatalf("expected ErrUnknownSender, got %v", err)
	}
}

func TestGroupForwardSecrecy(t *testing.T) {
	const room = "fs@conference.test"

	aliceAcct, err := newAccount()
	if err != nil {
		t.Fatal(err)
	}
	carolAcct, err := newAccount()
	if err != nil {
		t.Fatal(err)
	}

	members := []*x3dhpqcrypto.GroupMember{
		{AIKPub: aliceAcct.AIK.Public(), DeviceIDs: []uint32{1}},
		{AIKPub: carolAcct.AIK.Public(), DeviceIDs: []uint32{1}},
	}

	aliceSess, err := x3dhpqcrypto.NewGroupSession(room, aliceAcct.AIK.Public(), 1, members)
	if err != nil {
		t.Fatal(err)
	}
	carolSess, err := x3dhpqcrypto.NewGroupSession(room, carolAcct.AIK.Public(), 1, members)
	if err != nil {
		t.Fatal(err)
	}

	aliceAnn0 := aliceSess.AnnounceSenderChain()
	if err := carolSess.AcceptSenderChain(aliceAnn0); err != nil {
		t.Fatal(err)
	}

	carolRecordedEpoch0ChainKey := make([]byte, len(aliceAnn0.ChainKey))
	copy(carolRecordedEpoch0ChainKey, aliceAnn0.ChainKey)

	aliceSess.RemoveMember(carolAcct.AIK.Public())

	aliceAnn1 := aliceSess.AnnounceSenderChain()

	if bytes.Equal(carolRecordedEpoch0ChainKey, aliceAnn1.ChainKey) {
		t.Fatal("epoch-1 chain key equals epoch-0 chain key — FS violated")
	}

	if aliceAnn1.Epoch != 1 {
		t.Fatalf("expected epoch 1, got %d", aliceAnn1.Epoch)
	}
}

func TestGroupOutOfOrder(t *testing.T) {
	const room = "ooo@conference.test"

	aliceAcct, err := newAccount()
	if err != nil {
		t.Fatal(err)
	}
	bobAcct, err := newAccount()
	if err != nil {
		t.Fatal(err)
	}

	members := []*x3dhpqcrypto.GroupMember{
		{AIKPub: aliceAcct.AIK.Public(), DeviceIDs: []uint32{1}},
		{AIKPub: bobAcct.AIK.Public(), DeviceIDs: []uint32{1}},
	}

	aliceSess, err := x3dhpqcrypto.NewGroupSession(room, aliceAcct.AIK.Public(), 1, members)
	if err != nil {
		t.Fatal(err)
	}
	bobSess, err := x3dhpqcrypto.NewGroupSession(room, bobAcct.AIK.Public(), 1, members)
	if err != nil {
		t.Fatal(err)
	}

	if err := bobSess.AcceptSenderChain(aliceSess.AnnounceSenderChain()); err != nil {
		t.Fatal(err)
	}

	type enc struct {
		hdr *x3dhpqcrypto.GroupMessageHeader
		ct  []byte
		msg string
	}
	msgs := make([]enc, 5)
	for i := 0; i < 5; i++ {
		m := fmt.Sprintf("ooo-%d", i)
		h, c, err := aliceSess.Encrypt([]byte(m))
		if err != nil {
			t.Fatalf("encrypt[%d]: %v", i, err)
		}
		msgs[i] = enc{hdr: h, ct: c, msg: m}
	}

	for _, idx := range []int{3, 0, 4, 2, 1} {
		pt, err := bobSess.Decrypt(aliceAcct.AIK.Public(), msgs[idx].hdr, msgs[idx].ct)
		if err != nil {
			t.Fatalf("decrypt[%d]: %v", idx, err)
		}
		if string(pt) != msgs[idx].msg {
			t.Fatalf("mismatch[%d]: got %q want %q", idx, pt, msgs[idx].msg)
		}
	}
}

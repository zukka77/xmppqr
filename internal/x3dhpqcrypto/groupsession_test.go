// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"bytes"
	"errors"
	"testing"
)

func mkMember(t *testing.T, deviceIDs ...uint32) *GroupMember {
	t.Helper()
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return &GroupMember{AIKPub: aik.Public(), DeviceIDs: deviceIDs}
}

func TestNewGroupSession(t *testing.T) {
	alice := mkMember(t, 1)
	gs, err := NewGroupSession("room@example.com", alice.AIKPub, 1, []*GroupMember{alice})
	if err != nil {
		t.Fatal(err)
	}
	if gs.Epoch != 0 {
		t.Fatalf("expected epoch 0, got %d", gs.Epoch)
	}
	if gs.MySend == nil {
		t.Fatal("MySend is nil")
	}
	if len(gs.RecvChains) != 0 {
		t.Fatalf("expected empty RecvChains, got %d", len(gs.RecvChains))
	}
}

func TestAnnouncePropagatesChain(t *testing.T) {
	alice := mkMember(t, 1)
	bob := mkMember(t, 2)

	members := []*GroupMember{alice, bob}
	aliceSession, err := NewGroupSession("room@example.com", alice.AIKPub, 1, members)
	if err != nil {
		t.Fatal(err)
	}
	bobSession, err := NewGroupSession("room@example.com", bob.AIKPub, 2, members)
	if err != nil {
		t.Fatal(err)
	}

	ann := aliceSession.AnnounceSenderChain()
	if err := bobSession.AcceptSenderChain(ann); err != nil {
		t.Fatal(err)
	}

	k := recvKey{aikFP: alice.AIKPub.Fingerprint(), deviceID: 1, epoch: 0}
	if _, ok := bobSession.RecvChains[k]; !ok {
		t.Fatal("bob has no receiver chain for alice device 1 epoch 0")
	}
}

func TestEncryptDecryptHappyPath(t *testing.T) {
	alice := mkMember(t, 1)
	bob := mkMember(t, 2)
	members := []*GroupMember{alice, bob}

	aliceSession, err := NewGroupSession("room@example.com", alice.AIKPub, 1, members)
	if err != nil {
		t.Fatal(err)
	}
	bobSession, err := NewGroupSession("room@example.com", bob.AIKPub, 2, members)
	if err != nil {
		t.Fatal(err)
	}

	ann := aliceSession.AnnounceSenderChain()
	if err := bobSession.AcceptSenderChain(ann); err != nil {
		t.Fatal(err)
	}

	header, ct, err := aliceSession.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := bobSession.Decrypt(alice.AIKPub, header, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, []byte("hello")) {
		t.Fatalf("got %q, want %q", pt, "hello")
	}
}

func TestEncryptOutOfOrder(t *testing.T) {
	alice := mkMember(t, 1)
	bob := mkMember(t, 2)
	members := []*GroupMember{alice, bob}

	aliceSession, _ := NewGroupSession("room@example.com", alice.AIKPub, 1, members)
	bobSession, _ := NewGroupSession("room@example.com", bob.AIKPub, 2, members)

	ann := aliceSession.AnnounceSenderChain()
	bobSession.AcceptSenderChain(ann)

	msgs := [][]byte{[]byte("msg0"), []byte("msg1"), []byte("msg2")}
	headers := make([]*GroupMessageHeader, 3)
	cts := make([][]byte, 3)
	for i, m := range msgs {
		h, ct, err := aliceSession.Encrypt(m)
		if err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
		headers[i] = h
		cts[i] = ct
	}

	for _, idx := range []int{2, 0, 1} {
		pt, err := bobSession.Decrypt(alice.AIKPub, headers[idx], cts[idx])
		if err != nil {
			t.Fatalf("decrypt msg %d: %v", idx, err)
		}
		if !bytes.Equal(pt, msgs[idx]) {
			t.Fatalf("msg %d: got %q want %q", idx, pt, msgs[idx])
		}
	}
}

func TestEncryptReplayFails(t *testing.T) {
	alice := mkMember(t, 1)
	bob := mkMember(t, 2)
	members := []*GroupMember{alice, bob}

	aliceSession, _ := NewGroupSession("room@example.com", alice.AIKPub, 1, members)
	bobSession, _ := NewGroupSession("room@example.com", bob.AIKPub, 2, members)

	ann := aliceSession.AnnounceSenderChain()
	bobSession.AcceptSenderChain(ann)

	header, ct, err := aliceSession.Encrypt([]byte("once"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bobSession.Decrypt(alice.AIKPub, header, ct); err != nil {
		t.Fatal(err)
	}
	if _, err := bobSession.Decrypt(alice.AIKPub, header, ct); err == nil {
		t.Fatal("expected error on replay, got nil")
	}
}

func TestRemoveMemberRotatesEpoch(t *testing.T) {
	alice := mkMember(t, 1)
	bob := mkMember(t, 2)
	carol := mkMember(t, 3)
	members := []*GroupMember{alice, bob, carol}

	aliceSession, err := NewGroupSession("room@example.com", alice.AIKPub, 1, members)
	if err != nil {
		t.Fatal(err)
	}

	ann := carol.AIKPub.Fingerprint()
	// add a fake carol recv chain so we can verify it gets removed
	carolKey := recvKey{aikFP: ann, deviceID: 3, epoch: 0}
	sc, _ := NewSenderChain(0)
	aliceSession.RecvChains[carolKey] = sc

	aliceSession.RemoveMember(carol.AIKPub)

	if aliceSession.Epoch != 1 {
		t.Fatalf("expected epoch 1, got %d", aliceSession.Epoch)
	}
	if aliceSession.MySend.Epoch != 1 {
		t.Fatalf("expected MySend.Epoch 1, got %d", aliceSession.MySend.Epoch)
	}
	if _, ok := aliceSession.RecvChains[carolKey]; ok {
		t.Fatal("carol's receiver chain was not dropped")
	}
}

func TestRemovedMemberCannotDecryptNewEpoch(t *testing.T) {
	alice := mkMember(t, 1)
	bob := mkMember(t, 2)
	carol := mkMember(t, 3)
	members := []*GroupMember{alice, bob, carol}

	aliceSession, _ := NewGroupSession("room@example.com", alice.AIKPub, 1, members)
	carolSession, _ := NewGroupSession("room@example.com", carol.AIKPub, 3, members)

	// carol gets alice's epoch-0 chain
	ann0 := aliceSession.AnnounceSenderChain()
	carolSession.AcceptSenderChain(ann0)

	// alice removes carol → epoch=1
	aliceSession.RemoveMember(carol.AIKPub)

	// alice sends new announcement only to bob; carol never receives it
	// alice encrypts at epoch=1
	header, ct, err := aliceSession.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = carolSession.Decrypt(alice.AIKPub, header, ct)
	if !errors.Is(err, ErrUnknownSender) {
		t.Fatalf("expected ErrUnknownSender, got %v", err)
	}
}

func TestAddMemberRotatesEpoch(t *testing.T) {
	alice := mkMember(t, 1)
	bob := mkMember(t, 2)
	carol := mkMember(t, 3)
	members := []*GroupMember{alice, bob}

	aliceSession, err := NewGroupSession("room@example.com", alice.AIKPub, 1, members)
	if err != nil {
		t.Fatal(err)
	}

	aliceSession.AddMember(carol)

	if aliceSession.Epoch != 1 {
		t.Fatalf("expected epoch 1, got %d", aliceSession.Epoch)
	}
	found := false
	for _, m := range aliceSession.Members {
		if m.AIKPub.Equal(carol.AIKPub) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("carol not in member list after AddMember")
	}
}

func TestAcceptAnnouncementWrongRoomFails(t *testing.T) {
	alice := mkMember(t, 1)
	bob := mkMember(t, 2)
	members := []*GroupMember{alice, bob}

	aliceSession, _ := NewGroupSession("room-a@example.com", alice.AIKPub, 1, members)
	bobSession, _ := NewGroupSession("room-b@example.com", bob.AIKPub, 2, members)

	ann := aliceSession.AnnounceSenderChain()
	err := bobSession.AcceptSenderChain(ann)
	if !errors.Is(err, ErrAnnouncementWrongRoom) {
		t.Fatalf("expected ErrAnnouncementWrongRoom, got %v", err)
	}
}

func TestAcceptAnnouncementUnknownSenderFails(t *testing.T) {
	alice := mkMember(t, 1)
	bob := mkMember(t, 2)
	stranger := mkMember(t, 99)

	bobSession, _ := NewGroupSession("room@example.com", bob.AIKPub, 2, []*GroupMember{alice, bob})

	strangerSession, _ := NewGroupSession("room@example.com", stranger.AIKPub, 99, []*GroupMember{stranger})
	ann := strangerSession.AnnounceSenderChain()

	err := bobSession.AcceptSenderChain(ann)
	if !errors.Is(err, ErrAnnouncementUnknownSender) {
		t.Fatalf("expected ErrAnnouncementUnknownSender, got %v", err)
	}
}

func TestAnnouncementMarshalRoundTrip(t *testing.T) {
	alice := mkMember(t, 42)
	sc, _ := NewSenderChain(7)
	ann := &SenderChainAnnouncement{
		SenderAIKPub:   alice.AIKPub,
		SenderDeviceID: 42,
		RoomJID:        "multiroom@conference.example.com",
		Epoch:          7,
		ChainKey:       sc.ChainKey,
		NextIndex:      3,
	}

	b := ann.Marshal()
	got, err := UnmarshalSenderChainAnnouncement(b)
	if err != nil {
		t.Fatal(err)
	}
	if !got.SenderAIKPub.Equal(ann.SenderAIKPub) {
		t.Fatal("SenderAIKPub mismatch")
	}
	if got.SenderDeviceID != ann.SenderDeviceID {
		t.Fatalf("SenderDeviceID: got %d want %d", got.SenderDeviceID, ann.SenderDeviceID)
	}
	if got.RoomJID != ann.RoomJID {
		t.Fatalf("RoomJID: got %q want %q", got.RoomJID, ann.RoomJID)
	}
	if got.Epoch != ann.Epoch {
		t.Fatalf("Epoch: got %d want %d", got.Epoch, ann.Epoch)
	}
	if !bytes.Equal(got.ChainKey, ann.ChainKey) {
		t.Fatal("ChainKey mismatch")
	}
	if got.NextIndex != ann.NextIndex {
		t.Fatalf("NextIndex: got %d want %d", got.NextIndex, ann.NextIndex)
	}
}

func TestRemovedAIKAnnouncementRejected(t *testing.T) {
	alice := mkMember(t, 1)
	bob := mkMember(t, 2)
	carol := mkMember(t, 3)
	members := []*GroupMember{alice, bob, carol}

	aliceSession, err := NewGroupSession("room@example.com", alice.AIKPub, 1, members)
	if err != nil {
		t.Fatal(err)
	}
	bobSession, err := NewGroupSession("room@example.com", bob.AIKPub, 2, members)
	if err != nil {
		t.Fatal(err)
	}
	carolSession, err := NewGroupSession("room@example.com", carol.AIKPub, 3, members)
	if err != nil {
		t.Fatal(err)
	}
	_ = carolSession

	aliceSession.RemoveMember(carol.AIKPub)
	bobSession.RemoveMember(carol.AIKPub)

	carolAnn := carolSession.AnnounceSenderChain()
	err = bobSession.AcceptSenderChain(carolAnn)
	if !errors.Is(err, ErrAnnouncementFromRemovedMember) {
		t.Fatalf("expected ErrAnnouncementFromRemovedMember, got %v", err)
	}
	evts := bobSession.Events()
	if len(evts) != 1 {
		t.Fatalf("expected 1 security event, got %d", len(evts))
	}
	if evts[0].Kind != SecurityEventAnnouncementFromRemoved {
		t.Fatalf("expected SecurityEventAnnouncementFromRemoved, got %v", evts[0].Kind)
	}
}

func TestRemovedAIKMessageDetected(t *testing.T) {
	alice := mkMember(t, 1)
	bob := mkMember(t, 2)
	members := []*GroupMember{alice, bob}

	aliceSession, err := NewGroupSession("room@example.com", alice.AIKPub, 1, members)
	if err != nil {
		t.Fatal(err)
	}
	bobSession, err := NewGroupSession("room@example.com", bob.AIKPub, 2, members)
	if err != nil {
		t.Fatal(err)
	}

	ann := aliceSession.AnnounceSenderChain()
	if err := bobSession.AcceptSenderChain(ann); err != nil {
		t.Fatal(err)
	}

	bobSession.RemoveMember(alice.AIKPub)

	header, ct, err := aliceSession.Encrypt([]byte("post-removal"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = bobSession.Decrypt(alice.AIKPub, header, ct)
	if !errors.Is(err, ErrMessageFromRemovedMember) {
		t.Fatalf("expected ErrMessageFromRemovedMember, got %v", err)
	}
	evts := bobSession.Events()
	if len(evts) != 1 {
		t.Fatalf("expected 1 security event, got %d", len(evts))
	}
	if evts[0].Kind != SecurityEventMessageFromRemoved {
		t.Fatalf("expected SecurityEventMessageFromRemoved, got %v", evts[0].Kind)
	}
}

func TestEventsClearedAfterRead(t *testing.T) {
	alice := mkMember(t, 1)
	bob := mkMember(t, 2)
	members := []*GroupMember{alice, bob}

	bobSession, err := NewGroupSession("room@example.com", bob.AIKPub, 2, members)
	if err != nil {
		t.Fatal(err)
	}
	bobSession.RemoveMember(alice.AIKPub)

	aliceSession, _ := NewGroupSession("room@example.com", alice.AIKPub, 1, members)
	header, ct, _ := aliceSession.Encrypt([]byte("x"))
	bobSession.Decrypt(alice.AIKPub, header, ct)

	first := bobSession.Events()
	if len(first) != 1 {
		t.Fatalf("expected 1 event, got %d", len(first))
	}
	second := bobSession.Events()
	if len(second) != 0 {
		t.Fatalf("expected 0 events after drain, got %d", len(second))
	}
}

func TestRemovedAIKReinstateRequiresAddMember(t *testing.T) {
	alice := mkMember(t, 1)
	bob := mkMember(t, 2)
	members := []*GroupMember{alice, bob}

	bobSession, err := NewGroupSession("room@example.com", bob.AIKPub, 2, members)
	if err != nil {
		t.Fatal(err)
	}
	bobSession.RemoveMember(alice.AIKPub)

	if !bobSession.IsRemoved(alice.AIKPub) {
		t.Fatal("alice should be removed")
	}

	aliceSession, _ := NewGroupSession("room@example.com", alice.AIKPub, 1, members)
	header, ct, _ := aliceSession.Encrypt([]byte("sneaky"))
	bobSession.Decrypt(alice.AIKPub, header, ct)

	evtsBefore := bobSession.Events()
	if len(evtsBefore) != 1 || evtsBefore[0].Kind != SecurityEventMessageFromRemoved {
		t.Fatalf("expected 1 MessageFromRemoved event before re-add, got %v", evtsBefore)
	}

	bobSession.AddMember(alice)

	if bobSession.IsRemoved(alice.AIKPub) {
		t.Fatal("alice should no longer be removed after AddMember")
	}

	evtsAfter := bobSession.Events()
	if len(evtsAfter) != 0 {
		t.Fatalf("expected 0 events after Events() drain, got %d", len(evtsAfter))
	}
}

func TestEpochMismatchRejected(t *testing.T) {
	alice := mkMember(t, 1)
	bob := mkMember(t, 2)
	members := []*GroupMember{alice, bob}

	aliceSession, _ := NewGroupSession("room@example.com", alice.AIKPub, 1, members)
	bobSession, _ := NewGroupSession("room@example.com", bob.AIKPub, 2, members)

	ann := aliceSession.AnnounceSenderChain()
	bobSession.AcceptSenderChain(ann)

	// tamper the header to claim a future epoch that bob has no chain for
	header := &GroupMessageHeader{
		Version:        1,
		Epoch:          99,
		SenderDeviceID: 1,
		ChainIndex:     0,
	}
	fakeCT := make([]byte, 32)
	_, err := bobSession.Decrypt(alice.AIKPub, header, fakeCT)
	if !errors.Is(err, ErrUnknownSender) && !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("expected ErrEpochMismatch or ErrUnknownSender, got %v", err)
	}
}

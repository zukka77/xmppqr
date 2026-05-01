package muc

import (
	"context"
	"strings"
	"testing"

	"github.com/danielinux/xmppqr/internal/stanza"
)

func TestParseAIKExtension(t *testing.T) {
	raw := []byte(`<presence to='room@conference.example.com/alice'>` +
		`<x xmlns='http://jabber.org/protocol/muc'/>` +
		`<aik xmlns='urn:xmppqr:x3dhpq:group:0' fp='ABC123'/>` +
		`</presence>`)
	got := parseAIKExtension(raw)
	if got != "ABC123" {
		t.Errorf("expected ABC123, got %q", got)
	}
}

func TestParseAIKExtensionAbsent(t *testing.T) {
	raw := []byte(`<presence to='room@conference.example.com/alice'>` +
		`<x xmlns='http://jabber.org/protocol/muc'/>` +
		`</presence>`)
	got := parseAIKExtension(raw)
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestParseAIKExtensionWrongNS(t *testing.T) {
	raw := []byte(`<presence to='room@conference.example.com/alice'>` +
		`<aik xmlns='other' fp='SHOULDNOTMATCH'/>` +
		`</presence>`)
	got := parseAIKExtension(raw)
	if got != "" {
		t.Errorf("expected empty for wrong namespace, got %q", got)
	}
}

func TestParseAIKExtensionMalformed(t *testing.T) {
	got := parseAIKExtension([]byte(`<<<not xml`))
	if got != "" {
		t.Errorf("expected empty for malformed input, got %q", got)
	}
}

func TestJoinPopulatesOccupantAIK(t *testing.T) {
	room, r := makeRoom(t)
	j, _ := stanza.Parse("alice@example.com/laptop")
	s := &mockSession{jid: j}
	r.Register(s)

	occ := &Occupant{
		Nick:           "Alice",
		FullJID:        j,
		AIKFingerprint: "71FD4 C632A",
	}
	if err := room.Join(context.Background(), occ, "", r, nil); err != nil {
		t.Fatalf("join: %v", err)
	}

	room.mu.RLock()
	stored := room.occupants["Alice"]
	room.mu.RUnlock()

	if stored == nil {
		t.Fatal("occupant not found after join")
	}
	if stored.AIKFingerprint != "71FD4 C632A" {
		t.Errorf("AIKFingerprint not stored: got %q", stored.AIKFingerprint)
	}
}

func TestAIKMembersListUpdatesOnJoinAndLeave(t *testing.T) {
	room, r := makeRoom(t)

	jA, _ := stanza.Parse("alice@example.com/laptop")
	sA := &mockSession{jid: jA}
	r.Register(sA)
	occA := &Occupant{Nick: "Alice", FullJID: jA, AIKFingerprint: "AAA"}
	if err := room.Join(context.Background(), occA, "", r, nil); err != nil {
		t.Fatalf("alice join: %v", err)
	}

	jB, _ := stanza.Parse("bob@example.com/laptop")
	sB := &mockSession{jid: jB}
	r.Register(sB)
	occB := &Occupant{Nick: "Bob", FullJID: jB, AIKFingerprint: "ZZZ"}
	if err := room.Join(context.Background(), occB, "", r, nil); err != nil {
		t.Fatalf("bob join: %v", err)
	}

	members := room.AIKMembers()
	if len(members) != 2 {
		t.Fatalf("expected 2 AIK members, got %d: %v", len(members), members)
	}
	if members[0] != "AAA" || members[1] != "ZZZ" {
		t.Errorf("expected [AAA ZZZ], got %v", members)
	}

	if err := room.Leave(context.Background(), jB, r); err != nil {
		t.Fatalf("bob leave: %v", err)
	}

	members = room.AIKMembers()
	if len(members) != 1 || members[0] != "AAA" {
		t.Errorf("expected [AAA] after bob leave, got %v", members)
	}
}

func TestAIKMembersIgnoresEmpty(t *testing.T) {
	room, r := makeRoom(t)

	jA, _ := stanza.Parse("alice@example.com/laptop")
	sA := &mockSession{jid: jA}
	r.Register(sA)
	occA := &Occupant{Nick: "Alice", FullJID: jA}
	if err := room.Join(context.Background(), occA, "", r, nil); err != nil {
		t.Fatalf("join: %v", err)
	}

	members := room.AIKMembers()
	for _, m := range members {
		if m == "" {
			t.Error("AIKMembers() must not include empty string")
		}
	}
	if len(members) != 0 {
		t.Errorf("expected no AIK members, got %v", members)
	}
}

func TestAIKPassthroughOnJoinBroadcast(t *testing.T) {
	room, r := makeRoom(t)

	jA, _ := stanza.Parse("alice@example.com/laptop")
	sA := &mockSession{jid: jA}
	r.Register(sA)
	occA := &Occupant{Nick: "Alice", FullJID: jA, AIKFingerprint: "FP-ALICE"}
	if err := room.Join(context.Background(), occA, "", r, nil); err != nil {
		t.Fatalf("alice join: %v", err)
	}

	jB, _ := stanza.Parse("bob@example.com/laptop")
	sB := &mockSession{jid: jB}
	r.Register(sB)
	occB := &Occupant{Nick: "Bob", FullJID: jB, AIKFingerprint: "FP-BOB"}
	if err := room.Join(context.Background(), occB, "", r, nil); err != nil {
		t.Fatalf("bob join: %v", err)
	}

	found := false
	for _, raw := range sA.Received() {
		if strings.Contains(string(raw), "FP-BOB") {
			found = true
			break
		}
	}
	if !found {
		t.Error("alice did not receive bob's AIK fingerprint in join presence broadcast")
	}

	foundAlice := false
	for _, raw := range sB.Received() {
		if strings.Contains(string(raw), "FP-ALICE") {
			foundAlice = true
			break
		}
	}
	if !foundAlice {
		t.Error("bob did not receive alice's AIK fingerprint when joining")
	}
}

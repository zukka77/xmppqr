package muc

import (
	"context"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage/memstore"
)

func makeRoom(t *testing.T) (*Room, *router.Router) {
	t.Helper()
	r := router.New()
	j, _ := stanza.Parse("testroom@conference.example.com")
	room := newRoom(j, RoomConfig{AnonymityMode: AnonymitySemi, HistoryMax: 20, Moderated: false}, false)
	return room, r
}

func joinOccupant(t *testing.T, room *Room, r *router.Router, jidStr, nick string) *mockSession {
	t.Helper()
	j, _ := stanza.Parse(jidStr)
	s := &mockSession{jid: j}
	r.Register(s)
	occ := &Occupant{Nick: nick, FullJID: j}
	if err := room.Join(context.Background(), occ, "", r, nil, false); err != nil {
		t.Fatalf("join %s as %s: %v", jidStr, nick, err)
	}
	return s
}

func TestRoomCreateAndJoin_Room(t *testing.T) {
	room, r := makeRoom(t)
	ctx := context.Background()

	room.affiliations["alice@example.com"] = AffOwner

	sessA := joinOccupant(t, room, r, "alice@example.com/phone", "Alice")
	_ = sessA

	sessB := joinOccupant(t, room, r, "bob@example.com/phone", "Bob")

	recvB := sessB.Received()
	if len(recvB) == 0 {
		t.Fatal("Bob received nothing on join")
	}

	found := false
	for _, raw := range recvB {
		if strings.Contains(string(raw), "Alice") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Bob did not receive Alice's presence; got: %v", recvB)
	}

	_ = ctx
}

func TestBroadcastMessage(t *testing.T) {
	room, r := makeRoom(t)
	ctx := context.Background()

	room.affiliations["alice@example.com"] = AffOwner

	sessA := joinOccupant(t, room, r, "alice@example.com/phone", "Alice")
	sessB := joinOccupant(t, room, r, "bob@example.com/phone", "Bob")

	sessA.mu.Lock()
	sessA.received = nil
	sessA.mu.Unlock()
	sessB.mu.Lock()
	sessB.received = nil
	sessB.mu.Unlock()

	msgXML := []byte(`<message type="groupchat" from="alice@example.com/phone" to="testroom@conference.example.com"><body>hello</body></message>`)
	fromA, _ := stanza.Parse("alice@example.com/phone")
	if err := room.BroadcastMessage(ctx, fromA, msgXML, r); err != nil {
		t.Fatalf("BroadcastMessage: %v", err)
	}

	for _, sess := range []*mockSession{sessA, sessB} {
		got := sess.Received()
		if len(got) == 0 {
			t.Fatalf("%s received nothing", sess.jid)
		}
		raw := got[0]
		if !strings.Contains(string(raw), "Alice") {
			t.Errorf("%s: expected from-nick Alice in %s", sess.jid, raw)
		}
		if strings.Contains(string(raw), "alice@example.com/phone") {
			dec := xml.NewDecoder(strings.NewReader(string(raw)))
			tok, _ := dec.Token()
			se := tok.(xml.StartElement)
			for _, a := range se.Attr {
				if a.Name.Local == "from" && a.Value == "alice@example.com/phone" {
					t.Errorf("%s: from attr not rewritten; got %s", sess.jid, raw)
				}
			}
		}
	}
}

func TestSubjectChange(t *testing.T) {
	room, r := makeRoom(t)
	ctx := context.Background()

	room.config.Moderated = true
	room.affiliations["alice@example.com"] = AffOwner

	sessA := joinOccupant(t, room, r, "alice@example.com/phone", "Alice")
	sessB := joinOccupant(t, room, r, "bob@example.com/phone", "Bob")

	_ = sessA
	_ = sessB

	err := room.ChangeSubject(ctx, "Bob", "New Subject", r)
	if err == nil {
		t.Error("expected error for non-moderator subject change, got nil")
	}

	if err2 := room.ChangeSubject(ctx, "Alice", "New Subject", r); err2 != nil {
		t.Errorf("moderator should be able to change subject: %v", err2)
	}
	if room.subject != "New Subject" {
		t.Errorf("subject not updated, got: %s", room.subject)
	}
}

func TestSelfPing(t *testing.T) {
	room, r := makeRoom(t)
	ctx := context.Background()

	room.affiliations["alice@example.com"] = AffOwner

	sessA := joinOccupant(t, room, r, "alice@example.com/phone", "Alice")
	_ = sessA

	fromA, _ := stanza.Parse("alice@example.com/phone")
	if err := room.SelfPing(ctx, fromA, r); err != nil {
		t.Errorf("present occupant ping failed: %v", err)
	}

	fromB, _ := stanza.Parse("bob@example.com/phone")
	if err := room.SelfPing(ctx, fromB, r); err == nil {
		t.Error("expected not-acceptable for non-occupant ping")
	}
}

func TestSelfPresenceUsesExplicitMUCUserNamespace(t *testing.T) {
	raw := buildSelfPresence("room@conference.example.com/Alice", "alice@example.com/phone", RoleModerator, AffOwner, false)

	dec := xml.NewDecoder(strings.NewReader(string(raw)))
	var sawX, sawItem, sawStatus bool
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "x":
			if se.Name.Space == nsMUCUser {
				sawX = true
			}
		case "item":
			if se.Name.Space == nsMUCUser {
				sawItem = true
			}
		case "status":
			if se.Name.Space == nsMUCUser {
				sawStatus = true
			}
		}
	}
	if !sawX || !sawItem || !sawStatus {
		t.Fatalf("expected muc#user namespace on x/item/status, got: %s", raw)
	}
}

func TestJoinDeliversSubjectEvenWhenEmpty(t *testing.T) {
	room, r := makeRoom(t)
	room.affiliations["alice@example.com"] = AffOwner

	sessA := joinOccupant(t, room, r, "alice@example.com/phone", "Alice")

	var sawSubject bool
	for _, raw := range sessA.Received() {
		if !strings.Contains(string(raw), "<subject") {
			continue
		}
		dec := xml.NewDecoder(strings.NewReader(string(raw)))
		tok, _ := dec.Token()
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "message" {
			continue
		}
		sawSubject = true
		break
	}
	if !sawSubject {
		t.Fatalf("join must include a <subject/> message even when empty (XEP-0045 §7.2.16); got %v", sessA.Received())
	}
}

func TestAffiliationChange(t *testing.T) {
	stores := memstore.New()
	room, r := makeRoom(t)
	ctx := context.Background()

	room.affiliations["alice@example.com"] = AffOwner

	_ = joinOccupant(t, room, r, "alice@example.com/phone", "Alice")
	_ = joinOccupant(t, room, r, "bob@example.com/phone", "Bob")

	byJID, _ := stanza.Parse("alice@example.com/phone")
	targetJID, _ := stanza.Parse("bob@example.com/phone")

	if err := room.SetAffiliation(ctx, byJID, targetJID, AffAdmin, stores.MUC); err != nil {
		t.Fatalf("SetAffiliation: %v", err)
	}

	if room.affiliations["bob@example.com"] != AffAdmin {
		t.Errorf("expected bob to be admin, got %d", room.affiliations["bob@example.com"])
	}

	affs, err := stores.MUC.ListAffiliations(ctx, "testroom@conference.example.com")
	if err != nil {
		t.Fatalf("ListAffiliations: %v", err)
	}
	found := false
	for _, a := range affs {
		if a.UserJID == "bob@example.com" && a.Affiliation == AffAdmin {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("PutAffiliation not called or wrong value; affs=%v", affs)
	}
}

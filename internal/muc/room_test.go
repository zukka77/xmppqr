package muc

import (
	"context"
	"encoding/xml"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/danielinux/xmppqr/internal/mam"
	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage"
	"github.com/danielinux/xmppqr/internal/storage/memstore"
)

func makeRoom(t *testing.T) (*Room, *router.Router) {
	t.Helper()
	r := router.New()
	j, _ := stanza.Parse("testroom@conference.example.com")
	room := newRoom(j, RoomConfig{AnonymityMode: AnonymitySemi, HistoryMax: 20, Moderated: false}, false, nil, nil)
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

func TestJoinSameBareJIDDifferentResourceTakesOver(t *testing.T) {
	room, r := makeRoom(t)
	room.affiliations["alice@example.com"] = AffOwner

	// First join: alice/phone.
	_ = joinOccupant(t, room, r, "alice@example.com/phone", "Alice")

	// Simulate ungraceful disconnect: no <presence type='unavailable'/>,
	// just a fresh join from a different resource. Without the takeover
	// logic this would return <conflict/> and the user would be locked
	// out of the room.
	j2, _ := stanza.Parse("alice@example.com/laptop")
	s2 := &mockSession{jid: j2}
	r.Register(s2)
	occ := &Occupant{Nick: "Alice", FullJID: j2}
	if err := room.Join(context.Background(), occ, "", r, nil, false); err != nil {
		t.Fatalf("rejoin should take over stale entry: %v", err)
	}
	room.mu.RLock()
	cur := room.occupants["Alice"]
	room.mu.RUnlock()
	if cur == nil || cur.FullJID.Resource != "laptop" {
		t.Fatalf("expected occupant FullJID resource=laptop, got %+v", cur)
	}
}

func TestJoinSameNickDifferentBareJIDStillConflicts(t *testing.T) {
	room, r := makeRoom(t)
	room.affiliations["alice@example.com"] = AffOwner

	_ = joinOccupant(t, room, r, "alice@example.com/phone", "Alice")

	// Different bare JID using the same nick — this is a real conflict.
	j2, _ := stanza.Parse("eve@example.com/phone")
	s2 := &mockSession{jid: j2}
	r.Register(s2)
	occ := &Occupant{Nick: "Alice", FullJID: j2}
	err := room.Join(context.Background(), occ, "", r, nil, false)
	if err == nil {
		t.Fatal("different user with same nick must conflict")
	}
	se, ok := err.(*stanza.StanzaError)
	if !ok || se.Condition != stanza.ErrConflict {
		t.Fatalf("expected <conflict/>, got %v", err)
	}
}

func TestSelfPingAcceptsResourceChangeForSameBareJID(t *testing.T) {
	room, r := makeRoom(t)
	room.affiliations["alice@example.com"] = AffOwner

	_ = joinOccupant(t, room, r, "alice@example.com/phone", "Alice")

	// Self-ping from a new resource on the same bare JID — should succeed
	// and silently update the occupant's FullJID, mirroring the SM-resume
	// case where a client lands on a fresh resource.
	newJID, _ := stanza.Parse("alice@example.com/laptop")
	if err := room.SelfPing(context.Background(), newJID, r); err != nil {
		t.Fatalf("self-ping from new resource should refresh, got %v", err)
	}
	room.mu.RLock()
	cur := room.occupants["Alice"]
	room.mu.RUnlock()
	if cur.FullJID.Resource != "laptop" {
		t.Fatalf("self-ping should refresh FullJID resource; got %s", cur.FullJID.Resource)
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

// makePersistentRoom returns a persistent room backed by an in-memory store.
func makePersistentRoom(t *testing.T) (*Room, *router.Router, *storage.Stores) {
	t.Helper()
	stores := memstore.New()
	r := router.New()
	j, _ := stanza.Parse("testroom@conference.example.com")
	room := newRoom(j, RoomConfig{AnonymityMode: AnonymitySemi, HistoryMax: 20, Moderated: false}, true, stores.MUC, nil)
	return room, r, stores
}

func TestSubjectPersistenceCallsStore(t *testing.T) {
	room, r, stores := makePersistentRoom(t)
	ctx := context.Background()

	room.affiliations["alice@example.com"] = AffOwner
	_ = joinOccupant(t, room, r, "alice@example.com/phone", "Alice")

	if err := room.ChangeSubject(ctx, "Alice", "Test subject", r); err != nil {
		t.Fatalf("ChangeSubject: %v", err)
	}

	subj, byNick, _, err := stores.MUC.GetRoomSubject(ctx, "testroom@conference.example.com")
	if err != nil {
		t.Fatalf("GetRoomSubject: %v", err)
	}
	if subj != "Test subject" {
		t.Errorf("expected subject %q, got %q", "Test subject", subj)
	}
	if byNick != "Alice" {
		t.Errorf("expected byNick %q, got %q", "Alice", byNick)
	}
}

func TestNonPersistentDoesNotPersistHistory(t *testing.T) {
	stores := memstore.New()
	r := router.New()
	ctx := context.Background()

	j, _ := stanza.Parse("testroom@conference.example.com")
	// non-persistent room with store wired in
	room := newRoom(j, RoomConfig{AnonymityMode: AnonymitySemi, HistoryMax: 20}, false, stores.MUC, nil)
	room.affiliations["alice@example.com"] = AffOwner

	jA, _ := stanza.Parse("alice@example.com/phone")
	sA := &mockSession{jid: jA}
	r.Register(sA)
	occ := &Occupant{Nick: "Alice", FullJID: jA}
	if err := room.Join(ctx, occ, "", r, nil, false); err != nil {
		t.Fatalf("join: %v", err)
	}

	msgXML := []byte(`<message type="groupchat" from="alice@example.com/phone"><body>hi</body></message>`)
	fromA, _ := stanza.Parse("alice@example.com/phone")
	if err := room.BroadcastMessage(ctx, fromA, msgXML, r); err != nil {
		t.Fatalf("BroadcastMessage: %v", err)
	}

	rows, err := stores.MUC.QueryHistory(ctx, "testroom@conference.example.com", nil, nil, 100)
	if err != nil {
		t.Fatalf("QueryHistory: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected no history rows for non-persistent room, got %d", len(rows))
	}
}

// hasStatusCode returns true if the raw presence contains a <status code='N'/> element.
func hasStatusCode(raw []byte, code string) bool {
	dec := xml.NewDecoder(strings.NewReader(string(raw)))
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Local == "status" {
			for _, a := range se.Attr {
				if a.Name.Local == "code" && a.Value == code {
					return true
				}
			}
		}
	}
	return false
}

// hasPresenceType returns true if the raw stanza is a <presence type='T'>.
func hasPresenceType(raw []byte, presType string) bool {
	dec := xml.NewDecoder(strings.NewReader(string(raw)))
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	se, ok := tok.(xml.StartElement)
	if !ok || se.Name.Local != "presence" {
		return false
	}
	if presType == "available" {
		// available presence has no type attr
		for _, a := range se.Attr {
			if a.Name.Local == "type" {
				return false
			}
		}
		return true
	}
	for _, a := range se.Attr {
		if a.Name.Local == "type" && a.Value == presType {
			return true
		}
	}
	return false
}

func TestMUCAdminKickBroadcastsStatus307(t *testing.T) {
	room, r := makeRoom(t)
	ctx := context.Background()

	room.affiliations["alice@example.com"] = AffOwner

	sessAlice := joinOccupant(t, room, r, "alice@example.com/phone", "Alice")
	sessBob := joinOccupant(t, room, r, "bob@example.com/phone", "Bob")
	_ = sessAlice

	// Clear received buffers.
	sessAlice.mu.Lock()
	sessAlice.received = nil
	sessAlice.mu.Unlock()
	sessBob.mu.Lock()
	sessBob.received = nil
	sessBob.mu.Unlock()

	byJID, _ := stanza.Parse("alice@example.com/phone")
	if err := room.SetRole(ctx, byJID, "Bob", RoleNone, "spam", r); err != nil {
		t.Fatalf("SetRole (kick): %v", err)
	}

	// Bob should be evicted.
	if _, present := room.occupants["Bob"]; present {
		t.Error("Bob should have been removed from occupants after kick")
	}

	// Both Alice and Bob must receive an unavailable presence with status 307.
	for _, sess := range []*mockSession{sessAlice, sessBob} {
		found307 := false
		for _, raw := range sess.Received() {
			if hasPresenceType(raw, "unavailable") && hasStatusCode(raw, "307") {
				found307 = true
				break
			}
		}
		if !found307 {
			t.Errorf("%s: did not receive unavailable+307 presence; got %v", sess.jid, sess.Received())
		}
	}
}

func TestMUCAdminBanMultiItemAtomic(t *testing.T) {
	room, r := makeRoom(t)
	ctx := context.Background()

	room.affiliations["alice@example.com"] = AffOwner

	sessAlice := joinOccupant(t, room, r, "alice@example.com/phone", "Alice")
	sessCharlie := joinOccupant(t, room, r, "charlie@example.com/phone", "Charlie")
	sessDave := joinOccupant(t, room, r, "dave@example.com/phone", "Dave")
	_ = sessAlice

	sessAlice.mu.Lock()
	sessAlice.received = nil
	sessAlice.mu.Unlock()

	byJID, _ := stanza.Parse("alice@example.com/phone")
	items := []AdminItem{
		{Affiliation: "outcast", JID: "charlie@example.com"},
		{Affiliation: "outcast", JID: "dave@example.com"},
	}
	if err := room.ApplyAdminItems(ctx, byJID, items, r); err != nil {
		t.Fatalf("ApplyAdminItems: %v", err)
	}

	// Both should be AffOutcast.
	if room.affiliations["charlie@example.com"] != AffOutcast {
		t.Errorf("charlie should be outcast, got %d", room.affiliations["charlie@example.com"])
	}
	if room.affiliations["dave@example.com"] != AffOutcast {
		t.Errorf("dave should be outcast, got %d", room.affiliations["dave@example.com"])
	}

	// Both should be evicted.
	if _, present := room.occupants["Charlie"]; present {
		t.Error("Charlie should have been evicted")
	}
	if _, present := room.occupants["Dave"]; present {
		t.Error("Dave should have been evicted")
	}

	// Charlie and Dave must receive unavailable+301.
	for _, sess := range []*mockSession{sessCharlie, sessDave} {
		found301 := false
		for _, raw := range sess.Received() {
			if hasPresenceType(raw, "unavailable") && hasStatusCode(raw, "301") {
				found301 = true
				break
			}
		}
		if !found301 {
			t.Errorf("%s: did not receive unavailable+301; got %v", sess.jid, sess.Received())
		}
	}

	// Rejoin attempt must be rejected with <forbidden/>.
	rejoinOcc := &Occupant{Nick: "Charlie", FullJID: sessCharlie.jid}
	err := room.Join(ctx, rejoinOcc, "", r, nil, false)
	if err == nil {
		t.Fatal("expected forbidden on rejoin for banned user")
	}
	se, ok := err.(*stanza.StanzaError)
	if !ok || se.Condition != stanza.ErrForbidden {
		t.Errorf("expected forbidden stanza error, got %v", err)
	}
}

func TestMUCAdminGrantOwnerRequiresOwner(t *testing.T) {
	room, r := makeRoom(t)
	ctx := context.Background()

	room.affiliations["alice@example.com"] = AffOwner
	room.affiliations["admin@example.com"] = AffAdmin
	room.affiliations["member@example.com"] = AffMember

	_ = joinOccupant(t, room, r, "alice@example.com/phone", "Alice")
	_ = joinOccupant(t, room, r, "admin@example.com/phone", "Admin")
	_ = joinOccupant(t, room, r, "member@example.com/phone", "Member")

	adminJID, _ := stanza.Parse("admin@example.com/phone")
	memberJID, _ := stanza.Parse("member@example.com/phone")

	// Admin trying to promote member to owner → forbidden.
	items := []AdminItem{{Affiliation: "owner", JID: "member@example.com"}}
	err := room.ApplyAdminItems(ctx, adminJID, items, r)
	if err == nil {
		t.Fatal("expected forbidden when admin promotes to owner, got nil")
	}
	se, ok := err.(*stanza.StanzaError)
	if !ok || se.Condition != stanza.ErrForbidden {
		t.Errorf("expected forbidden, got %v", err)
	}

	// Owner promoting member to owner → succeeds.
	aliceJID, _ := stanza.Parse("alice@example.com/phone")
	items2 := []AdminItem{{Affiliation: "owner", JID: "member@example.com"}}
	if err := room.ApplyAdminItems(ctx, aliceJID, items2, r); err != nil {
		t.Fatalf("owner promote to owner failed: %v", err)
	}
	if room.affiliations["member@example.com"] != AffOwner {
		t.Errorf("expected member to be owner now, got %d", room.affiliations["member@example.com"])
	}
	_ = memberJID
}

func TestMUCAdminGetBanlist(t *testing.T) {
	room, r := makeRoom(t)
	ctx := context.Background()
	_ = ctx

	room.affiliations["alice@example.com"] = AffOwner
	room.affiliations["charlie@example.com"] = AffOutcast
	room.affiliations["dave@example.com"] = AffOutcast

	_ = joinOccupant(t, room, r, "alice@example.com/phone", "Alice")

	items := room.AdminItems(AffOutcast)
	if len(items) != 2 {
		t.Errorf("expected 2 outcast items, got %d: %v", len(items), items)
	}
	jids := map[string]bool{}
	for _, it := range items {
		jids[it.JID] = true
	}
	if !jids["charlie@example.com"] || !jids["dave@example.com"] {
		t.Errorf("missing expected JIDs in banlist: %v", jids)
	}
}

func TestMUCAdminRejectsNickOnlyBan(t *testing.T) {
	room, r := makeRoom(t)
	ctx := context.Background()

	room.affiliations["alice@example.com"] = AffOwner
	_ = joinOccupant(t, room, r, "alice@example.com/phone", "Alice")
	_ = joinOccupant(t, room, r, "bob@example.com/phone", "Bob")

	byJID, _ := stanza.Parse("alice@example.com/phone")
	// Nick-only ban: Affiliation=outcast but JID is empty.
	items := []AdminItem{{Affiliation: "outcast", Nick: "Bob"}}
	err := room.ApplyAdminItems(ctx, byJID, items, r)
	if err == nil {
		t.Fatal("expected not-acceptable for nick-only ban, got nil")
	}
	se, ok := err.(*stanza.StanzaError)
	if !ok || se.Condition != stanza.ErrNotAcceptable {
		t.Errorf("expected not-acceptable, got %v", err)
	}
}

// hasDestroyElement returns true if the raw presence contains a <destroy/>
// element inside the muc#user <x/> payload.
func hasDestroyElement(raw []byte) bool {
	dec := xml.NewDecoder(strings.NewReader(string(raw)))
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Local == "destroy" {
			return true
		}
	}
	return false
}

// hasItemAffRole returns true if the raw presence contains an <item> with both
// affiliation and role set to the given values.
func hasItemAffRole(raw []byte, affiliation, role string) bool {
	dec := xml.NewDecoder(strings.NewReader(string(raw)))
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "item" {
			continue
		}
		gotAff, gotRole := false, false
		for _, a := range se.Attr {
			if a.Name.Local == "affiliation" && a.Value == affiliation {
				gotAff = true
			}
			if a.Name.Local == "role" && a.Value == role {
				gotRole = true
			}
		}
		if gotAff && gotRole {
			return true
		}
	}
	return false
}

func TestMUCOwnerDestroyEvictsAllOccupants(t *testing.T) {
	room, r := makeRoom(t)
	ctx := context.Background()

	room.affiliations["alice@example.com"] = AffOwner
	room.affiliations["bob@example.com"] = AffMember

	sessAlice := joinOccupant(t, room, r, "alice@example.com/phone", "Alice")
	sessBob := joinOccupant(t, room, r, "bob@example.com/phone", "Bob")

	// Clear join noise before the destroy so we only see destroy stanzas.
	sessAlice.mu.Lock()
	sessAlice.received = nil
	sessAlice.mu.Unlock()
	sessBob.mu.Lock()
	sessBob.received = nil
	sessBob.mu.Unlock()

	room.Destroy(ctx, "", "moved", r)

	// Both occupants must receive an unavailable presence with <destroy/> and
	// <item affiliation='none' role='none'/>.
	for _, sess := range []*mockSession{sessAlice, sessBob} {
		var foundTombstone bool
		for _, raw := range sess.Received() {
			if hasPresenceType(raw, "unavailable") &&
				hasDestroyElement(raw) &&
				hasItemAffRole(raw, "none", "none") {
				foundTombstone = true
				break
			}
		}
		if !foundTombstone {
			t.Errorf("%s: did not receive destroy tombstone presence; got %v", sess.jid, sess.Received())
		}
	}

	// All occupants must be evicted.
	if len(room.occupants) != 0 {
		t.Errorf("expected 0 occupants after Destroy, got %d", len(room.occupants))
	}
}

func TestMUCOwnerDestroyClearsAffiliations(t *testing.T) {
	room, r := makeRoom(t)
	ctx := context.Background()

	room.affiliations["alice@example.com"] = AffOwner
	room.affiliations["bob@example.com"] = AffMember

	_ = joinOccupant(t, room, r, "alice@example.com/phone", "Alice")
	_ = joinOccupant(t, room, r, "bob@example.com/phone", "Bob")

	room.Destroy(ctx, "", "", r)

	if len(room.affiliations) != 0 {
		t.Errorf("expected empty affiliations after Destroy, got %v", room.affiliations)
	}
}

func TestMUCAdminMixedAffiliationAndRoleRejected(t *testing.T) {
	room, r := makeRoom(t)
	ctx := context.Background()

	room.affiliations["alice@example.com"] = AffOwner
	_ = joinOccupant(t, room, r, "alice@example.com/phone", "Alice")

	byJID, _ := stanza.Parse("alice@example.com/phone")
	// Mixing affiliation and role in one IQ → bad-request.
	items := []AdminItem{{Affiliation: "admin", Role: "moderator", JID: "bob@example.com"}}
	err := room.ApplyAdminItems(ctx, byJID, items, r)
	if err == nil {
		t.Fatal("expected bad-request for mixed affiliation+role, got nil")
	}
	se, ok := err.(*stanza.StanzaError)
	if !ok || se.Condition != stanza.ErrBadRequest {
		t.Errorf("expected bad-request, got %v", err)
	}
}

// makePersistentRoomWithMAM returns a persistent room backed by in-memory
// MUC and MAM stores, with a wired mam.Service.
func makePersistentRoomWithMAM(t *testing.T) (*Room, *router.Router, *storage.Stores, *mam.Service) {
	t.Helper()
	stores := memstore.New()
	r := router.New()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mamSvc := mam.New(stores.MAM, logger)
	j, _ := stanza.Parse("testroom@conference.example.com")
	room := newRoom(j, RoomConfig{AnonymityMode: AnonymitySemi, HistoryMax: 20, Moderated: false, Public: true}, true, stores.MUC, mamSvc)
	return room, r, stores, mamSvc
}

// TestMUCMAMArchivesGroupchat verifies that BroadcastMessage writes an entry
// to the MAM store using the rewritten (from='room/nick') stanza bytes.
func TestMUCMAMArchivesGroupchat(t *testing.T) {
	room, r, stores, _ := makePersistentRoomWithMAM(t)
	ctx := context.Background()

	room.affiliations["alice@example.com"] = AffOwner
	_ = joinOccupant(t, room, r, "alice@example.com/phone", "Alice")

	msgXML := []byte(`<message type="groupchat" from="alice@example.com/phone" to="testroom@conference.example.com"><body>hello mam</body></message>`)
	fromA, _ := stanza.Parse("alice@example.com/phone")
	if err := room.BroadcastMessage(ctx, fromA, msgXML, r); err != nil {
		t.Fatalf("BroadcastMessage: %v", err)
	}

	rows, err := stores.MAM.QueryMUC(ctx, "testroom@conference.example.com", nil, nil, nil, 100)
	if err != nil {
		t.Fatalf("QueryMUC: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 MAM row, got %d", len(rows))
	}
	// Archived bytes must carry from='room/nick', not the sender's real JID.
	if !strings.Contains(string(rows[0].StanzaXML), "testroom@conference.example.com/Alice") {
		t.Errorf("archived stanza does not contain room/nick from; got: %s", rows[0].StanzaXML)
	}
	if strings.Contains(string(rows[0].StanzaXML), "alice@example.com/phone") {
		t.Errorf("archived stanza must not contain real JID; got: %s", rows[0].StanzaXML)
	}
}

// TestMUCMAMArchivesUseRewrittenFrom asserts that the archived bytes carry
// from='room/nick' (the post-rewrite form), not the sender's real JID.
func TestMUCMAMArchivesUseRewrittenFrom(t *testing.T) {
	room, r, stores, _ := makePersistentRoomWithMAM(t)
	ctx := context.Background()

	room.affiliations["alice@example.com"] = AffOwner
	_ = joinOccupant(t, room, r, "alice@example.com/phone", "Alice")

	msgXML := []byte(`<message type="groupchat" from="alice@example.com/phone"><body>rewrite check</body></message>`)
	fromA, _ := stanza.Parse("alice@example.com/phone")
	if err := room.BroadcastMessage(ctx, fromA, msgXML, r); err != nil {
		t.Fatalf("BroadcastMessage: %v", err)
	}

	rows, err := stores.MAM.QueryMUC(ctx, "testroom@conference.example.com", nil, nil, nil, 100)
	if err != nil {
		t.Fatalf("QueryMUC: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("no MAM rows stored")
	}
	dec := xml.NewDecoder(strings.NewReader(string(rows[0].StanzaXML)))
	tok, _ := dec.Token()
	se, ok := tok.(xml.StartElement)
	if !ok || se.Name.Local != "message" {
		t.Fatalf("expected <message>, got %T", tok)
	}
	for _, a := range se.Attr {
		if a.Name.Local == "from" {
			if strings.Contains(a.Value, "alice@example.com") {
				t.Errorf("from attr must be room/nick, not real JID; got %q", a.Value)
			}
			if !strings.Contains(a.Value, "testroom@conference.example.com") {
				t.Errorf("from attr must be room/nick form; got %q", a.Value)
			}
			return
		}
	}
	t.Error("no from attribute found in archived stanza")
}

// TestMUCMAMQueryReturnsResultsWithDelay broadcasts 3 messages and then
// queries via mam.Service.HandleMUCIQ, asserting 3 forwarded results each
// containing a <delay stamp=...> element.
func TestMUCMAMQueryReturnsResultsWithDelay(t *testing.T) {
	room, r, _, mamSvc := makePersistentRoomWithMAM(t)
	ctx := context.Background()

	room.affiliations["alice@example.com"] = AffOwner
	_ = joinOccupant(t, room, r, "alice@example.com/phone", "Alice")

	fromA, _ := stanza.Parse("alice@example.com/phone")
	roomJID, _ := stanza.Parse("testroom@conference.example.com")
	for i := 0; i < 3; i++ {
		msgXML := []byte(`<message type="groupchat" from="alice@example.com/phone"><body>msg</body></message>`)
		if err := room.BroadcastMessage(ctx, fromA, msgXML, r); err != nil {
			t.Fatalf("BroadcastMessage %d: %v", i, err)
		}
	}

	iq := &stanza.IQ{
		ID:      "q1",
		From:    "alice@example.com/phone",
		To:      "testroom@conference.example.com",
		Type:    stanza.IQSet,
		Payload: []byte(`<query xmlns='urn:xmpp:mam:2' queryid='q1'/>`),
	}
	var delivered [][]byte
	deliver := func(raw []byte) error {
		cp := make([]byte, len(raw))
		copy(cp, raw)
		delivered = append(delivered, cp)
		return nil
	}
	resp, err := mamSvc.HandleMUCIQ(ctx, iq, roomJID, fromA, deliver)
	if err != nil {
		t.Fatalf("HandleMUCIQ: %v", err)
	}

	if len(delivered) != 3 {
		t.Fatalf("expected 3 delivered results, got %d", len(delivered))
	}
	// Each delivered message must contain a <delay stamp=...> element.
	for i, raw := range delivered {
		if !strings.Contains(string(raw), "stamp=") && !strings.Contains(string(raw), "stamp='") {
			t.Errorf("result %d missing delay stamp; got: %s", i, raw)
		}
	}
	// Response must be a result IQ with <fin complete=...>.
	if !strings.Contains(string(resp), `type="result"`) {
		t.Errorf("expected result IQ, got: %s", resp)
	}
	if !strings.Contains(string(resp), "fin") {
		t.Errorf("expected <fin> in response, got: %s", resp)
	}
}

// TestMUCMAMRequiresMembership verifies the access policy:
//   - non-member cannot query a members-only room;
//   - any caller can query an open+public room.
func TestMUCMAMRequiresMembership(t *testing.T) {
	stores := memstore.New()
	r := router.New()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mamSvc := mam.New(stores.MAM, logger)

	// Members-only room.
	j, _ := stanza.Parse("membersonly@conference.example.com")
	membersOnlyRoom := newRoom(j, RoomConfig{MembersOnly: true, Public: false, AnonymityMode: AnonymitySemi}, false, nil, mamSvc)
	membersOnlyRoom.affiliations["alice@example.com"] = AffMember

	svc := New("example.com", "conference", stores.MUC, mamSvc, nil, r, nil)
	svc.rooms.Store("membersonly@conference.example.com", membersOnlyRoom)

	// Alice (member) should be allowed.
	if !svc.CanQueryMAM(j, "alice@example.com") {
		t.Error("member should be allowed to query MAM")
	}
	// Bob (no affiliation) should be denied.
	if svc.CanQueryMAM(j, "bob@example.com") {
		t.Error("non-member should be denied MAM access on members-only room")
	}

	// Open+public room.
	j2, _ := stanza.Parse("openroom@conference.example.com")
	openRoom := newRoom(j2, RoomConfig{MembersOnly: false, Public: true, AnonymityMode: AnonymitySemi}, false, nil, mamSvc)
	svc.rooms.Store("openroom@conference.example.com", openRoom)

	// Anyone (including Bob with no affiliation) should be allowed.
	if !svc.CanQueryMAM(j2, "bob@example.com") {
		t.Error("anyone should be allowed to query MAM on open+public room")
	}
}

// TestMUCMAMRSMPaging broadcasts 5 messages and verifies that RSM <max/>
// limits work and the second page returns the remaining messages.
func TestMUCMAMRSMPaging(t *testing.T) {
	room, r, _, mamSvc := makePersistentRoomWithMAM(t)
	ctx := context.Background()

	room.affiliations["alice@example.com"] = AffOwner
	_ = joinOccupant(t, room, r, "alice@example.com/phone", "Alice")

	fromA, _ := stanza.Parse("alice@example.com/phone")
	roomJID, _ := stanza.Parse("testroom@conference.example.com")
	for i := 0; i < 5; i++ {
		msgXML := []byte(`<message type="groupchat" from="alice@example.com/phone"><body>msg</body></message>`)
		if err := room.BroadcastMessage(ctx, fromA, msgXML, r); err != nil {
			t.Fatalf("BroadcastMessage %d: %v", i, err)
		}
	}

	// Page 1: max=2.
	iq1 := &stanza.IQ{
		ID:      "p1",
		From:    "alice@example.com/phone",
		To:      "testroom@conference.example.com",
		Type:    stanza.IQSet,
		Payload: []byte(`<query xmlns='urn:xmpp:mam:2' queryid='p1'><set xmlns='http://jabber.org/protocol/rsm'><max>2</max></set></query>`),
	}
	var page1 [][]byte
	resp1, err := mamSvc.HandleMUCIQ(ctx, iq1, roomJID, fromA, func(raw []byte) error {
		cp := make([]byte, len(raw))
		copy(cp, raw)
		page1 = append(page1, cp)
		return nil
	})
	if err != nil {
		t.Fatalf("page1 HandleMUCIQ: %v", err)
	}
	if len(page1) != 2 {
		t.Fatalf("page1: expected 2 results, got %d", len(page1))
	}
	if !strings.Contains(string(resp1), "complete=\"false\"") && !strings.Contains(string(resp1), "complete='false'") {
		t.Errorf("page1 should not be complete: %s", resp1)
	}

	// Extract last cursor.
	lastCursor := extractLastCursor(string(resp1))
	if lastCursor == "" {
		t.Fatalf("no last cursor in fin: %s", resp1)
	}

	// Page 2: after=lastCursor.
	iq2 := &stanza.IQ{
		ID:      "p2",
		From:    "alice@example.com/phone",
		To:      "testroom@conference.example.com",
		Type:    stanza.IQSet,
		Payload: []byte(`<query xmlns='urn:xmpp:mam:2' queryid='p2'><set xmlns='http://jabber.org/protocol/rsm'><after>` + lastCursor + `</after></set></query>`),
	}
	var page2 [][]byte
	resp2, err := mamSvc.HandleMUCIQ(ctx, iq2, roomJID, fromA, func(raw []byte) error {
		cp := make([]byte, len(raw))
		copy(cp, raw)
		page2 = append(page2, cp)
		return nil
	})
	if err != nil {
		t.Fatalf("page2 HandleMUCIQ: %v", err)
	}
	if len(page2) != 3 {
		t.Fatalf("page2: expected 3 results, got %d", len(page2))
	}
	if !strings.Contains(string(resp2), "complete=\"true\"") && !strings.Contains(string(resp2), "complete='true'") {
		t.Errorf("page2 should be complete: %s", resp2)
	}
}

func extractLastCursor(fin string) string {
	const open = "<last>"
	const close = "</last>"
	i := strings.Index(fin, open)
	if i < 0 {
		return ""
	}
	j := strings.Index(fin[i:], close)
	if j < 0 {
		return ""
	}
	return fin[i+len(open) : i+j]
}

package muc

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage"
	"github.com/danielinux/xmppqr/internal/storage/memstore"
)

type mockSession struct {
	mu       sync.Mutex
	jid      stanza.JID
	received [][]byte
}

func (m *mockSession) JID() stanza.JID { return m.jid }
func (m *mockSession) Priority() int   { return 0 }
func (m *mockSession) IsAvailable() bool { return true }
func (m *mockSession) Deliver(_ context.Context, raw []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(raw))
	copy(cp, raw)
	m.received = append(m.received, cp)
	return nil
}

func (m *mockSession) Received() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]byte, len(m.received))
	copy(out, m.received)
	return out
}

func newTestService(t *testing.T) (*Service, *router.Router) {
	t.Helper()
	stores := memstore.New()
	r := router.New()
	svc := New("example.com", "conference", stores.MUC, nil, nil, r, nil)
	return svc, r
}

func registerSession(r *router.Router, jidStr string) *mockSession {
	j, _ := stanza.Parse(jidStr)
	s := &mockSession{jid: j}
	r.Register(s)
	return s
}

func presenceXML(from, to, nick string) []byte {
	p := &stanza.Presence{
		From: from,
		To:   to + "/" + nick,
	}
	raw, _ := p.Marshal()
	return raw
}

func TestRoomCreateAndJoin(t *testing.T) {
	svc, r := newTestService(t)
	ctx := context.Background()

	sessA := registerSession(r, "alice@example.com/phone")
	sessB := registerSession(r, "bob@example.com/phone")

	fromA, _ := stanza.Parse("alice@example.com/phone")
	toA, _ := stanza.Parse("testroom@conference.example.com/Alice")
	if err := svc.HandleStanza(ctx, presenceXML(fromA.String(), toA.Bare().String(), "Alice"), "presence", fromA, toA); err != nil {
		t.Fatalf("alice join: %v", err)
	}

	fromB, _ := stanza.Parse("bob@example.com/phone")
	toB, _ := stanza.Parse("testroom@conference.example.com/Bob")
	if err := svc.HandleStanza(ctx, presenceXML(fromB.String(), toB.Bare().String(), "Bob"), "presence", fromB, toB); err != nil {
		t.Fatalf("bob join: %v", err)
	}

	_ = sessA
	_ = sessB

	recvB := sessB.Received()
	if len(recvB) == 0 {
		t.Fatal("bob received nothing")
	}

	found := false
	for _, raw := range recvB {
		if strings.Contains(string(raw), "Alice") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("bob did not see alice's presence; got: %s", recvB)
	}
}

func TestSelfPingPresent(t *testing.T) {
	svc, r := newTestService(t)
	ctx := context.Background()

	sessA := registerSession(r, "alice@example.com/phone")
	_ = sessA

	fromA, _ := stanza.Parse("alice@example.com/phone")
	toA, _ := stanza.Parse("testroom@conference.example.com/Alice")
	if err := svc.HandleStanza(ctx, presenceXML(fromA.String(), toA.Bare().String(), "Alice"), "presence", fromA, toA); err != nil {
		t.Fatalf("join: %v", err)
	}

	pingIQ := &stanza.IQ{
		ID:      "ping1",
		From:    "alice@example.com/phone",
		To:      "testroom@conference.example.com/Alice",
		Type:    stanza.IQGet,
		Payload: []byte(`<ping xmlns='urn:xmpp:ping'/>`),
	}
	resp, err := svc.HandleIQ(ctx, pingIQ)
	if err != nil {
		t.Fatalf("HandleIQ error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response IQ")
	}
	if !strings.Contains(string(resp), `type="result"`) {
		t.Errorf("expected result IQ, got: %s", resp)
	}
}

func TestSelfPingNotPresent(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	pingIQ := &stanza.IQ{
		ID:      "ping2",
		From:    "alice@example.com/phone",
		To:      "noroom@conference.example.com/Alice",
		Type:    stanza.IQGet,
		Payload: []byte(`<ping xmlns='urn:xmpp:ping'/>`),
	}
	resp, err := svc.HandleIQ(ctx, pingIQ)
	if err != nil {
		t.Fatalf("HandleIQ error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected error IQ response")
	}
	if !strings.Contains(string(resp), `type="error"`) {
		t.Errorf("expected error IQ, got: %s", resp)
	}
}

// seedPersistentRoom inserts a bare persistent room record so that
// LoadPersistent will restore it on a fresh Service.
func seedPersistentRoom(t *testing.T, ctx context.Context, store storage.MUCStore, roomJID string) {
	t.Helper()
	cfg := RoomConfig{AnonymityMode: AnonymitySemi, HistoryMax: 20, Public: true}
	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json marshal cfg: %v", err)
	}
	if err := store.PutRoom(ctx, &storage.MUCRoom{
		JID:        roomJID,
		Config:     cfgBytes,
		Persistent: true,
	}); err != nil {
		t.Fatalf("PutRoom: %v", err)
	}
}

func TestPersistentRoomReplaysHistoryAfterRestart(t *testing.T) {
	ctx := context.Background()
	stores := memstore.New()
	r := router.New()

	const roomJID = "histroom@conference.example.com"
	seedPersistentRoom(t, ctx, stores.MUC, roomJID)

	// Pre-populate 3 history rows directly in the store.
	msgs := []string{"first message", "second message", "third message"}
	for _, body := range msgs {
		xml := `<message type="groupchat" from="histroom@conference.example.com/Alice"><body>` + body + `</body></message>`
		if _, err := stores.MUC.AppendHistory(ctx, &storage.MUCHistory{
			RoomJID:   roomJID,
			SenderJID: "histroom@conference.example.com/Alice",
			StanzaXML: []byte(xml),
		}); err != nil {
			t.Fatalf("AppendHistory: %v", err)
		}
	}

	// Fresh service over same store.
	svc := New("example.com", "conference", stores.MUC, nil, nil, r, nil)
	if err := svc.LoadPersistent(ctx); err != nil {
		t.Fatalf("LoadPersistent: %v", err)
	}

	// Join occupant.
	sess := registerSession(r, "bob@example.com/phone")
	fromB, _ := stanza.Parse("bob@example.com/phone")
	toB, _ := stanza.Parse(roomJID + "/Bob")
	if err := svc.HandleStanza(ctx, presenceXML(fromB.String(), toB.Bare().String(), "Bob"), "presence", fromB, toB); err != nil {
		t.Fatalf("join: %v", err)
	}

	received := sess.Received()
	// Find history messages before the subject message.
	var historyMsgs []string
	subjectIdx := -1
	for i, raw := range received {
		s := string(raw)
		if strings.Contains(s, "<subject") {
			subjectIdx = i
			break
		}
		if strings.Contains(s, "<body>") {
			historyMsgs = append(historyMsgs, s)
		}
	}
	if len(historyMsgs) != 3 {
		t.Errorf("expected 3 history messages, got %d; received: %v", len(historyMsgs), received)
	}
	if subjectIdx < 0 {
		t.Error("no subject message received")
	}
	if subjectIdx != -1 && len(historyMsgs) > 0 && subjectIdx < len(historyMsgs) {
		t.Errorf("subject message appeared before history (subjectIdx=%d, historyCount=%d)", subjectIdx, len(historyMsgs))
	}
}

func TestPersistentBanSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	stores := memstore.New()
	r := router.New()

	const roomJID = "banroom@conference.example.com"
	seedPersistentRoom(t, ctx, stores.MUC, roomJID)

	// Record outcast affiliation in store.
	if err := stores.MUC.PutAffiliation(ctx, &storage.MUCAffiliation{
		RoomJID:     roomJID,
		UserJID:     "banned@example.com",
		Affiliation: AffOutcast,
	}); err != nil {
		t.Fatalf("PutAffiliation: %v", err)
	}

	// Fresh service.
	svc := New("example.com", "conference", stores.MUC, nil, nil, r, nil)
	if err := svc.LoadPersistent(ctx); err != nil {
		t.Fatalf("LoadPersistent: %v", err)
	}

	_ = registerSession(r, "banned@example.com/phone")
	fromBanned, _ := stanza.Parse("banned@example.com/phone")
	toBanned, _ := stanza.Parse(roomJID + "/Banned")
	err := svc.HandleStanza(ctx, presenceXML(fromBanned.String(), toBanned.Bare().String(), "Banned"), "presence", fromBanned, toBanned)
	if err == nil {
		t.Fatal("expected error for banned user join, got nil")
	}
	stanzaErr, ok := err.(*stanza.StanzaError)
	if !ok {
		t.Fatalf("expected *stanza.StanzaError, got %T: %v", err, err)
	}
	if stanzaErr.Condition != stanza.ErrForbidden {
		t.Errorf("expected forbidden condition, got %q", stanzaErr.Condition)
	}
}

func TestPersistentSubjectSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	stores := memstore.New()
	r := router.New()

	const roomJID = "subjroom@conference.example.com"
	seedPersistentRoom(t, ctx, stores.MUC, roomJID)

	// Pre-store a subject.
	if err := stores.MUC.PutRoomSubject(ctx, roomJID, "Saved subject", "Alice", time.Now()); err != nil {
		t.Fatalf("PutRoomSubject: %v", err)
	}

	// Also store owner affiliation so subject message has correct nick.
	if err := stores.MUC.PutAffiliation(ctx, &storage.MUCAffiliation{
		RoomJID:     roomJID,
		UserJID:     "alice@example.com",
		Affiliation: AffOwner,
	}); err != nil {
		t.Fatalf("PutAffiliation: %v", err)
	}

	// Fresh service.
	svc := New("example.com", "conference", stores.MUC, nil, nil, r, nil)
	if err := svc.LoadPersistent(ctx); err != nil {
		t.Fatalf("LoadPersistent: %v", err)
	}

	sess := registerSession(r, "alice@example.com/phone")
	fromA, _ := stanza.Parse("alice@example.com/phone")
	toA, _ := stanza.Parse(roomJID + "/Alice")
	if err := svc.HandleStanza(ctx, presenceXML(fromA.String(), toA.Bare().String(), "Alice"), "presence", fromA, toA); err != nil {
		t.Fatalf("join: %v", err)
	}

	var subjText string
	var subjBy string
	for _, raw := range sess.Received() {
		s := string(raw)
		if !strings.Contains(s, "<subject") {
			continue
		}
		dec := xml.NewDecoder(strings.NewReader(s))
		for {
			tok, err := dec.Token()
			if err != nil {
				break
			}
			se, ok := tok.(xml.StartElement)
			if !ok {
				continue
			}
			if se.Name.Local == "message" {
				for _, a := range se.Attr {
					if a.Name.Local == "from" {
						// from is room@conf/nick
						j, _ := stanza.Parse(a.Value)
						subjBy = j.Resource
					}
				}
			}
			if se.Name.Local == "subject" {
				var text string
				_ = dec.DecodeElement(&text, &se)
				subjText = text
				break
			}
		}
		break
	}

	if subjText != "Saved subject" {
		t.Errorf("expected subject %q after restart, got %q", "Saved subject", subjText)
	}
	if subjBy != "Alice" {
		t.Errorf("expected subjectChangedBy %q, got %q", "Alice", subjBy)
	}
}

// destroyIQPayload builds the raw IQ bytes for a muc#owner destroy request.
func destroyIQPayload(altJID, reason string) []byte {
	var b strings.Builder
	b.WriteString(`<query xmlns='http://jabber.org/protocol/muc#owner'><destroy`)
	if altJID != "" {
		b.WriteString(` jid='`)
		b.WriteString(altJID)
		b.WriteString(`'`)
	}
	b.WriteString(`>`)
	if reason != "" {
		b.WriteString(`<reason>`)
		b.WriteString(reason)
		b.WriteString(`</reason>`)
	}
	b.WriteString(`</destroy></query>`)
	return []byte(b.String())
}

func TestMUCOwnerDestroyDeletesPersistentRoomFromStore(t *testing.T) {
	ctx := context.Background()
	stores := memstore.New()
	r := router.New()

	const roomJID = "destroyroom@conference.example.com"
	seedPersistentRoom(t, ctx, stores.MUC, roomJID)

	// Store owner affiliation so the room can be found after LoadPersistent.
	if err := stores.MUC.PutAffiliation(ctx, &storage.MUCAffiliation{
		RoomJID:     roomJID,
		UserJID:     "alice@example.com",
		Affiliation: AffOwner,
	}); err != nil {
		t.Fatalf("PutAffiliation: %v", err)
	}

	svc := New("example.com", "conference", stores.MUC, nil, nil, r, nil)
	if err := svc.LoadPersistent(ctx); err != nil {
		t.Fatalf("LoadPersistent: %v", err)
	}

	// Confirm room is present.
	if _, ok := svc.rooms.Load("destroyroom@conference.example.com"); !ok {
		t.Fatal("room not loaded after LoadPersistent")
	}

	// Apply the owner form to mark it persistent in the store first.
	room := svc.getRoom(mustParse(t, roomJID))
	if room == nil {
		t.Fatal("getRoom returned nil")
	}
	room.ApplyOwnerForm(map[string]string{"muc#roomconfig_persistentroom": "1"})
	if err := svc.persistRoom(ctx, room); err != nil {
		t.Fatalf("persistRoom: %v", err)
	}

	// Destroy via destroyRoom.
	if err := svc.destroyRoom(ctx, room, "", "test destroy"); err != nil {
		t.Fatalf("destroyRoom: %v", err)
	}

	// Room must be gone from the in-memory map.
	if _, ok := svc.rooms.Load("destroyroom@conference.example.com"); ok {
		t.Error("room still present in service map after destroyRoom")
	}

	// Fresh service over same store — room must not reappear.
	svc2 := New("example.com", "conference", stores.MUC, nil, nil, r, nil)
	if err := svc2.LoadPersistent(ctx); err != nil {
		t.Fatalf("LoadPersistent (svc2): %v", err)
	}
	if _, ok := svc2.rooms.Load("destroyroom@conference.example.com"); ok {
		t.Error("destroyed room reappeared after restart")
	}
}

func TestMUCOwnerDestroyViaHandleIQ(t *testing.T) {
	ctx := context.Background()
	stores := memstore.New()
	r := router.New()

	svc := New("example.com", "conference", stores.MUC, nil, nil, r, nil)

	// Alice joins to create the room (she becomes owner automatically).
	sessAlice := registerSession(r, "alice@example.com/phone")
	_ = sessAlice
	fromA, _ := stanza.Parse("alice@example.com/phone")
	toA, _ := stanza.Parse("myroom@conference.example.com/Alice")
	if err := svc.HandleStanza(ctx, presenceXML(fromA.String(), toA.Bare().String(), "Alice"), "presence", fromA, toA); err != nil {
		t.Fatalf("alice join: %v", err)
	}

	// Bob joins.
	sessBob := registerSession(r, "bob@example.com/phone")
	fromB, _ := stanza.Parse("bob@example.com/phone")
	toB, _ := stanza.Parse("myroom@conference.example.com/Bob")
	if err := svc.HandleStanza(ctx, presenceXML(fromB.String(), toB.Bare().String(), "Bob"), "presence", fromB, toB); err != nil {
		t.Fatalf("bob join: %v", err)
	}

	// Clear join noise.
	sessAlice.mu.Lock()
	sessAlice.received = nil
	sessAlice.mu.Unlock()
	sessBob.mu.Lock()
	sessBob.received = nil
	sessBob.mu.Unlock()

	// Alice sends a <destroy/> IQ.
	destroyIQ := &stanza.IQ{
		ID:      "destroy1",
		From:    "alice@example.com/phone",
		To:      "myroom@conference.example.com",
		Type:    stanza.IQSet,
		Payload: destroyIQPayload("", "closing down"),
	}
	resp, err := svc.HandleIQ(ctx, destroyIQ)
	if err != nil {
		t.Fatalf("HandleIQ destroy: %v", err)
	}
	if !strings.Contains(string(resp), `type="result"`) {
		t.Errorf("expected result IQ, got: %s", resp)
	}

	// Room must be gone from the service map.
	if _, ok := svc.rooms.Load("myroom@conference.example.com"); ok {
		t.Error("room still present after destroy IQ")
	}

	// Both Alice and Bob must have received the tombstone unavailable presence.
	for _, sess := range []*mockSession{sessAlice, sessBob} {
		found := false
		for _, raw := range sess.Received() {
			if hasPresenceType(raw, "unavailable") && hasDestroyElement(raw) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: did not receive destroy tombstone; got %v", sess.jid, sess.Received())
		}
	}
}

// mustParse is a test helper that parses a JID and fatals on error.
func mustParse(t *testing.T, s string) stanza.JID {
	t.Helper()
	j, err := stanza.Parse(s)
	if err != nil {
		t.Fatalf("stanza.Parse(%q): %v", s, err)
	}
	return j
}

// TestRoomDestroyDeletesPubsubNodes verifies that when a room is destroyed,
// all PEP nodes owned by that room JID are removed from the store so they do
// not persist across restarts.
func TestRoomDestroyDeletesPubsubNodes(t *testing.T) {
	ctx := context.Background()
	svc, stores, r := newMUCPubsubTestService(t)

	const roomJIDStr = "pubsubroom@conference.example.com"
	createTestRoom(svc, roomJIDStr, "alice@example.com", nil)

	_ = registerPubsubSession(t, r, "alice@example.com/res")
	owner, _ := stanza.Parse("alice@example.com/res")

	// Owner publishes a group:0 item so the node gets created in the store.
	iq := buildMUCPubsubIQ(roomJIDStr, owner.String(), "publish", xepGroupNode, []pubsubItem{{id: "e1", payload: []byte("<entry/>")}})
	raw, err := svc.HandleIQ(ctx, iq)
	if err != nil {
		t.Fatalf("publish HandleIQ: %v", err)
	}
	if !bytes.Contains(raw, []byte(`type="result"`)) {
		t.Fatalf("publish should succeed before destroy, got: %s", raw)
	}

	// Confirm the item is present in the store.
	items, err := stores.PEP.ListItems(ctx, roomJIDStr, xepGroupNode, 0)
	if err != nil {
		t.Fatalf("ListItems before destroy: %v", err)
	}
	if len(items) == 0 {
		t.Fatal("expected at least one item before destroy")
	}

	// Destroy the room.
	roomJID, _ := stanza.Parse(roomJIDStr)
	room := svc.getRoom(roomJID)
	if room == nil {
		t.Fatal("room not found")
	}
	if err := svc.destroyRoom(ctx, room, "", "gone"); err != nil {
		t.Fatalf("destroyRoom: %v", err)
	}

	// The PEP store must have no items for this room JID.
	items, err = stores.PEP.ListItems(ctx, roomJIDStr, xepGroupNode, 0)
	if err != nil {
		t.Fatalf("ListItems after destroy: %v", err)
	}
	if len(items) != 0 {
		t.Errorf("expected 0 items after room destroy, got %d", len(items))
	}
}

func hasXMLAttr(raw []byte, elem, attr, val string) bool {
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
		if se.Name.Local != elem {
			continue
		}
		for _, a := range se.Attr {
			if a.Name.Local == attr && a.Value == val {
				return true
			}
		}
	}
	return false
}

// TestMediatedInviteOpenRoom verifies XEP-0045 §7.8 forwarding for an open room.
func TestMediatedInviteOpenRoom(t *testing.T) {
	svc, r := newTestService(t)
	ctx := context.Background()

	sessA := registerSession(r, "alice@example.com/phone")
	sessB := registerSession(r, "bob@example.com/phone")
	_ = sessA

	// Alice joins, Bob is offline-but-known to the router.
	fromA, _ := stanza.Parse("alice@example.com/phone")
	toA, _ := stanza.Parse("openroom@conference.example.com/Alice")
	if err := svc.HandleStanza(ctx, presenceXML(fromA.String(), toA.Bare().String(), "Alice"), "presence", fromA, toA); err != nil {
		t.Fatalf("alice join: %v", err)
	}

	roomBare, _ := stanza.Parse("openroom@conference.example.com")
	invite := []byte(`<message from='alice@example.com/phone' to='openroom@conference.example.com'>` +
		`<x xmlns='http://jabber.org/protocol/muc#user'>` +
		`<invite to='bob@example.com'><reason>join us</reason></invite>` +
		`</x></message>`)
	if err := svc.HandleStanza(ctx, invite, "message", fromA, roomBare); err != nil {
		t.Fatalf("forward invite: %v", err)
	}

	recvB := sessB.Received()
	if len(recvB) == 0 {
		t.Fatal("bob received no invitation forward")
	}
	got := string(recvB[len(recvB)-1])
	if !strings.Contains(got, `from="openroom@conference.example.com"`) && !strings.Contains(got, "from='openroom@conference.example.com'") {
		t.Errorf("forwarded message must come from room bare JID; got: %s", got)
	}
	if !strings.Contains(got, `to="bob@example.com"`) && !strings.Contains(got, "to='bob@example.com'") {
		t.Errorf("forwarded message must address invitee; got: %s", got)
	}
	if !strings.Contains(got, `from="alice@example.com"`) && !strings.Contains(got, "from='alice@example.com'") {
		t.Errorf("forwarded <invite> must carry inviter's bare JID; got: %s", got)
	}
	if !strings.Contains(got, `<reason>join us</reason>`) {
		t.Errorf("forwarded invite must preserve reason; got: %s", got)
	}
	if !strings.Contains(got, "jabber:x:conference") {
		t.Errorf("forwarded message should include XEP-0249 shortcut; got: %s", got)
	}
}

// TestMediatedInviteRequiresOccupant rejects invites from non-occupants of a
// members-only room.
func TestMediatedInviteRequiresOccupant(t *testing.T) {
	svc, r := newTestService(t)
	ctx := context.Background()

	roomJID, _ := stanza.Parse("priv@conference.example.com")
	cfg := RoomConfig{Public: false, MembersOnly: true}
	room := newRoom(roomJID.Bare(), cfg, false, nil, nil)
	room.affiliations["alice@example.com"] = AffOwner
	svc.rooms.Store(roomJID.Bare().String(), room)

	_ = registerSession(r, "mallory@example.com/x")
	sessB := registerSession(r, "bob@example.com/phone")

	mallory, _ := stanza.Parse("mallory@example.com/x")
	invite := []byte(`<message from='mallory@example.com/x' to='priv@conference.example.com'>` +
		`<x xmlns='http://jabber.org/protocol/muc#user'><invite to='bob@example.com'/></x></message>`)
	err := svc.HandleStanza(ctx, invite, "message", mallory, roomJID)
	if err == nil {
		t.Fatal("expected forbidden error from non-member inviter to members-only room")
	}
	if se, ok := err.(*stanza.StanzaError); !ok || se.Condition != stanza.ErrForbidden {
		t.Errorf("expected forbidden, got %v", err)
	}
	if got := sessB.Received(); len(got) != 0 {
		t.Errorf("bob must not receive any invite forward; got %d", len(got))
	}
}

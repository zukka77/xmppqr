package muc

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/danielinux/xmppqr/internal/pubsub"
	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage"
	"github.com/danielinux/xmppqr/internal/storage/memstore"
)

// newMUCPubsubTestService constructs a MUC Service backed by a memstore with
// a real pubsub.Service wired in, then creates a room and registers the
// provided occupant sessions in the router.
func newMUCPubsubTestService(t *testing.T) (*Service, *storage.Stores, *router.Router) {
	t.Helper()
	stores := memstore.New()
	r := router.New()
	ps := pubsub.New(stores.PEP, r, slog.Default(), 0)
	svc := New("example.com", "conference", stores.MUC, nil, ps, r, slog.Default())
	return svc, stores, r
}

// registerPubsubSession adds a mock session for a full JID to the router.
func registerPubsubSession(t *testing.T, r *router.Router, fullJID string) *mockSession {
	t.Helper()
	j, err := stanza.Parse(fullJID)
	if err != nil {
		t.Fatalf("parse jid %q: %v", fullJID, err)
	}
	sess := &mockSession{jid: j}
	r.Register(sess)
	return sess
}

// buildMUCPubsubIQ builds a pubsub IQ targeted at a room JID.
func buildMUCPubsubIQ(host, from, op, node string, items []pubsubItem) *stanza.IQ {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)
	psEl := xml.StartElement{Name: xml.Name{Space: "http://jabber.org/protocol/pubsub", Local: "pubsub"}}
	enc.EncodeToken(psEl)

	switch op {
	case "publish":
		pubEl := xml.StartElement{
			Name: xml.Name{Local: "publish"},
			Attr: []xml.Attr{{Name: xml.Name{Local: "node"}, Value: node}},
		}
		enc.EncodeToken(pubEl)
		for _, it := range items {
			itemEl := xml.StartElement{
				Name: xml.Name{Local: "item"},
				Attr: []xml.Attr{{Name: xml.Name{Local: "id"}, Value: it.id}},
			}
			enc.EncodeToken(itemEl)
			enc.Flush()
			if len(it.payload) > 0 {
				buf.Write(it.payload)
			}
			enc.EncodeToken(itemEl.End())
		}
		enc.EncodeToken(pubEl.End())
	case "subscribe":
		subEl := xml.StartElement{
			Name: xml.Name{Local: "subscribe"},
			Attr: []xml.Attr{
				{Name: xml.Name{Local: "node"}, Value: node},
				{Name: xml.Name{Local: "jid"}, Value: from},
			},
		}
		enc.EncodeToken(subEl)
		enc.EncodeToken(subEl.End())
	}
	enc.EncodeToken(psEl.End())
	enc.Flush()

	return &stanza.IQ{
		ID:      "muc-ps",
		From:    from,
		To:      host,
		Type:    stanza.IQSet,
		Payload: buf.Bytes(),
	}
}

type pubsubItem struct {
	id      string
	payload []byte
}

// createTestRoom registers a new room in svc with given owner and affiliations.
func createTestRoom(svc *Service, roomJIDStr, ownerBare string, extraAffs map[string]int) *Room {
	roomJID, _ := stanza.Parse(roomJIDStr)
	cfg := RoomConfig{
		Public:      true,
		MembersOnly: false,
	}
	room := newRoom(roomJID.Bare(), cfg, false, nil, nil)
	room.affiliations[ownerBare] = AffOwner
	for jid, aff := range extraAffs {
		room.affiliations[jid] = aff
	}
	svc.rooms.Store(roomJID.Bare().String(), room)
	return room
}

func TestMUCPubsubHostAllowsOwnerPublish(t *testing.T) {
	svc, _, _ := newMUCPubsubTestService(t)
	room := createTestRoom(svc, "room@conference.example.com", "alice@example.com", map[string]int{
		"bob@example.com": AffMember,
	})
	_ = room

	ctx := context.Background()
	owner, _ := stanza.Parse("alice@example.com/res")
	nonOwner, _ := stanza.Parse("bob@example.com/phone")

	roomJIDStr := "room@conference.example.com"
	node := "urn:test:group:0"

	// Owner (alice) can publish.
	iq := buildMUCPubsubIQ(roomJIDStr, owner.String(), "publish", node, []pubsubItem{{id: "e1", payload: []byte("<entry/>")}})
	raw, err := svc.HandleIQ(ctx, iq)
	if err != nil {
		t.Fatalf("owner publish HandleIQ: %v", err)
	}
	if !bytes.Contains(raw, []byte(`type="result"`)) {
		t.Errorf("owner publish should succeed, got: %s", raw)
	}

	// Non-owner member (bob) cannot publish.
	iq2 := buildMUCPubsubIQ(roomJIDStr, nonOwner.String(), "publish", node, []pubsubItem{{id: "e2", payload: []byte("<entry/>")}})
	raw2, err := svc.HandleIQ(ctx, iq2)
	if err != nil {
		t.Fatalf("non-owner publish HandleIQ: %v", err)
	}
	if !bytes.Contains(raw2, []byte("forbidden")) {
		t.Errorf("non-owner publish should be forbidden, got: %s", raw2)
	}
}

func TestMUCPubsubHostAllowsMemberSubscribe(t *testing.T) {
	svc, _, _ := newMUCPubsubTestService(t)
	createTestRoom(svc, "room@conference.example.com", "alice@example.com", map[string]int{
		"bob@example.com":   AffMember,
		"carol@example.com": AffNone,
	})

	ctx := context.Background()
	member, _ := stanza.Parse("bob@example.com/phone")
	nonMember, _ := stanza.Parse("carol@example.com/laptop")
	node := "urn:test:group:0"
	roomJIDStr := "room@conference.example.com"

	// Make the room members-only so non-members get forbidden.
	room := svc.getRoom(stanza.JID{Local: "room", Domain: "conference.example.com"})
	room.mu.Lock()
	room.config.MembersOnly = true
	room.mu.Unlock()

	// Member (bob) can subscribe.
	iq := buildMUCPubsubIQ(roomJIDStr, member.String(), "subscribe", node, nil)
	raw, err := svc.HandleIQ(ctx, iq)
	if err != nil {
		t.Fatalf("member subscribe HandleIQ: %v", err)
	}
	if !bytes.Contains(raw, []byte(`type="result"`)) {
		t.Errorf("member subscribe should succeed, got: %s", raw)
	}

	// Non-member (carol) is forbidden in a members-only room.
	iq2 := buildMUCPubsubIQ(roomJIDStr, nonMember.String(), "subscribe", node, nil)
	raw2, err := svc.HandleIQ(ctx, iq2)
	if err != nil {
		t.Fatalf("non-member subscribe HandleIQ: %v", err)
	}
	if !bytes.Contains(raw2, []byte("forbidden")) {
		t.Errorf("non-member subscribe should be forbidden in members-only room, got: %s", raw2)
	}
}

func TestMUCPubsubHostOpenPublicRoomLetsAnyoneSubscribe(t *testing.T) {
	svc, _, _ := newMUCPubsubTestService(t)
	// Open, public room: MembersOnly=false, Public=true (defaults).
	createTestRoom(svc, "open@conference.example.com", "alice@example.com", nil)

	ctx := context.Background()
	stranger, _ := stanza.Parse("stranger@example.com/mob")
	node := "urn:test:group:0"
	roomJIDStr := "open@conference.example.com"

	iq := buildMUCPubsubIQ(roomJIDStr, stranger.String(), "subscribe", node, nil)
	raw, err := svc.HandleIQ(ctx, iq)
	if err != nil {
		t.Fatalf("HandleIQ: %v", err)
	}
	if !bytes.Contains(raw, []byte(`type="result"`)) {
		t.Errorf("open-public room should allow anyone to subscribe, got: %s", raw)
	}
}

func TestMUCPubsubHostDropsSubscriptionsOnEviction(t *testing.T) {
	svc, stores, r := newMUCPubsubTestService(t)
	createTestRoom(svc, "room@conference.example.com", "alice@example.com", map[string]int{
		"bob@example.com": AffMember,
	})

	// Register bob's session in the router so subscribe delivery does not error.
	_ = registerPubsubSession(t, r, "bob@example.com/phone")

	ctx := context.Background()
	bob, _ := stanza.Parse("bob@example.com/phone")
	alice, _ := stanza.Parse("alice@example.com/res")
	node := "urn:test:group:0"
	roomJIDStr := "room@conference.example.com"

	// Bob subscribes to the room's node.
	subIQ := buildMUCPubsubIQ(roomJIDStr, bob.String(), "subscribe", node, nil)
	if _, err := svc.HandleIQ(ctx, subIQ); err != nil {
		t.Fatalf("bob subscribe: %v", err)
	}

	// Verify bob is subscribed.
	subs, err := stores.PEP.ListSubscribers(ctx, "room@conference.example.com", node)
	if err != nil {
		t.Fatalf("ListSubscribers: %v", err)
	}
	found := false
	for _, s := range subs {
		if s == bob.Bare().String() {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("bob should be subscribed before eviction, subs: %v", subs)
	}

	// Admin (alice) demotes bob to none — triggers eviction and subscription drop.
	roomJID, _ := stanza.Parse(roomJIDStr)
	room := svc.getRoom(roomJID)
	if room == nil {
		t.Fatal("room not found")
	}
	if err := room.setAffiliationFull(ctx, alice, bob, AffNone, "evicted", nil, r); err != nil {
		t.Fatalf("setAffiliationFull: %v", err)
	}

	// Give the goroutine time to run.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		subs, _ = stores.PEP.ListSubscribers(ctx, "room@conference.example.com", node)
		found = false
		for _, s := range subs {
			if s == bob.Bare().String() {
				found = true
				break
			}
		}
		if !found {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if found {
		t.Error("bob's subscription should have been dropped after eviction")
	}
}

// TestX3DHPQGroupPublishRequiresOwner verifies that publishing to
// urn:xmppqr:x3dhpq:group:0 requires AffOwner.
// An admin (not owner) must be rejected; the owner must succeed.
// Other nodes (non-group) must still allow admin-level publish.
func TestX3DHPQGroupPublishRequiresOwner(t *testing.T) {
	svc, _, _ := newMUCPubsubTestService(t)
	createTestRoom(svc, "room@conference.example.com", "alice@example.com", map[string]int{
		"bob@example.com": AffAdmin, // admin, not owner
	})

	ctx := context.Background()
	owner, _ := stanza.Parse("alice@example.com/res")
	admin, _ := stanza.Parse("bob@example.com/phone")

	roomJIDStr := "room@conference.example.com"

	// Admin (bob) cannot publish to the group node.
	iq := buildMUCPubsubIQ(roomJIDStr, admin.String(), "publish", xepGroupNode, []pubsubItem{{id: "e1", payload: []byte("<entry/>")}})
	raw, err := svc.HandleIQ(ctx, iq)
	if err != nil {
		t.Fatalf("admin publish group node HandleIQ: %v", err)
	}
	if !bytes.Contains(raw, []byte("forbidden")) {
		t.Errorf("admin should be forbidden from publishing to group node, got: %s", raw)
	}

	// Owner (alice) can publish to the group node.
	iq2 := buildMUCPubsubIQ(roomJIDStr, owner.String(), "publish", xepGroupNode, []pubsubItem{{id: "e2", payload: []byte("<entry/>")}})
	raw2, err := svc.HandleIQ(ctx, iq2)
	if err != nil {
		t.Fatalf("owner publish group node HandleIQ: %v", err)
	}
	if !bytes.Contains(raw2, []byte(`type="result"`)) {
		t.Errorf("owner publish to group node should succeed, got: %s", raw2)
	}

	// Admin (bob) CAN publish to a different (non-group) node.
	iq3 := buildMUCPubsubIQ(roomJIDStr, admin.String(), "publish", "urn:test:other:0", []pubsubItem{{id: "e3", payload: []byte("<entry/>")}})
	raw3, err := svc.HandleIQ(ctx, iq3)
	if err != nil {
		t.Fatalf("admin publish other node HandleIQ: %v", err)
	}
	if !bytes.Contains(raw3, []byte(`type="result"`)) {
		t.Errorf("admin publish to non-group node should succeed, got: %s", raw3)
	}
}

// TestX3DHPQGroupPublishSizeCapEnforced verifies that items larger than
// groupNodeItemMaxBytes (16 KiB) are rejected with <not-acceptable/>, and
// items within the limit succeed.
func TestX3DHPQGroupPublishSizeCapEnforced(t *testing.T) {
	svc, _, _ := newMUCPubsubTestService(t)
	createTestRoom(svc, "room@conference.example.com", "alice@example.com", nil)

	ctx := context.Background()
	owner, _ := stanza.Parse("alice@example.com/res")
	roomJIDStr := "room@conference.example.com"

	// 17 KiB payload — must be rejected.
	big := make([]byte, 17*1024)
	for i := range big {
		big[i] = 'x'
	}
	iq := buildMUCPubsubIQ(roomJIDStr, owner.String(), "publish", xepGroupNode, []pubsubItem{{id: "big", payload: big}})
	raw, err := svc.HandleIQ(ctx, iq)
	if err != nil {
		t.Fatalf("big publish HandleIQ: %v", err)
	}
	if !bytes.Contains(raw, []byte("not-acceptable")) {
		t.Errorf("17 KiB item should be rejected with not-acceptable, got: %s", raw)
	}

	// 15 KiB payload — must succeed.
	small := make([]byte, 15*1024)
	for i := range small {
		small[i] = 'y'
	}
	iq2 := buildMUCPubsubIQ(roomJIDStr, owner.String(), "publish", xepGroupNode, []pubsubItem{{id: "small", payload: small}})
	raw2, err := svc.HandleIQ(ctx, iq2)
	if err != nil {
		t.Fatalf("small publish HandleIQ: %v", err)
	}
	if !bytes.Contains(raw2, []byte(`type="result"`)) {
		t.Errorf("15 KiB item should succeed, got: %s", raw2)
	}
}

// TestX3DHPQGroupItemCapPrunesOldest verifies that after 205 publishes to the
// group node, ListItems returns at most 200 items and the oldest are gone.
func TestX3DHPQGroupItemCapPrunesOldest(t *testing.T) {
	svc, stores, _ := newMUCPubsubTestService(t)
	createTestRoom(svc, "room@conference.example.com", "alice@example.com", nil)

	ctx := context.Background()
	owner, _ := stanza.Parse("alice@example.com/res")
	roomJIDStr := "room@conference.example.com"

	// Publish 205 items.
	for i := 0; i < 205; i++ {
		id := fmt.Sprintf("entry-%03d", i)
		iq := buildMUCPubsubIQ(roomJIDStr, owner.String(), "publish", xepGroupNode, []pubsubItem{
			{id: id, payload: []byte("<entry/>")},
		})
		raw, err := svc.HandleIQ(ctx, iq)
		if err != nil {
			t.Fatalf("publish %d: HandleIQ error: %v", i, err)
		}
		if !bytes.Contains(raw, []byte(`type="result"`)) {
			t.Fatalf("publish %d: unexpected response: %s", i, raw)
		}
	}

	// After 205 publishes the store should hold at most groupNodeItemCap (200) items.
	items, err := stores.PEP.ListItems(ctx, "room@conference.example.com", xepGroupNode, 0)
	if err != nil {
		t.Fatalf("ListItems: %v", err)
	}
	if len(items) > groupNodeItemCap {
		t.Errorf("expected at most %d items, got %d", groupNodeItemCap, len(items))
	}
	// The first 5 items (entry-000 through entry-004) should have been pruned.
	for _, it := range items {
		for i := 0; i < 5; i++ {
			pruned := fmt.Sprintf("entry-%03d", i)
			if it.ItemID == pruned {
				t.Errorf("pruned item %q still present after cap enforcement", pruned)
			}
		}
	}
}

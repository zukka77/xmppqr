package memstore

import (
	"context"
	"testing"
	"time"

	"github.com/danielinux/xmppqr/internal/storage"
)

var ctx = context.Background()

func TestUsers(t *testing.T) {
	s := newUserStore()

	u := &storage.User{Username: "alice", ScramIter: 4096, Disabled: false}
	if err := s.Put(ctx, u); err != nil {
		t.Fatal(err)
	}

	got, err := s.Get(ctx, "alice")
	if err != nil || got.Username != "alice" {
		t.Fatalf("get: %v %v", got, err)
	}

	list, err := s.List(ctx, 10, 0)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v", err)
	}

	if err := s.Delete(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "alice"); err == nil {
		t.Fatal("expected not found after delete")
	}
}

func TestUserListPagination(t *testing.T) {
	s := newUserStore()
	for _, name := range []string{"a", "b", "c"} {
		s.Put(ctx, &storage.User{Username: name})
	}
	list, _ := s.List(ctx, 2, 0)
	if len(list) != 2 {
		t.Fatalf("expected 2, got %d", len(list))
	}
	list2, _ := s.List(ctx, 10, 2)
	if len(list2) != 1 {
		t.Fatalf("expected 1, got %d", len(list2))
	}
}

func TestRoster(t *testing.T) {
	s := newRosterStore()

	item := &storage.RosterItem{Owner: "alice", Contact: "bob@example.com", Subscription: 3}
	ver, err := s.Put(ctx, item)
	if err != nil || ver != 1 {
		t.Fatalf("put: %v %d", err, ver)
	}

	items, cv, err := s.Get(ctx, "alice")
	if err != nil || len(items) != 1 || cv != 1 {
		t.Fatalf("get: %v %v %d", items, err, cv)
	}

	ver2, err := s.Delete(ctx, "alice", "bob@example.com")
	if err != nil || ver2 != 2 {
		t.Fatalf("delete: %v %d", err, ver2)
	}

	items, _, _ = s.Get(ctx, "alice")
	if len(items) != 0 {
		t.Fatal("expected empty roster after delete")
	}
}

func TestMAM(t *testing.T) {
	s := newMAMStore()

	now := time.Now()
	id, err := s.Append(ctx, &storage.ArchivedStanza{
		Owner: "alice", With: "bob@example.com", TS: now, StanzaXML: []byte("<msg/>"),
	})
	if err != nil || id != 1 {
		t.Fatalf("append: %v %d", err, id)
	}

	bob := storage.JID("bob@example.com")
	msgs, err := s.Query(ctx, "alice", &bob, nil, nil, 10)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("query: %v %v", msgs, err)
	}

	past := now.Add(-time.Hour)
	n, err := s.Prune(ctx, "alice", past)
	if err != nil || n != 0 {
		t.Fatalf("prune past: %v %d", err, n)
	}

	future := now.Add(time.Hour)
	n, err = s.Prune(ctx, "alice", future)
	if err != nil || n != 1 {
		t.Fatalf("prune future: %v %d", err, n)
	}
}

func TestPEP(t *testing.T) {
	s := newPEPStore()

	node := &storage.PEPNode{Owner: "alice", Node: "urn:xmpp:mood:0", AccessModel: 0}
	if err := s.PutNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	gn, err := s.GetNode(ctx, "alice", "urn:xmpp:mood:0")
	if err != nil || gn.Node != node.Node {
		t.Fatalf("get node: %v %v", gn, err)
	}

	item := &storage.PEPItem{Owner: "alice", Node: "urn:xmpp:mood:0", ItemID: "current", Payload: []byte("<mood/>")}
	if err := s.PutItem(ctx, item); err != nil {
		t.Fatal(err)
	}

	gi, err := s.GetItem(ctx, "alice", "urn:xmpp:mood:0", "current")
	if err != nil || gi.ItemID != "current" {
		t.Fatalf("get item: %v %v", gi, err)
	}

	list, err := s.ListItems(ctx, "alice", "urn:xmpp:mood:0", 10)
	if err != nil || len(list) != 1 {
		t.Fatalf("list items: %v", err)
	}

	if err := s.DeleteItem(ctx, "alice", "urn:xmpp:mood:0", "current"); err != nil {
		t.Fatal(err)
	}
	list, _ = s.ListItems(ctx, "alice", "urn:xmpp:mood:0", 10)
	if len(list) != 0 {
		t.Fatal("expected 0 items after delete")
	}

	if err := s.DeleteNode(ctx, "alice", "urn:xmpp:mood:0"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetNode(ctx, "alice", "urn:xmpp:mood:0"); err == nil {
		t.Fatal("expected not found after node delete")
	}
}

func TestMUC(t *testing.T) {
	s := newMUCStore()

	room := &storage.MUCRoom{JID: "chat@conference.example.com", Persistent: true}
	if err := s.PutRoom(ctx, room); err != nil {
		t.Fatal(err)
	}

	gr, err := s.GetRoom(ctx, "chat@conference.example.com")
	if err != nil || !gr.Persistent {
		t.Fatalf("get room: %v %v", gr, err)
	}

	aff := &storage.MUCAffiliation{RoomJID: "chat@conference.example.com", UserJID: "alice@example.com", Affiliation: 4}
	if err := s.PutAffiliation(ctx, aff); err != nil {
		t.Fatal(err)
	}

	affs, err := s.ListAffiliations(ctx, "chat@conference.example.com")
	if err != nil || len(affs) != 1 {
		t.Fatalf("list affiliations: %v %v", affs, err)
	}

	if err := s.DeleteRoom(ctx, "chat@conference.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetRoom(ctx, "chat@conference.example.com"); err == nil {
		t.Fatal("expected not found after room delete")
	}
	affs, _ = s.ListAffiliations(ctx, "chat@conference.example.com")
	if len(affs) != 0 {
		t.Fatal("affiliations should be removed with room")
	}
}

func TestPush(t *testing.T) {
	s := newPushStore()

	reg := &storage.PushRegistration{Owner: "alice", ServiceJID: "push.example.com", Node: "token123"}
	if err := s.Put(ctx, reg); err != nil {
		t.Fatal(err)
	}

	list, err := s.List(ctx, "alice")
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %v", list, err)
	}

	if err := s.Delete(ctx, "alice", "push.example.com", "token123"); err != nil {
		t.Fatal(err)
	}
	list, _ = s.List(ctx, "alice")
	if len(list) != 0 {
		t.Fatal("expected empty after delete")
	}
}

func TestBlock(t *testing.T) {
	s := newBlockStore()

	if err := s.Add(ctx, "alice", "spam@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(ctx, "alice", "evil@example.com"); err != nil {
		t.Fatal(err)
	}

	list, err := s.List(ctx, "alice")
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %v %v", list, err)
	}

	if err := s.Remove(ctx, "alice", "spam@example.com"); err != nil {
		t.Fatal(err)
	}
	list, _ = s.List(ctx, "alice")
	if len(list) != 1 {
		t.Fatalf("expected 1 after remove, got %d", len(list))
	}

	if err := s.Clear(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	list, _ = s.List(ctx, "alice")
	if len(list) != 0 {
		t.Fatal("expected 0 after clear")
	}
}

func TestOffline(t *testing.T) {
	s := newOfflineStore()

	now := time.Now()
	id, err := s.Push(ctx, &storage.OfflineMessage{Owner: "alice", TS: now, Stanza: []byte("<msg/>")})
	if err != nil || id != 1 {
		t.Fatalf("push: %v %d", err, id)
	}
	s.Push(ctx, &storage.OfflineMessage{Owner: "alice", TS: now, Stanza: []byte("<msg2/>")})

	n, err := s.Count(ctx, "alice")
	if err != nil || n != 2 {
		t.Fatalf("count: %v %d", err, n)
	}

	msgs, err := s.Pop(ctx, "alice", 1)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("pop: %v %v", msgs, err)
	}

	n, _ = s.Count(ctx, "alice")
	if n != 1 {
		t.Fatalf("expected 1 remaining, got %d", n)
	}
}

func TestNew(t *testing.T) {
	stores := New()
	if stores.Users == nil || stores.Roster == nil || stores.MAM == nil ||
		stores.PEP == nil || stores.MUC == nil || stores.Push == nil ||
		stores.Block == nil || stores.Offline == nil {
		t.Fatal("New() left a nil store field")
	}
}

func TestMUCSubject(t *testing.T) {
	s := newMUCStore()
	room := &storage.MUCRoom{JID: "chat@conference.example.com", Persistent: true}
	if err := s.PutRoom(ctx, room); err != nil {
		t.Fatal(err)
	}

	sub, by, ts, err := s.GetRoomSubject(ctx, room.JID)
	if err != nil {
		t.Fatalf("get before put: %v", err)
	}
	if sub != "" || by != "" || !ts.IsZero() {
		t.Fatal("expected zero values before first put")
	}

	now := time.Now()
	if err := s.PutRoomSubject(ctx, room.JID, "Welcome", "alice", now); err != nil {
		t.Fatal(err)
	}
	sub, by, ts, err = s.GetRoomSubject(ctx, room.JID)
	if err != nil {
		t.Fatalf("get after put: %v", err)
	}
	if sub != "Welcome" || by != "alice" || !ts.Equal(now) {
		t.Fatalf("got subject=%q by=%q ts=%v", sub, by, ts)
	}

	now2 := now.Add(time.Minute)
	if err := s.PutRoomSubject(ctx, room.JID, "Updated", "bob", now2); err != nil {
		t.Fatal(err)
	}
	sub, by, _, err = s.GetRoomSubject(ctx, room.JID)
	if err != nil || sub != "Updated" || by != "bob" {
		t.Fatalf("overwrite: sub=%q by=%q err=%v", sub, by, err)
	}
}

func TestMUCHistory(t *testing.T) {
	s := newMUCStore()
	room := &storage.MUCRoom{JID: "chat@conference.example.com", Persistent: true}
	s.PutRoom(ctx, room)

	base := time.Now()
	for i := 0; i < 3; i++ {
		h := &storage.MUCHistory{
			RoomJID:   room.JID,
			SenderJID: "alice@example.com/phone",
			TS:        base.Add(time.Duration(i) * time.Second),
			StanzaID:  "id" + string(rune('0'+i)),
			StanzaXML: []byte("<message/>"),
		}
		id, err := s.AppendHistory(ctx, h)
		if err != nil || id != int64(i+1) {
			t.Fatalf("append %d: id=%d err=%v", i, id, err)
		}
	}

	all, err := s.QueryHistory(ctx, room.JID, nil, nil, 0)
	if err != nil || len(all) != 3 {
		t.Fatalf("query all: len=%d err=%v", len(all), err)
	}

	after := base.Add(500 * time.Millisecond)
	some, err := s.QueryHistory(ctx, room.JID, nil, &after, 0)
	if err != nil || len(some) != 2 {
		t.Fatalf("query after: len=%d err=%v", len(some), err)
	}

	before := base.Add(2 * time.Second)
	some, err = s.QueryHistory(ctx, room.JID, &before, nil, 0)
	if err != nil || len(some) != 2 {
		t.Fatalf("query before: len=%d err=%v", len(some), err)
	}

	limited, err := s.QueryHistory(ctx, room.JID, nil, nil, 2)
	if err != nil || len(limited) != 2 {
		t.Fatalf("query limit: len=%d err=%v", len(limited), err)
	}

	del, err := s.DeleteHistoryBefore(ctx, room.JID, base.Add(2*time.Second))
	if err != nil || del != 2 {
		t.Fatalf("delete before: del=%d err=%v", del, err)
	}
	remaining, _ := s.QueryHistory(ctx, room.JID, nil, nil, 0)
	if len(remaining) != 1 {
		t.Fatalf("expected 1 remaining, got %d", len(remaining))
	}
}

func TestMUCMAM(t *testing.T) {
	s := newMAMStore()
	room := "chat@conference.example.com"

	base := time.Now()
	for i := 0; i < 3; i++ {
		m := &storage.MUCArchivedStanza{
			RoomJID:       room,
			SenderBareJID: "alice@example.com",
			TS:            base.Add(time.Duration(i) * time.Second),
			StanzaID:      "sid" + string(rune('0'+i)),
			OriginID:      "oid" + string(rune('0'+i)),
			StanzaXML:     []byte("<message/>"),
		}
		id, err := s.AppendMUC(ctx, m)
		if err != nil || id != int64(i+1) {
			t.Fatalf("append muc %d: id=%d err=%v", i, id, err)
		}
	}
	extra := &storage.MUCArchivedStanza{
		RoomJID:       room,
		SenderBareJID: "bob@example.com",
		TS:            base.Add(3 * time.Second),
		StanzaXML:     []byte("<message/>"),
	}
	s.AppendMUC(ctx, extra)

	all, err := s.QueryMUC(ctx, room, nil, nil, nil, 0)
	if err != nil || len(all) != 4 {
		t.Fatalf("query all: len=%d err=%v", len(all), err)
	}

	alice := storage.JID("alice@example.com")
	byAlice, err := s.QueryMUC(ctx, room, &alice, nil, nil, 0)
	if err != nil || len(byAlice) != 3 {
		t.Fatalf("query by sender: len=%d err=%v", len(byAlice), err)
	}

	after := base.Add(500 * time.Millisecond)
	some, err := s.QueryMUC(ctx, room, nil, nil, &after, 0)
	if err != nil || len(some) != 3 {
		t.Fatalf("query after: len=%d err=%v", len(some), err)
	}

	before := base.Add(2 * time.Second)
	some, err = s.QueryMUC(ctx, room, nil, &before, nil, 0)
	if err != nil || len(some) != 2 {
		t.Fatalf("query before: len=%d err=%v", len(some), err)
	}

	limited, err := s.QueryMUC(ctx, room, nil, nil, nil, 2)
	if err != nil || len(limited) != 2 {
		t.Fatalf("query limit: len=%d err=%v", len(limited), err)
	}

	pruned, err := s.PruneMUC(ctx, room, base.Add(2*time.Second))
	if err != nil || pruned != 2 {
		t.Fatalf("prune: pruned=%d err=%v", pruned, err)
	}
	remaining, _ := s.QueryMUC(ctx, room, nil, nil, nil, 0)
	if len(remaining) != 2 {
		t.Fatalf("expected 2 remaining after prune, got %d", len(remaining))
	}
}

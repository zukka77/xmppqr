//go:build pgintegration

package pg

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/danielinux/xmppqr/internal/storage"
)

func testDB(t *testing.T) *DB {
	t.Helper()
	dsn := os.Getenv("XMPPQR_TEST_DSN")
	if dsn == "" {
		dsn = "postgres://postgres@localhost:5432/xmppqr_test?sslmode=disable"
	}
	ctx := context.Background()
	db, err := Open(ctx, dsn, 5)
	if err != nil {
		t.Skipf("no PG available: %v", err)
	}
	t.Cleanup(db.Close)
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestMigrate(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

func TestPGUsers(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	s := &pgUsers{pool: db.pool}

	u := &storage.User{Username: "pgtest_alice", ScramIter: 4096, CreatedAt: time.Now()}
	if err := s.Put(ctx, u); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Delete(ctx, u.Username) })

	got, err := s.Get(ctx, "pgtest_alice")
	if err != nil || got.Username != "pgtest_alice" {
		t.Fatalf("get: %v %v", got, err)
	}

	list, err := s.List(ctx, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, lu := range list {
		if lu.Username == "pgtest_alice" {
			found = true
		}
	}
	if !found {
		t.Fatal("alice not in list")
	}

	if err := s.Delete(ctx, "pgtest_alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "pgtest_alice"); err == nil {
		t.Fatal("expected not found after delete")
	}
}

func TestPGRoster(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	us := &pgUsers{pool: db.pool}
	owner := "pgtest_rowner"
	us.Put(ctx, &storage.User{Username: owner, CreatedAt: time.Now()})
	t.Cleanup(func() { us.Delete(ctx, owner) })

	s := &pgRoster{pool: db.pool}
	item := &storage.RosterItem{Owner: owner, Contact: "bob@example.com", Subscription: 1}
	ver, err := s.Put(ctx, item)
	if err != nil || ver != 1 {
		t.Fatalf("put: %v %d", err, ver)
	}

	items, cv, err := s.Get(ctx, owner)
	if err != nil || len(items) != 1 || cv != 1 {
		t.Fatalf("get: %v %v %d", items, err, cv)
	}

	ver2, err := s.Delete(ctx, owner, "bob@example.com")
	if err != nil || ver2 != 2 {
		t.Fatalf("delete: %v %d", err, ver2)
	}

	items, _, _ = s.Get(ctx, owner)
	if len(items) != 0 {
		t.Fatal("expected empty roster after delete")
	}
}

func TestPGMAM(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	us := &pgUsers{pool: db.pool}
	owner := "pgtest_mamowner"
	us.Put(ctx, &storage.User{Username: owner, CreatedAt: time.Now()})
	t.Cleanup(func() { us.Delete(ctx, owner) })

	s := &pgMAM{pool: db.pool}
	now := time.Now().UTC().Truncate(time.Millisecond)
	id, err := s.Append(ctx, &storage.ArchivedStanza{
		Owner: owner, With: "bob@example.com", TS: now, StanzaXML: []byte("<msg/>"),
	})
	if err != nil || id == 0 {
		t.Fatalf("append: %v %d", err, id)
	}

	bob := storage.JID("bob@example.com")
	msgs, err := s.Query(ctx, owner, &bob, nil, nil, 10)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("query: %v %v", msgs, err)
	}

	past := now.Add(-time.Hour)
	n, err := s.Prune(ctx, owner, past)
	if err != nil || n != 0 {
		t.Fatalf("prune past: %v %d", err, n)
	}

	future := now.Add(time.Hour)
	n, err = s.Prune(ctx, owner, future)
	if err != nil || n != 1 {
		t.Fatalf("prune future: %v %d", err, n)
	}
}

func TestPGPEP(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	us := &pgUsers{pool: db.pool}
	owner := "pgtest_pepowner"
	us.Put(ctx, &storage.User{Username: owner, CreatedAt: time.Now()})
	t.Cleanup(func() { us.Delete(ctx, owner) })

	s := &pgPEP{pool: db.pool}
	node := &storage.PEPNode{Owner: owner, Node: "urn:xmpp:mood:0"}
	if err := s.PutNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	gn, err := s.GetNode(ctx, owner, "urn:xmpp:mood:0")
	if err != nil || gn.Node != node.Node {
		t.Fatalf("get node: %v %v", gn, err)
	}

	item := &storage.PEPItem{Owner: owner, Node: "urn:xmpp:mood:0", ItemID: "current",
		Payload: []byte("<mood/>"), PublishedAt: time.Now()}
	if err := s.PutItem(ctx, item); err != nil {
		t.Fatal(err)
	}
	gi, err := s.GetItem(ctx, owner, "urn:xmpp:mood:0", "current")
	if err != nil || gi.ItemID != "current" {
		t.Fatalf("get item: %v %v", gi, err)
	}
	list, err := s.ListItems(ctx, owner, "urn:xmpp:mood:0", 10)
	if err != nil || len(list) != 1 {
		t.Fatalf("list items: %v", err)
	}
	list, err = s.ListItems(ctx, owner, "urn:xmpp:mood:0", 0)
	if err != nil || len(list) != 1 {
		t.Fatalf("list items zero limit: len=%d err=%v", len(list), err)
	}
	if err := s.DeleteItem(ctx, owner, "urn:xmpp:mood:0", "current"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteNode(ctx, owner, "urn:xmpp:mood:0"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetNode(ctx, owner, "urn:xmpp:mood:0"); err == nil {
		t.Fatal("expected not found after delete")
	}
}

func TestPGMUC(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	s := &pgMUC{pool: db.pool}

	room := &storage.MUCRoom{JID: "pgtest_chat@conference.example.com", Persistent: true, CreatedAt: time.Now()}
	if err := s.PutRoom(ctx, room); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DeleteRoom(ctx, room.JID) })

	gr, err := s.GetRoom(ctx, room.JID)
	if err != nil || !gr.Persistent {
		t.Fatalf("get room: %v %v", gr, err)
	}

	aff := &storage.MUCAffiliation{RoomJID: room.JID, UserJID: "alice@example.com", Affiliation: 4}
	if err := s.PutAffiliation(ctx, aff); err != nil {
		t.Fatal(err)
	}
	affs, err := s.ListAffiliations(ctx, room.JID)
	if err != nil || len(affs) != 1 {
		t.Fatalf("list affiliations: %v %v", affs, err)
	}

	if err := s.DeleteRoom(ctx, room.JID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetRoom(ctx, room.JID); err == nil {
		t.Fatal("expected not found after delete")
	}
}

func TestPGPush(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	us := &pgUsers{pool: db.pool}
	owner := "pgtest_pushowner"
	us.Put(ctx, &storage.User{Username: owner, CreatedAt: time.Now()})
	t.Cleanup(func() { us.Delete(ctx, owner) })

	s := &pgPush{pool: db.pool}
	reg := &storage.PushRegistration{Owner: owner, ServiceJID: "push.example.com", Node: "tok", EnabledAt: time.Now()}
	if err := s.Put(ctx, reg); err != nil {
		t.Fatal(err)
	}
	list, err := s.List(ctx, owner)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %v", list, err)
	}
	if err := s.Delete(ctx, owner, "push.example.com", "tok"); err != nil {
		t.Fatal(err)
	}
	list, _ = s.List(ctx, owner)
	if len(list) != 0 {
		t.Fatal("expected empty after delete")
	}
}

func TestPGBlock(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	us := &pgUsers{pool: db.pool}
	owner := "pgtest_blockowner"
	us.Put(ctx, &storage.User{Username: owner, CreatedAt: time.Now()})
	t.Cleanup(func() { us.Delete(ctx, owner) })

	s := &pgBlock{pool: db.pool}
	if err := s.Add(ctx, owner, "spam@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(ctx, owner, "evil@example.com"); err != nil {
		t.Fatal(err)
	}
	list, err := s.List(ctx, owner)
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %v %v", list, err)
	}
	if err := s.Remove(ctx, owner, "spam@example.com"); err != nil {
		t.Fatal(err)
	}
	list, _ = s.List(ctx, owner)
	if len(list) != 1 {
		t.Fatalf("expected 1 after remove, got %d", len(list))
	}
	if err := s.Clear(ctx, owner); err != nil {
		t.Fatal(err)
	}
	list, _ = s.List(ctx, owner)
	if len(list) != 0 {
		t.Fatal("expected 0 after clear")
	}
}

func TestPGOffline(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	us := &pgUsers{pool: db.pool}
	owner := "pgtest_offlineowner"
	us.Put(ctx, &storage.User{Username: owner, CreatedAt: time.Now()})
	t.Cleanup(func() { us.Delete(ctx, owner) })

	s := &pgOffline{pool: db.pool}
	now := time.Now()
	id, err := s.Push(ctx, &storage.OfflineMessage{Owner: owner, TS: now, Stanza: []byte("<msg/>")})
	if err != nil || id == 0 {
		t.Fatalf("push: %v %d", err, id)
	}
	s.Push(ctx, &storage.OfflineMessage{Owner: owner, TS: now, Stanza: []byte("<msg2/>")})

	n, err := s.Count(ctx, owner)
	if err != nil || n != 2 {
		t.Fatalf("count: %v %d", err, n)
	}

	msgs, err := s.Pop(ctx, owner, 1)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("pop: %v %v", msgs, err)
	}

	n, _ = s.Count(ctx, owner)
	if n != 1 {
		t.Fatalf("expected 1 remaining, got %d", n)
	}
}

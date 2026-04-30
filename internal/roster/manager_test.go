package roster

import (
	"context"
	"log/slog"
	"testing"

	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage/memstore"
)

func newManager() *Manager {
	s := memstore.New()
	return New(s.Roster, slog.Default())
}

func mustParse(s string) stanza.JID {
	j, err := stanza.Parse(s)
	if err != nil {
		panic(err)
	}
	return j
}

func TestGetSetRemove(t *testing.T) {
	ctx := context.Background()
	m := newManager()
	owner := "alice@example.com"
	contact := mustParse("bob@example.com")

	items, ver, err := m.Get(ctx, owner)
	if err != nil || len(items) != 0 || ver != 0 {
		t.Fatalf("empty roster: items=%v ver=%d err=%v", items, ver, err)
	}

	ver2, err := m.Set(ctx, owner, contact, "Bob", []string{"Friends"})
	if err != nil || ver2 == 0 {
		t.Fatalf("set: ver=%d err=%v", ver2, err)
	}

	items, _, err = m.Get(ctx, owner)
	if err != nil || len(items) != 1 {
		t.Fatalf("get after set: %v %v", items, err)
	}
	if items[0].Name != "Bob" {
		t.Errorf("name: got %q", items[0].Name)
	}

	_, err = m.Remove(ctx, owner, contact)
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	items, _, _ = m.Get(ctx, owner)
	if len(items) != 0 {
		t.Fatalf("expected empty after remove, got %d items", len(items))
	}
}

func TestSubscribeSubscribed(t *testing.T) {
	ctx := context.Background()

	// Two managers sharing the same memstore (different owners).
	stores := memstore.New()
	mAlice := New(stores.Roster, slog.Default())
	mBob := New(stores.Roster, slog.Default())

	alice := "alice@example.com"
	bob := mustParse("bob@example.com")
	aliceJID := mustParse(alice)

	// Alice subscribes to Bob.
	_, err := mAlice.Subscribe(ctx, alice, bob)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	// Verify alice has ask=subscribe.
	items, _, _ := mAlice.Get(ctx, alice)
	if len(items) != 1 || items[0].Ask != askSubscribe {
		t.Fatalf("alice ask not subscribe: %+v", items)
	}

	// Bob approves Alice's subscription (Bob's roster: alice has subscription=from).
	bobOwner := "bob@example.com"
	err = mBob.Subscribed(ctx, bobOwner, aliceJID)
	if err != nil {
		t.Fatalf("subscribed: %v", err)
	}

	// Bob's roster: alice subscription=from.
	items, _, _ = mBob.Get(ctx, bobOwner)
	if len(items) != 1 || items[0].Subscription != subFrom {
		t.Fatalf("bob subscription not from: %+v", items)
	}

	// Now Alice subscribes bob→alice (bob initiates subscribe to alice).
	_, err = mBob.Subscribe(ctx, bobOwner, aliceJID)
	if err != nil {
		t.Fatalf("bob subscribe to alice: %v", err)
	}

	// Alice approves.
	err = mAlice.Subscribed(ctx, alice, bob)
	if err != nil {
		t.Fatalf("alice subscribed: %v", err)
	}

	// Alice's roster: bob subscription=from (alice approved bob's sub request).
	items, _, _ = mAlice.Get(ctx, alice)
	if len(items) != 1 || items[0].Subscription != subFrom {
		t.Fatalf("alice sub after subscribed: %+v", items)
	}
}

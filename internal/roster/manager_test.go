package roster

import (
	"context"
	"log/slog"
	"testing"

	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage"
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
	_, err = mBob.Subscribed(ctx, bobOwner, aliceJID)
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
	_, err = mAlice.Subscribed(ctx, alice, bob)
	if err != nil {
		t.Fatalf("alice subscribed: %v", err)
	}

	// Alice's roster: bob subscription=from (alice approved bob's sub request).
	items, _, _ = mAlice.Get(ctx, alice)
	if len(items) != 1 || items[0].Subscription != subFrom {
		t.Fatalf("alice sub after subscribed: %+v", items)
	}
}

func TestSubscriptionMath(t *testing.T) {
	// RFC 6121 §3.1.5 table 1 state transitions.
	ctx := context.Background()
	contact := mustParse("bob@example.com")

	type transition struct {
		startSub  int
		startAsk  int
		op        string
		wantSub   int
		wantAsk   int
	}

	cases := []transition{
		// Subscribe (outbound)
		{subNone, askNone, "subscribe", subNone, askSubscribe},
		{subFrom, askNone, "subscribe", subFrom, askSubscribe},
		{subTo, askNone, "subscribe", subTo, askSubscribe},
		{subBoth, askNone, "subscribe", subBoth, askSubscribe},

		// Subscribed (outbound: owner approves inbound sub request)
		{subNone, askNone, "subscribed", subFrom, askNone},
		{subTo, askNone, "subscribed", subBoth, askNone},
		{subFrom, askNone, "subscribed", subFrom, askNone},
		{subBoth, askNone, "subscribed", subBoth, askNone},

		// Unsubscribe (outbound)
		{subTo, askNone, "unsubscribe", subNone, askUnsubscribe},
		{subBoth, askNone, "unsubscribe", subFrom, askUnsubscribe},
		{subNone, askNone, "unsubscribe", subNone, askUnsubscribe},
		{subFrom, askNone, "unsubscribe", subFrom, askUnsubscribe},

		// Unsubscribed (outbound: owner cancels contact's sub)
		{subFrom, askNone, "unsubscribed", subNone, askNone},
		{subBoth, askNone, "unsubscribed", subTo, askNone},
		{subNone, askNone, "unsubscribed", subNone, askNone},
		{subTo, askNone, "unsubscribed", subTo, askNone},

		// InboundSubscribed
		{subNone, askSubscribe, "inbound-subscribed", subTo, askNone},
		{subFrom, askSubscribe, "inbound-subscribed", subBoth, askNone},

		// InboundUnsubscribed
		{subTo, askNone, "inbound-unsubscribed", subNone, askNone},
		{subBoth, askNone, "inbound-unsubscribed", subFrom, askNone},
	}

	for _, tc := range cases {
		t.Run(tc.op, func(t *testing.T) {
			s := memstore.New()
			m := New(s.Roster, slog.Default())
			owner := "alice@example.com"

			seed := &storage.RosterItem{
				Owner:        owner,
				Contact:      contact.String(),
				Subscription: tc.startSub,
				Ask:          tc.startAsk,
			}
			if _, err := s.Roster.Put(ctx, seed); err != nil {
				t.Fatal(err)
			}

			var item *storage.RosterItem
			var err error
			switch tc.op {
			case "subscribe":
				item, err = m.Subscribe(ctx, owner, contact)
			case "subscribed":
				item, err = m.Subscribed(ctx, owner, contact)
			case "unsubscribe":
				item, err = m.Unsubscribe(ctx, owner, contact)
			case "unsubscribed":
				item, err = m.Unsubscribed(ctx, owner, contact)
			case "inbound-subscribed":
				item, err = m.InboundSubscribed(ctx, owner, contact)
			case "inbound-unsubscribed":
				item, err = m.InboundUnsubscribed(ctx, owner, contact)
			}
			if err != nil {
				t.Fatalf("%s: err %v", tc.op, err)
			}
			if item == nil {
				items, _, _ := m.Get(ctx, owner)
				if len(items) > 0 {
					item = items[0]
				}
			}
			if item == nil {
				if tc.wantSub == subNone && tc.wantAsk == askNone {
					return
				}
				t.Fatalf("nil item, want sub=%d ask=%d", tc.wantSub, tc.wantAsk)
			}
			if item.Subscription != tc.wantSub || item.Ask != tc.wantAsk {
				t.Errorf("start sub=%d ask=%d op=%s → got sub=%d ask=%d, want sub=%d ask=%d",
					tc.startSub, tc.startAsk, tc.op, item.Subscription, item.Ask, tc.wantSub, tc.wantAsk)
			}
		})
	}
}

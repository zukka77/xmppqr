package presence

import (
	"context"
	"log/slog"
	"testing"

	"github.com/danielinux/xmppqr/internal/roster"
	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage"
	"github.com/danielinux/xmppqr/internal/storage/memstore"
)

type mockSess struct {
	jid      stanza.JID
	received [][]byte
}

func (m *mockSess) JID() stanza.JID                             { return m.jid }
func (m *mockSess) Priority() int                               { return 0 }
func (m *mockSess) IsAvailable() bool                           { return true }
func (m *mockSess) Deliver(_ context.Context, raw []byte) error { m.received = append(m.received, raw); return nil }

func mustParseJID(s string) stanza.JID {
	j, err := stanza.Parse(s)
	if err != nil {
		panic(err)
	}
	return j
}

func setup(t *testing.T) (*Broadcaster, *router.Router, *roster.Manager, *mockSess, []*mockSess) {
	t.Helper()
	stores := memstore.New()
	rm := roster.New(stores.Roster, slog.Default())
	r := router.New()

	owner := "alice@example.com/res"
	ownerSess := &mockSess{jid: mustParseJID(owner)}

	ctx := context.Background()

	// contact1: subscription=both (3)
	contact1JID := mustParseJID("bob@example.com")
	contact1Sess := &mockSess{jid: mustParseJID("bob@example.com/phone")}
	stores.Roster.Put(ctx, &storage.RosterItem{
		Owner: "alice@example.com", Contact: "bob@example.com", Subscription: 3,
	})
	r.Register(contact1Sess)

	// contact2: subscription=from (1)
	contact2JID := mustParseJID("carol@example.com")
	contact2Sess := &mockSess{jid: mustParseJID("carol@example.com/pc")}
	stores.Roster.Put(ctx, &storage.RosterItem{
		Owner: "alice@example.com", Contact: "carol@example.com", Subscription: 1,
	})
	r.Register(contact2Sess)

	// contact3: subscription=to (2) — should NOT receive presence
	stores.Roster.Put(ctx, &storage.RosterItem{
		Owner: "alice@example.com", Contact: "dave@example.com", Subscription: 2,
	})
	_ = contact1JID
	_ = contact2JID

	b := New(r, rm, slog.Default())
	return b, r, rm, ownerSess, []*mockSess{contact1Sess, contact2Sess}
}

func TestOnInitialPresence(t *testing.T) {
	b, _, _, ownerSess, contacts := setup(t)
	raw := []byte("<presence from='alice@example.com/res'/>")
	if err := b.OnInitialPresence(context.Background(), ownerSess, raw); err != nil {
		t.Fatalf("OnInitialPresence: %v", err)
	}
	for i, c := range contacts {
		if len(c.received) != 1 {
			t.Errorf("contact %d: expected 1 delivery, got %d", i, len(c.received))
		}
	}
}

func TestOnUnavailablePresence(t *testing.T) {
	b, _, _, ownerSess, contacts := setup(t)
	raw := []byte("<presence from='alice@example.com/res' type='unavailable'/>")
	if err := b.OnUnavailablePresence(context.Background(), ownerSess, raw); err != nil {
		t.Fatalf("OnUnavailablePresence: %v", err)
	}
	for i, c := range contacts {
		if len(c.received) != 1 {
			t.Errorf("contact %d: expected 1 delivery, got %d", i, len(c.received))
		}
	}
}

func TestOnDirectedPresence(t *testing.T) {
	b, r, _, ownerSess, _ := setup(t)
	target := &mockSess{jid: mustParseJID("zoe@example.com/pc")}
	r.Register(target)

	raw := []byte("<presence from='alice@example.com/res' to='zoe@example.com/pc'/>")
	to := mustParseJID("zoe@example.com/pc")
	if err := b.OnDirectedPresence(context.Background(), ownerSess, to, raw); err != nil {
		t.Fatalf("OnDirectedPresence: %v", err)
	}
	if len(target.received) != 1 {
		t.Errorf("directed target: expected 1, got %d", len(target.received))
	}
}

package carbons

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/stanza"
)

type mockSession struct {
	jid   stanza.JID
	queue chan []byte
}

func newMock(jidStr string) *mockSession {
	j, err := stanza.Parse(jidStr)
	if err != nil {
		panic(err)
	}
	return &mockSession{jid: j, queue: make(chan []byte, 16)}
}

func (m *mockSession) JID() stanza.JID                           { return m.jid }
func (m *mockSession) Priority() int                             { return 0 }
func (m *mockSession) IsAvailable() bool                         { return true }
func (m *mockSession) Deliver(_ context.Context, raw []byte) error {
	select {
	case m.queue <- raw:
		return nil
	default:
		return router.ErrBackpressure
	}
}

func newTestManager() (*Manager, *router.Router) {
	r := router.New()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return New(r, logger), r
}

func mustJID(s string) stanza.JID {
	j, err := stanza.Parse(s)
	if err != nil {
		panic(err)
	}
	return j
}

func TestDeliverCarbons_ReceivedDirection(t *testing.T) {
	mgr, r := newTestManager()

	sA := newMock("alice@example.com/phone")
	sB := newMock("alice@example.com/tablet")
	r.Register(sA)
	r.Register(sB)

	mgr.EnableForSession(sA.jid)
	mgr.EnableForSession(sB.jid)

	original := []byte(`<message from="bob@example.com" to="alice@example.com/phone"><body>hi</body></message>`)
	ownerBare := mustJID("alice@example.com")
	recipient := mustJID("alice@example.com/phone")
	allRes := []stanza.JID{sA.jid, sB.jid}

	delivered := mgr.DeliverCarbons(context.Background(), ownerBare, recipient, original, 0, allRes)
	if delivered != 1 {
		t.Fatalf("expected 1 delivered, got %d", delivered)
	}

	// sA is the original recipient; only sB should get the carbon.
	select {
	case got := <-sB.queue:
		s := string(got)
		if !strings.Contains(s, "received") {
			t.Fatalf("expected <received> carbon, got: %s", s)
		}
		if !strings.Contains(s, "alice@example.com/tablet") {
			t.Fatalf("carbon should be addressed to tablet: %s", s)
		}
	default:
		t.Fatal("sB did not receive carbon")
	}

	select {
	case <-sA.queue:
		t.Fatal("original recipient sA should not receive carbon")
	default:
	}
}

func TestDeliverCarbons_SentDirection(t *testing.T) {
	mgr, r := newTestManager()

	sA := newMock("alice@example.com/phone")
	sB := newMock("alice@example.com/tablet")
	r.Register(sA)
	r.Register(sB)

	mgr.EnableForSession(sA.jid)
	mgr.EnableForSession(sB.jid)

	original := []byte(`<message from="alice@example.com/phone" to="bob@example.com"><body>hello</body></message>`)
	ownerBare := mustJID("alice@example.com")
	// For sent, the originalRecipient is the sender's full JID (the one that sent it).
	sender := mustJID("alice@example.com/phone")
	allRes := []stanza.JID{sA.jid, sB.jid}

	delivered := mgr.DeliverCarbons(context.Background(), ownerBare, sender, original, 1, allRes)
	if delivered != 1 {
		t.Fatalf("expected 1 delivered, got %d", delivered)
	}

	select {
	case got := <-sB.queue:
		s := string(got)
		if !strings.Contains(s, "sent") {
			t.Fatalf("expected <sent> carbon, got: %s", s)
		}
	default:
		t.Fatal("sB did not receive sent carbon")
	}

	select {
	case <-sA.queue:
		t.Fatal("sender sA should not receive sent carbon")
	default:
	}
}

func TestDeliverCarbons_NoCopyHint(t *testing.T) {
	mgr, r := newTestManager()

	sA := newMock("alice@example.com/phone")
	sB := newMock("alice@example.com/tablet")
	r.Register(sA)
	r.Register(sB)

	mgr.EnableForSession(sA.jid)
	mgr.EnableForSession(sB.jid)

	original := []byte(`<message from="bob@example.com" to="alice@example.com/phone"><body>secret</body><no-copy xmlns='urn:xmpp:hints'/></message>`)
	ownerBare := mustJID("alice@example.com")
	recipient := mustJID("alice@example.com/phone")
	allRes := []stanza.JID{sA.jid, sB.jid}

	delivered := mgr.DeliverCarbons(context.Background(), ownerBare, recipient, original, 0, allRes)
	if delivered != 0 {
		t.Fatalf("no-copy: expected 0 delivered, got %d", delivered)
	}

	select {
	case <-sB.queue:
		t.Fatal("no-copy hint should suppress carbons")
	default:
	}
}

func TestDeliverCarbons_PrivateHint(t *testing.T) {
	mgr, r := newTestManager()

	sA := newMock("alice@example.com/phone")
	sB := newMock("alice@example.com/tablet")
	r.Register(sA)
	r.Register(sB)

	mgr.EnableForSession(sA.jid)
	mgr.EnableForSession(sB.jid)

	original := []byte(`<message from="bob@example.com" to="alice@example.com/phone"><body>private</body><private xmlns='urn:xmpp:carbons:2'/></message>`)
	ownerBare := mustJID("alice@example.com")
	recipient := mustJID("alice@example.com/phone")
	allRes := []stanza.JID{sA.jid, sB.jid}

	delivered := mgr.DeliverCarbons(context.Background(), ownerBare, recipient, original, 0, allRes)
	if delivered != 0 {
		t.Fatalf("private: expected 0 delivered, got %d", delivered)
	}
}

func TestDeliverCarbons_OnlyOtherResource(t *testing.T) {
	mgr, r := newTestManager()

	sA := newMock("alice@example.com/phone")
	sB := newMock("alice@example.com/tablet")
	sC := newMock("alice@example.com/desktop")
	r.Register(sA)
	r.Register(sB)
	r.Register(sC)

	mgr.EnableForSession(sA.jid)
	mgr.EnableForSession(sB.jid)
	// sC not enabled

	original := []byte(`<message from="bob@example.com" to="alice@example.com/phone"><body>hey</body></message>`)
	ownerBare := mustJID("alice@example.com")
	recipient := mustJID("alice@example.com/phone")
	allRes := []stanza.JID{sA.jid, sB.jid, sC.jid}

	delivered := mgr.DeliverCarbons(context.Background(), ownerBare, recipient, original, 0, allRes)
	if delivered != 1 {
		t.Fatalf("expected 1 (only enabled non-recipient), got %d", delivered)
	}

	select {
	case <-sC.queue:
		t.Fatal("disabled session sC should not receive carbon")
	default:
	}
}

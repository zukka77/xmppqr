package muc

import (
	"context"
	"encoding/xml"
	"strings"
	"sync"
	"testing"

	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/stanza"
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
	svc := New("example.com", "conference", stores.MUC, r, nil)
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

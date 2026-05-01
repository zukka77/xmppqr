package pep

import (
	"bytes"
	"context"
	"encoding/xml"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/danielinux/xmppqr/internal/pubsub"
	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage/memstore"
)

type mockSession struct {
	jid      stanza.JID
	mu       sync.Mutex
	received [][]byte
}

func (m *mockSession) JID() stanza.JID      { return m.jid }
func (m *mockSession) Priority() int        { return 0 }
func (m *mockSession) IsAvailable() bool    { return true }
func (m *mockSession) Deliver(_ context.Context, raw []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(raw))
	copy(cp, raw)
	m.received = append(m.received, cp)
	return nil
}

func (m *mockSession) deliveries() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]byte, len(m.received))
	copy(out, m.received)
	return out
}

func newTestPEP(t *testing.T) (*Service, *mockSession) {
	t.Helper()
	stores := memstore.New()
	r := router.New()

	aliceJID, _ := stanza.Parse("alice@example.com/work")
	sess := &mockSession{jid: aliceJID}
	r.Register(sess)

	logger := slog.Default()
	ps := pubsub.New(stores.PEP, r, logger, 0)
	svc := New(ps, logger)
	return svc, sess
}

func buildPEPPublishIQ(node, itemID string, payload []byte) *stanza.IQ {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)

	psEl := xml.StartElement{Name: xml.Name{Space: "http://jabber.org/protocol/pubsub", Local: "pubsub"}}
	pubEl := xml.StartElement{
		Name: xml.Name{Local: "publish"},
		Attr: []xml.Attr{{Name: xml.Name{Local: "node"}, Value: node}},
	}
	itemEl := xml.StartElement{
		Name: xml.Name{Local: "item"},
		Attr: []xml.Attr{{Name: xml.Name{Local: "id"}, Value: itemID}},
	}
	enc.EncodeToken(psEl)
	enc.EncodeToken(pubEl)
	enc.EncodeToken(itemEl)
	enc.Flush()
	if len(payload) > 0 {
		buf.Write(payload)
	}
	enc.EncodeToken(itemEl.End())
	enc.EncodeToken(pubEl.End())
	enc.EncodeToken(psEl.End())
	enc.Flush()

	return &stanza.IQ{
		ID:      "pep1",
		From:    "alice@example.com/work",
		To:      "alice@example.com",
		Type:    stanza.IQSet,
		Payload: buf.Bytes(),
	}
}

func TestPEPAutoCreateAndNotify(t *testing.T) {
	svc, sess := newTestPEP(t)
	ctx := context.Background()
	from, _ := stanza.Parse("alice@example.com/work")
	node := "urn:xmppqr:x3dhpq:bundle:0"

	iq := buildPEPPublishIQ(node, "bundle1", []byte("<bundle/>"))
	raw, err := svc.HandleIQ(ctx, from, iq)
	if err != nil {
		t.Fatalf("HandleIQ: %v", err)
	}
	if !bytes.Contains(raw, []byte(`type="result"`)) {
		t.Fatalf("expected result IQ, got: %s", raw)
	}

	// Notify is async; wait up to 200ms.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) && len(sess.deliveries()) == 0 {
		time.Sleep(5 * time.Millisecond)
	}

	deliveries := sess.deliveries()
	if len(deliveries) == 0 {
		t.Fatal("expected notify delivery, got none")
	}
	if !bytes.Contains(deliveries[0], []byte("bundle1")) {
		t.Errorf("notify missing item id: %s", deliveries[0])
	}
}

func TestOMEMODevicelistRoundTrip(t *testing.T) {
	svc, _ := newTestPEP(t)
	ctx := context.Background()
	from, _ := stanza.Parse("alice@example.com/work")
	node := "eu.siacs.conversations.axolotl.devicelist"

	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte('a' + i%26)
	}
	wrappedPayload := append([]byte("<list xmlns='eu.siacs.conversations.axolotl'>"), payload...)
	wrappedPayload = append(wrappedPayload, []byte("</list>")...)

	iq := buildPEPPublishIQ(node, "current", wrappedPayload)
	raw, err := svc.HandleIQ(ctx, from, iq)
	if err != nil {
		t.Fatalf("publish HandleIQ: %v", err)
	}
	if !bytes.Contains(raw, []byte(`type="result"`)) {
		t.Fatalf("expected result IQ, got: %s", raw)
	}

	fetchIQ := &stanza.IQ{
		ID:   "fetch1",
		From: "alice@example.com/work",
		To:   "alice@example.com",
		Type: stanza.IQGet,
	}
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)
	psEl := xml.StartElement{Name: xml.Name{Space: "http://jabber.org/protocol/pubsub", Local: "pubsub"}}
	itemsEl := xml.StartElement{
		Name: xml.Name{Local: "items"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "node"}, Value: node},
			{Name: xml.Name{Local: "max_items"}, Value: "1"},
		},
	}
	enc.EncodeToken(psEl)
	enc.EncodeToken(itemsEl)
	enc.EncodeToken(itemsEl.End())
	enc.EncodeToken(psEl.End())
	enc.Flush()
	fetchIQ.Payload = buf.Bytes()

	raw, err = svc.HandleIQ(ctx, from, fetchIQ)
	if err != nil {
		t.Fatalf("fetch HandleIQ: %v", err)
	}
	if !bytes.Contains(raw, []byte(`id="current"`)) {
		t.Fatalf("expected item id=current in response, got: %s", raw)
	}
	if !bytes.Contains(raw, []byte("eu.siacs.conversations.axolotl.devicelist")) {
		t.Fatalf("expected node name in response, got: %s", raw)
	}
}

func TestPEPForbiddenWrongTo(t *testing.T) {
	svc, _ := newTestPEP(t)
	ctx := context.Background()
	from, _ := stanza.Parse("alice@example.com/work")

	iq := buildPEPPublishIQ("urn:test:node", "i1", []byte("<x/>"))
	iq.To = "bob@example.com"

	raw, err := svc.HandleIQ(ctx, from, iq)
	if err != nil {
		t.Fatalf("HandleIQ: %v", err)
	}
	if !bytes.Contains(raw, []byte("forbidden")) {
		t.Fatalf("expected forbidden, got: %s", raw)
	}
	if !bytes.Contains(raw, []byte(`type="error"`)) {
		t.Fatalf("expected error IQ, got: %s", raw)
	}
}

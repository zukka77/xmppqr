package pubsub

import (
	"bytes"
	"context"
	"encoding/xml"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage/memstore"
)

type mockSession struct {
	jid      stanza.JID
	mu       sync.Mutex
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

func (m *mockSession) deliveries() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]byte, len(m.received))
	copy(out, m.received)
	return out
}

func newTestService(t *testing.T) (*Service, *router.Router, *mockSession) {
	t.Helper()
	stores := memstore.New()
	r := router.New()
	jid, _ := stanza.Parse("alice@example.com/res")
	sess := &mockSession{jid: jid}
	r.Register(sess)

	logger := slog.Default()
	svc := New(stores.PEP, r, logger, 1024)
	return svc, r, sess
}

func buildPublishIQ(node string, items []rawItem) *stanza.IQ {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)

	psEl := xml.StartElement{Name: xml.Name{Space: nsPubSub, Local: "pubsub"}}
	pubEl := xml.StartElement{
		Name: xml.Name{Local: "publish"},
		Attr: []xml.Attr{{Name: xml.Name{Local: "node"}, Value: node}},
	}
	enc.EncodeToken(psEl)
	enc.EncodeToken(pubEl)
	for _, it := range items {
		itemEl := xml.StartElement{
			Name: xml.Name{Local: "item"},
			Attr: []xml.Attr{{Name: xml.Name{Local: "id"}, Value: it.ID}},
		}
		enc.EncodeToken(itemEl)
		enc.Flush()
		if len(it.Payload) > 0 {
			buf.Write(it.Payload)
		}
		enc.EncodeToken(itemEl.End())
	}
	enc.EncodeToken(pubEl.End())
	enc.EncodeToken(psEl.End())
	enc.Flush()

	return &stanza.IQ{
		ID:      "pub1",
		From:    "alice@example.com/res",
		To:      "alice@example.com",
		Type:    stanza.IQSet,
		Payload: buf.Bytes(),
	}
}

func buildItemsIQ(node string) *stanza.IQ {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)
	psEl := xml.StartElement{Name: xml.Name{Space: nsPubSub, Local: "pubsub"}}
	itemsEl := xml.StartElement{
		Name: xml.Name{Local: "items"},
		Attr: []xml.Attr{{Name: xml.Name{Local: "node"}, Value: node}},
	}
	enc.EncodeToken(psEl)
	enc.EncodeToken(itemsEl)
	enc.EncodeToken(itemsEl.End())
	enc.EncodeToken(psEl.End())
	enc.Flush()

	return &stanza.IQ{
		ID:      "items1",
		From:    "alice@example.com/res",
		To:      "alice@example.com",
		Type:    stanza.IQGet,
		Payload: buf.Bytes(),
	}
}

func buildRetractIQ(node, itemID string) *stanza.IQ {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)
	psEl := xml.StartElement{Name: xml.Name{Space: nsPubSub, Local: "pubsub"}}
	retEl := xml.StartElement{
		Name: xml.Name{Local: "retract"},
		Attr: []xml.Attr{{Name: xml.Name{Local: "node"}, Value: node}},
	}
	itemEl := xml.StartElement{
		Name: xml.Name{Local: "item"},
		Attr: []xml.Attr{{Name: xml.Name{Local: "id"}, Value: itemID}},
	}
	enc.EncodeToken(psEl)
	enc.EncodeToken(retEl)
	enc.EncodeToken(itemEl)
	enc.EncodeToken(itemEl.End())
	enc.EncodeToken(retEl.End())
	enc.EncodeToken(psEl.End())
	enc.Flush()

	return &stanza.IQ{
		ID:      "ret1",
		From:    "alice@example.com/res",
		To:      "alice@example.com",
		Type:    stanza.IQSet,
		Payload: buf.Bytes(),
	}
}

func TestPublishItemsRoundtrip(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	owner, _ := stanza.Parse("alice@example.com/res")
	node := "urn:test:node"

	items := []rawItem{
		{ID: "item1", Payload: []byte("<val>1</val>")},
		{ID: "item2", Payload: []byte("<val>2</val>")},
		{ID: "item3", Payload: []byte("<val>3</val>")},
	}

	pubIQ := buildPublishIQ(node, items)
	raw, err := svc.HandleIQ(ctx, owner, pubIQ)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if !bytes.Contains(raw, []byte(`type="result"`)) {
		t.Fatalf("expected result IQ, got: %s", raw)
	}

	listIQ := buildItemsIQ(node)
	raw, err = svc.HandleIQ(ctx, owner, listIQ)
	if err != nil {
		t.Fatalf("items: %v", err)
	}
	for _, id := range []string{"item1", "item2", "item3"} {
		if !bytes.Contains(raw, []byte(id)) {
			t.Errorf("items response missing %s: %s", id, raw)
		}
	}
}

func TestItemSizeCapViolation(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	owner, _ := stanza.Parse("alice@example.com/res")
	node := "urn:test:node"

	bigPayload := make([]byte, 2048)
	for i := range bigPayload {
		bigPayload[i] = 'x'
	}

	items := []rawItem{{ID: "big", Payload: bigPayload}}
	pubIQ := buildPublishIQ(node, items)
	raw, err := svc.HandleIQ(ctx, owner, pubIQ)
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if !bytes.Contains(raw, []byte("policy-violation")) {
		t.Fatalf("expected policy-violation, got: %s", raw)
	}
}

func TestRetractRemovesItem(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	owner, _ := stanza.Parse("alice@example.com/res")
	node := "urn:test:node"

	items := []rawItem{{ID: "del-me", Payload: []byte("<v/>")}}
	pubIQ := buildPublishIQ(node, items)
	if _, err := svc.HandleIQ(ctx, owner, pubIQ); err != nil {
		t.Fatalf("publish: %v", err)
	}

	retIQ := buildRetractIQ(node, "del-me")
	raw, err := svc.HandleIQ(ctx, owner, retIQ)
	if err != nil {
		t.Fatalf("retract: %v", err)
	}
	if !bytes.Contains(raw, []byte(`type="result"`)) {
		t.Fatalf("expected result, got: %s", raw)
	}

	listIQ := buildItemsIQ(node)
	raw, err = svc.HandleIQ(ctx, owner, listIQ)
	if err != nil {
		t.Fatalf("items: %v", err)
	}
	if bytes.Contains(raw, []byte("del-me")) {
		t.Fatalf("item still present after retract: %s", raw)
	}
}

func TestNotifyDispatched(t *testing.T) {
	svc, _, sess := newTestService(t)
	ctx := context.Background()
	owner, _ := stanza.Parse("alice@example.com/res")
	node := "urn:test:notify"

	items := []rawItem{{ID: "n1", Payload: []byte("<data/>")}}
	pubIQ := buildPublishIQ(node, items)
	if _, err := svc.HandleIQ(ctx, owner, pubIQ); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// Wait briefly for the notify goroutine to deliver.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) && len(sess.deliveries()) == 0 {
		time.Sleep(5 * time.Millisecond)
	}

	deliveries := sess.deliveries()
	if len(deliveries) == 0 {
		t.Fatal("expected notify delivery, got none")
	}
	if !bytes.Contains(deliveries[0], []byte("n1")) {
		t.Errorf("notify missing item id: %s", deliveries[0])
	}
}


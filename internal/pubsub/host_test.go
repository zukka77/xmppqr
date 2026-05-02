package pubsub

import (
	"bytes"
	"context"
	"encoding/xml"
	"log/slog"
	"testing"
	"time"

	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage/memstore"
)

// stubHostAuth is a HostAuth whose allow/deny decision is controlled per-test.
type stubHostAuth struct {
	allowPublish   bool
	allowSubscribe bool
}

func (s *stubHostAuth) CanPublish(_ stanza.JID, _ string, _ stanza.JID) bool   { return s.allowPublish }
func (s *stubHostAuth) CanSubscribe(_ stanza.JID, _ string, _ stanza.JID) bool { return s.allowSubscribe }

func newHostTestService(t *testing.T, auth HostAuth) (*HostService, *router.Router, *mockSession) {
	t.Helper()
	stores := memstore.New()
	r := router.New()
	jid, _ := stanza.Parse("alice@example.com/res")
	sess := &mockSession{jid: jid}
	r.Register(sess)
	inner := New(stores.PEP, r, slog.Default(), 1024)
	hs := NewHostService(inner, auth)
	return hs, r, sess
}

func buildHostPublishIQ(host, from, node string, items []rawItem) *stanza.IQ {
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
		ID:      "pub-host",
		From:    from,
		To:      host,
		Type:    stanza.IQSet,
		Payload: buf.Bytes(),
	}
}

func buildHostSubscribeIQ(host, from, node string) *stanza.IQ {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)
	psEl := xml.StartElement{Name: xml.Name{Space: nsPubSub, Local: "pubsub"}}
	subEl := xml.StartElement{
		Name: xml.Name{Local: "subscribe"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "node"}, Value: node},
			{Name: xml.Name{Local: "jid"}, Value: from},
		},
	}
	enc.EncodeToken(psEl)
	enc.EncodeToken(subEl)
	enc.EncodeToken(subEl.End())
	enc.EncodeToken(psEl.End())
	enc.Flush()
	return &stanza.IQ{
		ID:      "sub-host",
		From:    from,
		To:      host,
		Type:    stanza.IQSet,
		Payload: buf.Bytes(),
	}
}

func TestHostServiceAuthRejectsPublish(t *testing.T) {
	hs, _, _ := newHostTestService(t, &stubHostAuth{allowPublish: false, allowSubscribe: true})
	ctx := context.Background()

	host, _ := stanza.Parse("room@conference.example.com")
	requester, _ := stanza.Parse("alice@example.com/res")
	iq := buildHostPublishIQ(host.String(), requester.String(), "urn:test:node", []rawItem{{ID: "i1", Payload: []byte("<x/>")}})

	raw, err := hs.HandleIQ(ctx, host, requester, iq)
	if err != nil {
		t.Fatalf("HandleIQ error: %v", err)
	}
	if !bytes.Contains(raw, []byte("forbidden")) {
		t.Errorf("expected forbidden error, got: %s", raw)
	}
}

func TestHostServiceAuthRejectsSubscribe(t *testing.T) {
	hs, _, _ := newHostTestService(t, &stubHostAuth{allowPublish: true, allowSubscribe: false})
	ctx := context.Background()

	host, _ := stanza.Parse("room@conference.example.com")
	requester, _ := stanza.Parse("alice@example.com/res")
	iq := buildHostSubscribeIQ(host.String(), requester.String(), "urn:test:node")

	raw, err := hs.HandleIQ(ctx, host, requester, iq)
	if err != nil {
		t.Fatalf("HandleIQ error: %v", err)
	}
	if !bytes.Contains(raw, []byte("forbidden")) {
		t.Errorf("expected forbidden error, got: %s", raw)
	}
}

func TestHostServicePublishToMUCJIDStores(t *testing.T) {
	stores := memstore.New()
	r := router.New()
	inner := New(stores.PEP, r, slog.Default(), 1024)
	hs := NewHostService(inner, &stubHostAuth{allowPublish: true, allowSubscribe: true})

	ctx := context.Background()
	host, _ := stanza.Parse("room@conference.example.com")
	requester, _ := stanza.Parse("alice@example.com/res")
	node := "urn:xmppqr:x3dhpq:group:0"

	iq := buildHostPublishIQ(host.String(), requester.String(), node, []rawItem{{ID: "entry-1", Payload: []byte("<membership-entry/>>")}})
	raw, err := hs.HandleIQ(ctx, host, requester, iq)
	if err != nil {
		t.Fatalf("HandleIQ error: %v", err)
	}
	if !bytes.Contains(raw, []byte(`type="result"`)) {
		t.Fatalf("expected result, got: %s", raw)
	}

	// Verify the item is stored under the MUC room JID as owner.
	it, err := stores.PEP.GetItem(ctx, host.Bare().String(), node, "entry-1")
	if err != nil {
		t.Fatalf("GetItem: %v", err)
	}
	if it.Owner != host.Bare().String() {
		t.Errorf("expected owner=%q, got %q", host.Bare().String(), it.Owner)
	}
}

func TestLastItemReplayOnSubscribe(t *testing.T) {
	stores := memstore.New()
	r := router.New()

	// Subscriber session.
	subscriberJID, _ := stanza.Parse("bob@example.com/phone")
	bobSess := &mockSession{jid: subscriberJID}
	r.Register(bobSess)

	inner := New(stores.PEP, r, slog.Default(), 1024)
	hs := NewHostService(inner, &stubHostAuth{allowPublish: true, allowSubscribe: true})

	ctx := context.Background()
	host, _ := stanza.Parse("room@conference.example.com")
	publisher, _ := stanza.Parse("alice@example.com/res")
	node := "urn:test:replay"

	// Publish one item as the host-owning node.
	pubIQ := buildHostPublishIQ(host.String(), publisher.String(), node, []rawItem{{ID: "item-1", Payload: []byte("<data>hello</data>")}})
	if _, err := hs.HandleIQ(ctx, host, publisher, pubIQ); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// Now subscribe bob.
	subIQ := buildHostSubscribeIQ(host.String(), subscriberJID.String(), node)
	raw, err := hs.HandleIQ(ctx, host, subscriberJID, subIQ)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if !bytes.Contains(raw, []byte(`type="result"`)) {
		t.Fatalf("expected subscribe result, got: %s", raw)
	}

	// Last-item replay is async; wait briefly.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(bobSess.deliveries()) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if len(bobSess.deliveries()) == 0 {
		t.Fatal("expected last-item replay delivery to bob, got none")
	}
	if !bytes.Contains(bobSess.deliveries()[0], []byte("item-1")) {
		t.Errorf("replay missing item id: %s", bobSess.deliveries()[0])
	}
	if !bytes.Contains(bobSess.deliveries()[0], []byte("hello")) {
		t.Errorf("replay missing payload: %s", bobSess.deliveries()[0])
	}
}

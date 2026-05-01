//go:build integ

package integ_test

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"testing"
	"time"
)

func publishPEPItem(c *Client, node, itemID, payloadXML string) error {
	iq := fmt.Sprintf(`<iq type='set' id='pub-%s'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='%s'><item id='%s'>%s</item></publish></pubsub></iq>`,
		itemID, node, itemID, payloadXML)
	return c.Send([]byte(iq))
}

func waitForIQResult(t *testing.T, c *Client, id string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		start, raw, err := c.NextStanzaWithTimeout(500 * time.Millisecond)
		if err == ErrTimeout {
			continue
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if start.Name.Local != "iq" {
			continue
		}
		pubID := "pub-" + id
		if !bytes.Contains(raw, []byte(pubID)) {
			continue
		}
		for _, a := range start.Attr {
			if a.Name.Local == "type" {
				if a.Value == "error" {
					t.Fatalf("got error iq: %s", raw)
				}
				return
			}
		}
	}
	t.Fatal("timed out waiting for IQ result")
}

func TestDiscoAdvertisesX3DHPQFeatures(t *testing.T) {
	h := NewHarness(t)
	defer h.Close()
	h.AddUser(t, "alice", "pw")

	a := MustDial(t, h.TLSAddr(), h.Domain, "alice", "pw")
	defer a.Close()

	discoIQ := fmt.Sprintf(`<iq id='disco1' type='get' to='%s'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>`, h.Domain)
	if err := a.Send([]byte(discoIQ)); err != nil {
		t.Fatalf("send disco#info: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	_, raw := waitForStanza(t, a, deadline, func(se xml.StartElement, raw []byte) bool {
		return se.Name.Local == "iq" && bytes.Contains(raw, []byte("disco#info"))
	})

	want := []string{
		"urn:xmppqr:x3dhpq:0",
		"urn:xmppqr:x3dhpq:devicelist:0+notify",
		"urn:xmppqr:x3dhpq:audit:0+notify",
	}
	for _, f := range want {
		if !bytes.Contains(raw, []byte(f)) {
			t.Errorf("disco#info missing feature %q; response: %s", f, raw)
		}
	}
}

func TestPairStanzaRoutedFullJIDToFullJID(t *testing.T) {
	h := NewHarness(t)
	defer h.Close()
	h.AddUser(t, "alice", "pw")

	a1 := MustDial(t, h.TLSAddr(), h.Domain, "alice", "pw")
	defer a1.Close()
	a2 := MustDial(t, h.TLSAddr(), h.Domain, "alice", "pw")
	defer a2.Close()

	if err := a1.Send([]byte(`<presence/>`)); err != nil {
		t.Fatalf("a1 presence: %v", err)
	}
	if err := a2.Send([]byte(`<presence/>`)); err != nil {
		t.Fatalf("a2 presence: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	pairMsg := fmt.Sprintf(
		`<message to='%s'><pair xmlns='urn:xmppqr:x3dhpq:pair:0' type='1'>OPAQUE</pair></message>`,
		a2.JID().String(),
	)
	if err := a1.Send([]byte(pairMsg)); err != nil {
		t.Fatalf("send pair message: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	waitForStanza(t, a2, deadline, func(se xml.StartElement, raw []byte) bool {
		return se.Name.Local == "message" &&
			bytes.Contains(raw, []byte("urn:xmppqr:x3dhpq:pair:0")) &&
			bytes.Contains(raw, []byte("OPAQUE"))
	})
}

func TestDeviceListPublishAndFetch(t *testing.T) {
	h := NewHarness(t)
	defer h.Close()
	h.AddUser(t, "alice", "pw")

	a := MustDial(t, h.TLSAddr(), h.Domain, "alice", "pw")
	defer a.Close()

	node := "urn:xmppqr:x3dhpq:devicelist:0"
	payload := "<list>device-1</list>"
	if err := publishPEPItem(a, node, "current", payload); err != nil {
		t.Fatalf("publish: %v", err)
	}
	waitForIQResult(t, a, "current")

	fetchIQ := fmt.Sprintf(
		`<iq id='fetch1' type='get'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='%s' max_items='1'/></pubsub></iq>`,
		node,
	)
	if err := a.Send([]byte(fetchIQ)); err != nil {
		t.Fatalf("send items fetch: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	_, raw := waitForStanza(t, a, deadline, func(se xml.StartElement, raw []byte) bool {
		return se.Name.Local == "iq" && bytes.Contains(raw, []byte("fetch1"))
	})

	if !bytes.Contains(raw, []byte("device-1")) {
		t.Fatalf("fetch response missing payload; got: %s", raw)
	}
}

func TestDeviceListNotifyToOwnerResources(t *testing.T) {
	h := NewHarness(t)
	defer h.Close()
	h.AddUser(t, "alice", "pw")

	a1 := MustDial(t, h.TLSAddr(), h.Domain, "alice", "pw")
	defer a1.Close()
	a2 := MustDial(t, h.TLSAddr(), h.Domain, "alice", "pw")
	defer a2.Close()

	if err := a1.Send([]byte(`<presence/>`)); err != nil {
		t.Fatalf("a1 presence: %v", err)
	}
	if err := a2.Send([]byte(`<presence/>`)); err != nil {
		t.Fatalf("a2 presence: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	node := "urn:xmppqr:x3dhpq:devicelist:0"
	if err := publishPEPItem(a1, node, "current", "<list>device-1</list>"); err != nil {
		t.Fatalf("publish: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	waitForStanza(t, a2, deadline, func(se xml.StartElement, raw []byte) bool {
		return se.Name.Local == "message" &&
			bytes.Contains(raw, []byte("pubsub#event")) &&
			bytes.Contains(raw, []byte(node))
	})
}

func TestAuditChainAppend(t *testing.T) {
	h := NewHarness(t)
	defer h.Close()
	h.AddUser(t, "alice", "pw")

	a := MustDial(t, h.TLSAddr(), h.Domain, "alice", "pw")
	defer a.Close()

	node := "urn:xmppqr:x3dhpq:audit:0"
	for _, id := range []string{"1", "2", "3"} {
		payload := fmt.Sprintf("<entry>audit-%s</entry>", id)
		if err := publishPEPItem(a, node, id, payload); err != nil {
			t.Fatalf("publish item %s: %v", id, err)
		}
		waitForIQResult(t, a, id)
	}

	fetchIQ := fmt.Sprintf(
		`<iq id='audit-fetch' type='get'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='%s'/></pubsub></iq>`,
		node,
	)
	if err := a.Send([]byte(fetchIQ)); err != nil {
		t.Fatalf("send fetch: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	_, raw := waitForStanza(t, a, deadline, func(se xml.StartElement, raw []byte) bool {
		return se.Name.Local == "iq" && bytes.Contains(raw, []byte("audit-fetch"))
	})

	for _, id := range []string{"1", "2", "3"} {
		if !bytes.Contains(raw, []byte("audit-"+id)) {
			t.Errorf("fetch response missing audit item %s; got: %s", id, raw)
		}
	}
}

func TestBundleItemSizeCap(t *testing.T) {
	h := NewHarness(t)
	defer h.Close()
	h.AddUser(t, "alice", "pw")

	a := MustDial(t, h.TLSAddr(), h.Domain, "alice", "pw")
	defer a.Close()

	// The harness initialises pubsub with a 64 KiB cap (65536 bytes).
	// A payload under that limit must succeed; one over it must be rejected.
	node := "urn:xmppqr:x3dhpq:bundle:0"

	smallData := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("A"), 100))
	smallPayload := fmt.Sprintf("<opaque>%s</opaque>", smallData)
	if err := publishPEPItem(a, node, "small", smallPayload); err != nil {
		t.Fatalf("publish small: %v", err)
	}
	waitForIQResult(t, a, "small")

	largeData := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("A"), 300<<10))
	largePayload := fmt.Sprintf("<opaque>%s</opaque>", largeData)
	largeIQ := fmt.Sprintf(
		`<iq type='set' id='pub-large'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='%s'><item id='large'>%s</item></publish></pubsub></iq>`,
		node, largePayload,
	)
	if err := a.Send([]byte(largeIQ)); err != nil {
		t.Fatalf("send large: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	_, raw := waitForStanza(t, a, deadline, func(se xml.StartElement, raw []byte) bool {
		return se.Name.Local == "iq" && bytes.Contains(raw, []byte("pub-large"))
	})

	if !bytes.Contains(raw, []byte("policy-violation")) {
		t.Fatalf("expected policy-violation for oversized item; got: %s", raw)
	}
}

func TestMUCAIKExtensionPreservedOnBroadcast(t *testing.T) {
	h := NewHarness(t)
	defer h.Close()
	h.AddUser(t, "alice", "pw")
	h.AddUser(t, "bob", "pw")

	a := MustDial(t, h.TLSAddr(), h.Domain, "alice", "pw")
	defer a.Close()
	b := MustDial(t, h.TLSAddr(), h.Domain, "bob", "pw")
	defer b.Close()

	room := fmt.Sprintf("lab@conference.%s", h.Domain)
	bobFP := "AAAA1 BBBB2 CCCC3"

	joinA := fmt.Sprintf(
		`<presence to='%s/alice'><x xmlns='http://jabber.org/protocol/muc'/><aik xmlns='urn:xmppqr:x3dhpq:group:0' fp='aliceFP'/></presence>`,
		room,
	)
	if err := a.Send([]byte(joinA)); err != nil {
		t.Fatalf("alice join: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	waitForStanza(t, a, deadline, func(se xml.StartElement, raw []byte) bool {
		return se.Name.Local == "presence" && bytes.Contains(raw, []byte("110"))
	})

	joinB := fmt.Sprintf(
		`<presence to='%s/bob'><x xmlns='http://jabber.org/protocol/muc'/><aik xmlns='urn:xmppqr:x3dhpq:group:0' fp='%s'/></presence>`,
		room, bobFP,
	)
	if err := b.Send([]byte(joinB)); err != nil {
		t.Fatalf("bob join: %v", err)
	}
	deadline = time.Now().Add(5 * time.Second)
	waitForStanza(t, b, deadline, func(se xml.StartElement, raw []byte) bool {
		return se.Name.Local == "presence" && bytes.Contains(raw, []byte("110"))
	})

	deadline = time.Now().Add(5 * time.Second)
	_, raw := waitForStanza(t, a, deadline, func(se xml.StartElement, raw []byte) bool {
		return se.Name.Local == "presence" && bytes.Contains(raw, []byte("bob"))
	})

	if !bytes.Contains(raw, []byte("urn:xmppqr:x3dhpq:group:0")) {
		t.Fatalf("bob's join presence missing AIK namespace; got: %s", raw)
	}
	if !bytes.Contains(raw, []byte(bobFP)) {
		t.Fatalf("bob's join presence missing AIK fp %q; got: %s", bobFP, raw)
	}
}

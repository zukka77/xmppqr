//go:build integ

package integ_test

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"testing"
	"time"
)

func MustDial(t *testing.T, addr, domain, username, password string) *Client {
	t.Helper()
	c, err := DialAndAuthDirectTLS(addr, domain, username, password)
	if err != nil {
		t.Fatalf("dial %s as %s: %v", addr, username, err)
	}
	return c
}

func requireAttr(t *testing.T, start xml.StartElement, name, want string) {
	t.Helper()
	for _, a := range start.Attr {
		if a.Name.Local == name {
			if a.Value != want {
				t.Fatalf("<%s> attr %s: got %q, want %q", start.Name.Local, name, a.Value, want)
			}
			return
		}
	}
	t.Fatalf("<%s> missing attr %s (want %q)", start.Name.Local, name, want)
}

func TestSingleSessionRoundtrip(t *testing.T) {
	h := NewHarness(t)
	defer h.Close()
	h.AddUser(t, "alice", "alicepw")

	c := MustDial(t, h.TLSAddr(), h.Domain, "alice", "alicepw")
	defer c.Close()

	if err := c.Send([]byte(`<iq id='1' type='get'><ping xmlns='urn:xmpp:ping'/></iq>`)); err != nil {
		t.Fatalf("send ping: %v", err)
	}

	start, _, err := c.NextStanzaWithTimeout(5 * time.Second)
	if err != nil {
		t.Fatalf("next stanza: %v", err)
	}
	if start.Name.Local != "iq" {
		t.Fatalf("expected <iq>, got <%s>", start.Name.Local)
	}
	requireAttr(t, start, "type", "result")
	requireAttr(t, start, "id", "1")
}

func TestPingViaIQNamespaceDispatch(t *testing.T) {
	h := NewHarness(t)
	defer h.Close()
	h.AddUser(t, "pinger", "pw")

	c := MustDial(t, h.TLSAddr(), h.Domain, "pinger", "pw")
	defer c.Close()

	if err := c.Send([]byte(`<iq id='ping1' type='get'><ping xmlns='urn:xmpp:ping'/></iq>`)); err != nil {
		t.Fatalf("send: %v", err)
	}

	start, _, err := c.NextStanzaWithTimeout(5 * time.Second)
	if err != nil {
		t.Fatalf("next stanza: %v", err)
	}
	if start.Name.Local != "iq" {
		t.Fatalf("expected <iq>, got <%s>", start.Name.Local)
	}
	requireAttr(t, start, "type", "result")
	requireAttr(t, start, "id", "ping1")
}

func TestUnknownIQReturnsFeatureNotImplemented(t *testing.T) {
	h := NewHarness(t)
	defer h.Close()
	h.AddUser(t, "unknown", "pw")

	c := MustDial(t, h.TLSAddr(), h.Domain, "unknown", "pw")
	defer c.Close()

	if err := c.Send([]byte(`<iq id='u1' type='get'><query xmlns='urn:custom:not:registered'/></iq>`)); err != nil {
		t.Fatalf("send: %v", err)
	}

	start, raw, err := c.NextStanzaWithTimeout(5 * time.Second)
	if err != nil {
		t.Fatalf("next stanza: %v", err)
	}
	if start.Name.Local != "iq" {
		t.Fatalf("expected <iq>, got <%s>", start.Name.Local)
	}
	requireAttr(t, start, "type", "error")
	requireAttr(t, start, "id", "u1")
	if !bytes.Contains(raw, []byte("feature-not-implemented")) {
		t.Fatalf("expected feature-not-implemented in response, got: %s", raw)
	}
}

func TestTwoClientMessageExchange(t *testing.T) {
	h := NewHarness(t)
	defer h.Close()
	h.AddUser(t, "alice", "pw")
	h.AddUser(t, "bob", "pw")

	a := MustDial(t, h.TLSAddr(), h.Domain, "alice", "pw")
	defer a.Close()
	b := MustDial(t, h.TLSAddr(), h.Domain, "bob", "pw")
	defer b.Close()

	if err := a.Send([]byte(`<presence/>`)); err != nil {
		t.Fatalf("alice presence: %v", err)
	}
	if err := b.Send([]byte(`<presence/>`)); err != nil {
		t.Fatalf("bob presence: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	msg := fmt.Sprintf(
		`<message to='%s' type='chat' id='m1'><body>hello bob</body></message>`,
		b.JID().String(),
	)
	if err := a.Send([]byte(msg)); err != nil {
		t.Fatalf("send message: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		start, raw, err := b.NextStanzaWithTimeout(500 * time.Millisecond)
		if err == ErrTimeout {
			continue
		}
		if err != nil {
			t.Fatalf("bob read: %v", err)
		}
		if start.Name.Local == "message" && bytes.Contains(raw, []byte("hello bob")) {
			return
		}
	}
	t.Fatal("timed out waiting for message at bob")
}

func TestMessageArchivedToMAMOnSend(t *testing.T) {
	h := NewHarness(t)
	defer h.Close()
	h.AddUser(t, "alice", "pw")
	h.AddUser(t, "bob", "pw")

	a := MustDial(t, h.TLSAddr(), h.Domain, "alice", "pw")
	defer a.Close()
	b := MustDial(t, h.TLSAddr(), h.Domain, "bob", "pw")
	defer b.Close()

	if err := a.Send([]byte(`<presence/>`)); err != nil {
		t.Fatalf("alice presence: %v", err)
	}
	if err := b.Send([]byte(`<presence/>`)); err != nil {
		t.Fatalf("bob presence: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	bobBare := b.JID().Bare().String()
	msg := fmt.Sprintf(
		`<message to='%s' type='chat' id='mam1'><body>archive me</body></message>`,
		b.JID().String(),
	)
	if err := a.Send([]byte(msg)); err != nil {
		t.Fatalf("send: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	aliceBare := a.JID().Bare().String()
	archived, err := h.MAMStore().Query(context.Background(), aliceBare, &bobBare, nil, nil, 10)
	if err != nil {
		t.Fatalf("MAM query: %v", err)
	}
	if len(archived) == 0 {
		t.Fatal("expected at least one archived stanza for alice, got none")
	}
	found := false
	for _, a := range archived {
		if bytes.Contains(a.StanzaXML, []byte("archive me")) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("archived stanza does not contain expected body text")
	}
}

func TestCarbonsFanout(t *testing.T) {
	h := NewHarness(t)
	defer h.Close()
	h.AddUser(t, "alice", "pw")
	h.AddUser(t, "bob", "pw")

	a1 := MustDial(t, h.TLSAddr(), h.Domain, "alice", "pw")
	defer a1.Close()
	a2 := MustDial(t, h.TLSAddr(), h.Domain, "alice", "pw")
	defer a2.Close()
	b := MustDial(t, h.TLSAddr(), h.Domain, "bob", "pw")
	defer b.Close()

	if err := a1.Send([]byte(`<presence/>`)); err != nil {
		t.Fatalf("a1 presence: %v", err)
	}
	if err := a2.Send([]byte(`<presence/>`)); err != nil {
		t.Fatalf("a2 presence: %v", err)
	}
	if err := b.Send([]byte(`<presence/>`)); err != nil {
		t.Fatalf("bob presence: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	enableCarbons := `<iq id='c1' type='set'><enable xmlns='urn:xmpp:carbons:2'/></iq>`
	for _, c := range []*Client{a1, a2} {
		if err := c.Send([]byte(enableCarbons)); err != nil {
			t.Fatalf("enable carbons: %v", err)
		}
		r, _, err := c.NextStanzaWithTimeout(3 * time.Second)
		if err != nil {
			t.Fatalf("carbons iq result: %v", err)
		}
		if r.Name.Local != "iq" {
			t.Fatalf("expected <iq>, got <%s>", r.Name.Local)
		}
	}

	msg := fmt.Sprintf(
		`<message to='%s' type='chat' id='carb1'><body>carbon copy</body></message>`,
		b.JID().String(),
	)
	if err := a1.Send([]byte(msg)); err != nil {
		t.Fatalf("a1 send message: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		start, raw, err := a2.NextStanzaWithTimeout(500 * time.Millisecond)
		if err == ErrTimeout {
			continue
		}
		if err != nil {
			t.Fatalf("a2 read: %v", err)
		}
		if start.Name.Local == "message" && bytes.Contains(raw, []byte("carbon copy")) {
			return
		}
	}
	t.Fatal("timed out waiting for carbon copy at a2")
}

//go:build integ

package integ_test

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func waitForStanza(t *testing.T, c *Client, deadline time.Time, match func(xml.StartElement, []byte) bool) (xml.StartElement, []byte) {
	t.Helper()
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		timeout := remaining
		if timeout > 500*time.Millisecond {
			timeout = 500 * time.Millisecond
		}
		start, raw, err := c.NextStanzaWithTimeout(timeout)
		if err == ErrTimeout {
			continue
		}
		if err != nil {
			t.Fatalf("read stanza: %v", err)
		}
		if match(start, raw) {
			return start, raw
		}
	}
	t.Fatal("timed out waiting for matching stanza")
	return xml.StartElement{}, nil
}

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

func TestMUCRoomCreateAndJoin(t *testing.T) {
	h := NewHarness(t)
	defer h.Close()
	h.AddUser(t, "alice", "pw")
	h.AddUser(t, "bob", "pw")

	a := MustDial(t, h.TLSAddr(), h.Domain, "alice", "pw")
	defer a.Close()
	b := MustDial(t, h.TLSAddr(), h.Domain, "bob", "pw")
	defer b.Close()

	room := fmt.Sprintf("chat@conference.%s", h.Domain)

	joinA := fmt.Sprintf(`<presence to='%s/alice'><x xmlns='http://jabber.org/protocol/muc'/></presence>`, room)
	if err := a.Send([]byte(joinA)); err != nil {
		t.Fatalf("alice join: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	waitForStanza(t, a, deadline, func(se xml.StartElement, raw []byte) bool {
		return se.Name.Local == "presence" && bytes.Contains(raw, []byte("110"))
	})

	joinB := fmt.Sprintf(`<presence to='%s/bob'><x xmlns='http://jabber.org/protocol/muc'/></presence>`, room)
	if err := b.Send([]byte(joinB)); err != nil {
		t.Fatalf("bob join: %v", err)
	}

	deadline = time.Now().Add(5 * time.Second)
	waitForStanza(t, b, deadline, func(se xml.StartElement, raw []byte) bool {
		return se.Name.Local == "presence" && bytes.Contains(raw, []byte("110"))
	})

	deadline = time.Now().Add(5 * time.Second)
	waitForStanza(t, a, deadline, func(se xml.StartElement, raw []byte) bool {
		return se.Name.Local == "presence" && bytes.Contains(raw, []byte("bob"))
	})
}

func TestMUCGroupchatBroadcast(t *testing.T) {
	h := NewHarness(t)
	defer h.Close()
	h.AddUser(t, "alice", "pw")
	h.AddUser(t, "bob", "pw")

	a := MustDial(t, h.TLSAddr(), h.Domain, "alice", "pw")
	defer a.Close()
	b := MustDial(t, h.TLSAddr(), h.Domain, "bob", "pw")
	defer b.Close()

	room := fmt.Sprintf("chat@conference.%s", h.Domain)

	joinA := fmt.Sprintf(`<presence to='%s/alice'><x xmlns='http://jabber.org/protocol/muc'/></presence>`, room)
	if err := a.Send([]byte(joinA)); err != nil {
		t.Fatalf("alice join: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	waitForStanza(t, a, deadline, func(se xml.StartElement, raw []byte) bool {
		return se.Name.Local == "presence" && bytes.Contains(raw, []byte("110"))
	})

	joinB := fmt.Sprintf(`<presence to='%s/bob'><x xmlns='http://jabber.org/protocol/muc'/></presence>`, room)
	if err := b.Send([]byte(joinB)); err != nil {
		t.Fatalf("bob join: %v", err)
	}
	deadline = time.Now().Add(5 * time.Second)
	waitForStanza(t, b, deadline, func(se xml.StartElement, raw []byte) bool {
		return se.Name.Local == "presence" && bytes.Contains(raw, []byte("110"))
	})

	time.Sleep(100 * time.Millisecond)

	msg := fmt.Sprintf(`<message to='%s' type='groupchat'><body>hello</body></message>`, room)
	if err := a.Send([]byte(msg)); err != nil {
		t.Fatalf("alice send groupchat: %v", err)
	}

	deadline = time.Now().Add(5 * time.Second)
	waitForStanza(t, b, deadline, func(se xml.StartElement, raw []byte) bool {
		return se.Name.Local == "message" && bytes.Contains(raw, []byte("hello")) &&
			bytes.Contains(raw, []byte("alice"))
	})
}

func TestMUCSelfPing(t *testing.T) {
	h := NewHarness(t)
	defer h.Close()
	h.AddUser(t, "alice", "pw")

	a := MustDial(t, h.TLSAddr(), h.Domain, "alice", "pw")
	defer a.Close()

	room := fmt.Sprintf("chat@conference.%s", h.Domain)
	nick := "alice"

	joinA := fmt.Sprintf(`<presence to='%s/%s'><x xmlns='http://jabber.org/protocol/muc'/></presence>`, room, nick)
	if err := a.Send([]byte(joinA)); err != nil {
		t.Fatalf("join: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	waitForStanza(t, a, deadline, func(se xml.StartElement, raw []byte) bool {
		return se.Name.Local == "presence" && bytes.Contains(raw, []byte("110"))
	})

	pingIQ := fmt.Sprintf(`<iq id='sp1' type='get' to='%s/%s'><ping xmlns='urn:xmpp:ping'/></iq>`, room, nick)
	if err := a.Send([]byte(pingIQ)); err != nil {
		t.Fatalf("send self-ping: %v", err)
	}

	deadline = time.Now().Add(5 * time.Second)
	pingResult, _ := waitForStanza(t, a, deadline, func(se xml.StartElement, raw []byte) bool {
		return se.Name.Local == "iq"
	})
	requireAttr(t, pingResult, "type", "result")
	requireAttr(t, pingResult, "id", "sp1")

	a2 := MustDial(t, h.TLSAddr(), h.Domain, "alice", "pw")
	defer a2.Close()

	pingNotIn := fmt.Sprintf(`<iq id='sp2' type='get' to='%s/ghost'><ping xmlns='urn:xmpp:ping'/></iq>`, room)
	if err := a2.Send([]byte(pingNotIn)); err != nil {
		t.Fatalf("send not-in-room ping: %v", err)
	}

	deadline = time.Now().Add(5 * time.Second)
	var errStart xml.StartElement
	var errRaw []byte
	errStart, errRaw = waitForStanza(t, a2, deadline, func(se xml.StartElement, raw []byte) bool {
		return se.Name.Local == "iq"
	})
	requireAttr(t, errStart, "type", "error")
	if !bytes.Contains(errRaw, []byte("not-acceptable")) && !bytes.Contains(errRaw, []byte("item-not-found")) {
		t.Fatalf("expected not-acceptable or item-not-found, got: %s", errRaw)
	}
}

func TestDiscoItemsListsConference(t *testing.T) {
	h := NewHarness(t)
	defer h.Close()
	h.AddUser(t, "alice", "pw")

	a := MustDial(t, h.TLSAddr(), h.Domain, "alice", "pw")
	defer a.Close()

	discoItems := fmt.Sprintf(`<iq id='di1' type='get' to='%s'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>`, h.Domain)
	if err := a.Send([]byte(discoItems)); err != nil {
		t.Fatalf("send disco#items: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	_, raw := waitForStanza(t, a, deadline, func(se xml.StartElement, raw []byte) bool {
		return se.Name.Local == "iq" && bytes.Contains(raw, []byte("disco#items"))
	})

	conf := fmt.Sprintf("conference.%s", h.Domain)
	if !bytes.Contains(raw, []byte(conf)) {
		t.Fatalf("disco#items response does not contain %q; got: %s", conf, raw)
	}
}

func TestPEPNotifyContactReceivesEvent(t *testing.T) {
	h := NewHarness(t)
	defer h.Close()
	h.AddUser(t, "alice", "pw")
	h.AddUser(t, "bob", "pw")

	aliceBare := fmt.Sprintf("alice@%s", h.Domain)
	bobBare := fmt.Sprintf("bob@%s", h.Domain)
	h.AddRosterItem(t, aliceBare, bobBare, 3)

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

	h.Caps().PutFeatures(b.JID(), "https://example.org", "v1", []string{"urn:xmpp:foo+notify"})

	pubIQ := `<iq id='pep1' type='set'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:xmpp:foo'><item id='i1'><data/></item></publish></pubsub></iq>`
	if err := a.Send([]byte(pubIQ)); err != nil {
		t.Fatalf("alice publish: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		start, raw, err := b.NextStanzaWithTimeout(500 * time.Millisecond)
		if err == ErrTimeout {
			continue
		}
		if err != nil {
			t.Fatalf("bob read: %v", err)
		}
		if start.Name.Local == "message" && bytes.Contains(raw, []byte("urn:xmpp:foo")) {
			return
		}
	}
	t.Fatal("timed out waiting for PEP +notify event at bob")
}

func TestIBRRegisterThenAuth(t *testing.T) {
	h := NewHarnessWithIBR(t, true)
	defer h.Close()

	if err := RegisterViaIBR(h.TLSAddr(), h.Domain, "newuser", "strongpassword"); err != nil {
		t.Fatalf("IBR registration: %v", err)
	}

	c := MustDial(t, h.TLSAddr(), h.Domain, "newuser", "strongpassword")
	defer c.Close()

	if err := c.Send([]byte(`<iq id='ping1' type='get'><ping xmlns='urn:xmpp:ping'/></iq>`)); err != nil {
		t.Fatalf("send ping: %v", err)
	}

	start, _, err := c.NextStanzaWithTimeout(5 * time.Second)
	if err != nil {
		t.Fatalf("read ping result: %v", err)
	}
	if start.Name.Local != "iq" {
		t.Fatalf("expected <iq>, got <%s>", start.Name.Local)
	}
	requireAttr(t, start, "type", "result")
	requireAttr(t, start, "id", "ping1")
}

func TestSMResumeAfterDisconnect(t *testing.T) {
	h := NewHarness(t)
	defer h.Close()
	h.AddUser(t, "alice", "pw")
	h.AddUser(t, "bob", "pw")

	a := MustDial(t, h.TLSAddr(), h.Domain, "alice", "pw")
	token, err := a.EnableSM(true)
	if err != nil {
		t.Fatalf("EnableSM: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty resume token")
	}

	aliceJID := a.JID()

	a.RawDisconnect()
	time.Sleep(150 * time.Millisecond)

	b := MustDial(t, h.TLSAddr(), h.Domain, "bob", "pw")
	defer b.Close()

	msg1 := fmt.Sprintf(`<message to='%s' type='chat' id='q1'><body>queued1</body></message>`, aliceJID.String())
	msg2 := fmt.Sprintf(`<message to='%s' type='chat' id='q2'><body>queued2</body></message>`, aliceJID.String())
	if err := b.Send([]byte(msg1)); err != nil {
		t.Fatalf("bob send msg1: %v", err)
	}
	if err := b.Send([]byte(msg2)); err != nil {
		t.Fatalf("bob send msg2: %v", err)
	}
	time.Sleep(400 * time.Millisecond)

	a2 := h.NewClientForResume(t, "alice", "pw")
	defer a2.Close()

	if err := a2.ResumeSM(token, 0); err != nil {
		t.Fatalf("ResumeSM: %v", err)
	}

	received := make(map[string]bool)
	deadline := time.Now().Add(5 * time.Second)
	for len(received) < 2 && time.Now().Before(deadline) {
		start, raw, rerr := a2.NextStanzaWithTimeout(500 * time.Millisecond)
		if rerr == ErrTimeout {
			continue
		}
		if rerr != nil {
			t.Fatalf("a2 read: %v", rerr)
		}
		if start.Name.Local == "message" {
			if bytes.Contains(raw, []byte("queued1")) {
				received["queued1"] = true
			}
			if bytes.Contains(raw, []byte("queued2")) {
				received["queued2"] = true
			}
		}
	}
	if !received["queued1"] {
		t.Fatal("queued1 not delivered on resume")
	}
	if !received["queued2"] {
		t.Fatal("queued2 not delivered on resume")
	}
}

func TestSMResumeExpiresAfterTTL(t *testing.T) {
	h := NewHarness(t)
	defer h.Close()
	h.AddUser(t, "alice", "pw")

	h.WithResumeTimeout(400 * time.Millisecond)

	a := MustDial(t, h.TLSAddr(), h.Domain, "alice", "pw")
	token, err := a.EnableSM(true)
	if err != nil {
		t.Fatalf("EnableSM: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty resume token")
	}

	a.RawDisconnect()
	time.Sleep(600 * time.Millisecond)

	a2 := h.NewClientForResume(t, "alice", "pw")
	defer a2.Close()

	pkt := fmt.Sprintf(`<resume xmlns='urn:xmpp:sm:3' previd='%s' h='0'/>`, token)
	if err := a2.Send([]byte(pkt)); err != nil {
		t.Fatalf("send resume: %v", err)
	}

	start, _, rerr := a2.NextStanzaWithTimeout(5 * time.Second)
	if rerr != nil {
		t.Fatalf("read after resume: %v", rerr)
	}
	if start.Name.Local != "failed" {
		t.Fatalf("expected <failed>, got <%s>", start.Name.Local)
	}
}

func parseSlotURLs(t *testing.T, raw []byte) (putURL, getURL string) {
	t.Helper()
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
		switch se.Name.Local {
		case "put":
			for _, a := range se.Attr {
				if a.Name.Local == "url" {
					putURL = a.Value
				}
			}
		case "get":
			for _, a := range se.Attr {
				if a.Name.Local == "url" {
					getURL = a.Value
				}
			}
		}
	}
	return
}

func TestHTTPUploadRoundTrip(t *testing.T) {
	h := NewHarness(t)
	defer h.Close()
	h.AddUser(t, "alice", "pw")
	a := MustDial(t, h.TLSAddr(), h.Domain, "alice", "pw")
	defer a.Close()

	req := `<iq id='u1' type='set'><request xmlns='urn:xmpp:http:upload:0' filename='hello.txt' size='5' content-type='text/plain'/></iq>`
	if err := a.Send([]byte(req)); err != nil {
		t.Fatalf("send slot request: %v", err)
	}
	start, raw, err := a.NextStanzaWithTimeout(3 * time.Second)
	if err != nil {
		t.Fatalf("next stanza: %v", err)
	}
	if start.Name.Local != "iq" {
		t.Fatalf("expected <iq>, got <%s>", start.Name.Local)
	}
	requireAttr(t, start, "type", "result")

	putURL, getURL := parseSlotURLs(t, raw)
	if putURL == "" {
		t.Fatalf("no put URL in slot response: %s", raw)
	}
	if getURL == "" {
		t.Fatalf("no get URL in slot response: %s", raw)
	}

	body := []byte("hello")
	putReq, _ := http.NewRequest(http.MethodPut, putURL, bytes.NewReader(body))
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusCreated && putResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT status: %d", putResp.StatusCode)
	}

	getResp, err := http.Get(getURL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	got, _ := io.ReadAll(getResp.Body)
	getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET status: %d", getResp.StatusCode)
	}
	if string(got) != "hello" {
		t.Fatalf("GET body: got %q, want %q", got, "hello")
	}
}

func TestPushFiresOnCSIInactiveDelivery(t *testing.T) {
	h := NewHarness(t)
	defer h.Close()
	h.AddUser(t, "alice", "pw")
	h.AddUser(t, "bob", "pw")

	a := MustDial(t, h.TLSAddr(), h.Domain, "alice", "pw")
	defer a.Close()

	b := MustDial(t, h.TLSAddr(), h.Domain, "bob", "pw")
	defer b.Close()

	pushEnable := `<iq id='p1' type='set'><enable xmlns='urn:xmpp:push:0' jid='push@localhost' node='dev1'><x xmlns='jabber:x:data'><field var='device_token'><value>tok-bob</value></field></x></enable></iq>`
	if err := b.Send([]byte(pushEnable)); err != nil {
		t.Fatalf("push enable send: %v", err)
	}
	_, _, err := b.NextStanzaWithTimeout(2 * time.Second)
	if err != nil {
		t.Fatalf("push enable result: %v", err)
	}

	if err := b.Send([]byte(`<inactive xmlns='urn:xmpp:csi:0'/>`)); err != nil {
		t.Fatalf("csi inactive: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	if err := a.Send([]byte(fmt.Sprintf(
		`<message to='%s' type='chat'><body>wake up</body></message>`,
		b.JID().String(),
	))); err != nil {
		t.Fatalf("alice send: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(h.PushSends()) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	sends := h.PushSends()
	if len(sends) == 0 {
		t.Fatal("expected at least one push send, got none")
	}
	if sends[0].DeviceToken != "tok-bob" {
		t.Fatalf("push device token: got %q, want %q", sends[0].DeviceToken, "tok-bob")
	}
}

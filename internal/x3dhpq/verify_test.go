package x3dhpq

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/danielinux/xmppqr/internal/stanza"
)

type stubSession struct{ jid stanza.JID }

func (s stubSession) JID() stanza.JID { return s.jid }

type stubRouter struct {
	sessions []RouterSession
	routed   []routedFull
}

type routedFull struct {
	to  stanza.JID
	raw []byte
}

func (r *stubRouter) SessionsFor(string) []RouterSession { return r.sessions }
func (r *stubRouter) RouteToFull(_ context.Context, full stanza.JID, raw []byte) error {
	r.routed = append(r.routed, routedFull{to: full, raw: raw})
	return nil
}

func mkJID(s string) stanza.JID {
	j, _ := stanza.Parse(s)
	return j
}

func TestVerifyDeviceFanOutSucceeds(t *testing.T) {
	from := mkJID("alice@example.org/phone")
	peers := []RouterSession{
		stubSession{jid: mkJID("alice@example.org/desktop")},
		stubSession{jid: mkJID("alice@example.org/laptop")},
		stubSession{jid: from},
	}
	rt := &stubRouter{sessions: peers}
	v := NewVerifyDevice(rt, NewPairLimiter(DefaultPairLimiterConfig()), nil)

	iq := &stanza.IQ{
		ID:      "vd-1",
		Type:    stanza.IQSet,
		Payload: []byte(`<verify-device xmlns='urn:xmppqr:x3dhpq:pair:0' device-id='42424242' transport='message'/>`),
	}

	resp, err := v.HandleIQ(context.Background(), from, iq)
	if err != nil {
		t.Fatalf("HandleIQ err: %v", err)
	}
	if !bytes.Contains(resp, []byte("count='2'")) {
		t.Fatalf("expected count='2' in result; got: %s", resp)
	}
	if len(rt.routed) != 2 {
		t.Fatalf("expected 2 fan-out messages, got %d", len(rt.routed))
	}
	for _, m := range rt.routed {
		if !bytes.Contains(m.raw, []byte("new-resource='alice@example.org/phone'")) {
			t.Fatalf("fan-out missing new-resource attr; got: %s", m.raw)
		}
		if !bytes.Contains(m.raw, []byte("device-id='42424242'")) {
			t.Fatalf("fan-out missing device-id; got: %s", m.raw)
		}
		if m.to.Equal(from) {
			t.Fatalf("fan-out delivered back to originator")
		}
	}
}

func TestVerifyDeviceNoPeersIsNotAcceptable(t *testing.T) {
	from := mkJID("alice@example.org/phone")
	rt := &stubRouter{sessions: []RouterSession{stubSession{jid: from}}}
	v := NewVerifyDevice(rt, NewPairLimiter(DefaultPairLimiterConfig()), nil)

	iq := &stanza.IQ{
		ID:      "vd-1",
		Type:    stanza.IQSet,
		Payload: []byte(`<verify-device xmlns='urn:xmppqr:x3dhpq:pair:0' device-id='42'/>`),
	}
	_, err := v.HandleIQ(context.Background(), from, iq)
	se, ok := err.(*stanza.StanzaError)
	if !ok {
		t.Fatalf("expected StanzaError, got %T: %v", err, err)
	}
	if se.Condition != stanza.ErrNotAcceptable {
		t.Fatalf("expected not-acceptable, got %s", se.Condition)
	}
}

func TestVerifyDeviceRejectsUnauthorisedTo(t *testing.T) {
	from := mkJID("alice@example.org/phone")
	rt := &stubRouter{sessions: []RouterSession{stubSession{jid: mkJID("alice@example.org/desktop")}, stubSession{jid: from}}}
	v := NewVerifyDevice(rt, NewPairLimiter(DefaultPairLimiterConfig()), nil)

	iq := &stanza.IQ{
		ID:      "vd-1",
		Type:    stanza.IQSet,
		To:      "mallory@example.org",
		Payload: []byte(`<verify-device xmlns='urn:xmppqr:x3dhpq:pair:0' device-id='42'/>`),
	}
	_, err := v.HandleIQ(context.Background(), from, iq)
	se, ok := err.(*stanza.StanzaError)
	if !ok {
		t.Fatalf("expected StanzaError")
	}
	if se.Condition != stanza.ErrForbidden {
		t.Fatalf("expected forbidden, got %s", se.Condition)
	}
}

func TestVerifyDeviceRequiresFullJID(t *testing.T) {
	bare := mkJID("alice@example.org")
	rt := &stubRouter{}
	v := NewVerifyDevice(rt, NewPairLimiter(DefaultPairLimiterConfig()), nil)

	iq := &stanza.IQ{
		ID:      "vd-1",
		Type:    stanza.IQSet,
		Payload: []byte(`<verify-device xmlns='urn:xmppqr:x3dhpq:pair:0' device-id='42'/>`),
	}
	_, err := v.HandleIQ(context.Background(), bare, iq)
	se, ok := err.(*stanza.StanzaError)
	if !ok || se.Condition != stanza.ErrForbidden {
		t.Fatalf("expected forbidden for bare-jid sender; got %v", err)
	}
}

func TestVerifyDeviceRejectsMissingDeviceID(t *testing.T) {
	from := mkJID("alice@example.org/phone")
	peers := []RouterSession{stubSession{jid: mkJID("alice@example.org/desktop")}, stubSession{jid: from}}
	rt := &stubRouter{sessions: peers}
	v := NewVerifyDevice(rt, NewPairLimiter(DefaultPairLimiterConfig()), nil)

	iq := &stanza.IQ{
		ID:      "vd-1",
		Type:    stanza.IQSet,
		Payload: []byte(`<verify-device xmlns='urn:xmppqr:x3dhpq:pair:0'/>`),
	}
	_, err := v.HandleIQ(context.Background(), from, iq)
	se, ok := err.(*stanza.StanzaError)
	if !ok || se.Condition != stanza.ErrBadRequest {
		t.Fatalf("expected bad-request; got %v", err)
	}
}

func TestPairLimiterPair(t *testing.T) {
	l := NewPairLimiter(PairLimiterConfig{Burst: 3, WindowSeconds: 60})
	for i := 0; i < 3; i++ {
		if !l.AllowPair("a/x", "b/y") {
			t.Fatalf("burst %d denied prematurely", i)
		}
	}
	if l.AllowPair("a/x", "b/y") {
		t.Fatalf("expected fourth call to be denied")
	}
	if !l.AllowPair("a/x", "c/z") {
		t.Fatalf("different (from,to) bucket should not share state")
	}
}

func TestPairLimiterVerify(t *testing.T) {
	l := NewPairLimiter(DefaultPairLimiterConfig())
	for i := 0; i < 3; i++ {
		if !l.AllowVerify("alice@x/phone") {
			t.Fatalf("verify burst %d denied prematurely", i)
		}
	}
	if l.AllowVerify("alice@x/phone") {
		t.Fatalf("expected fourth verify call to be denied")
	}
}

func TestBundleRateCheckerAllowPublishOnlyForBundleNode(t *testing.T) {
	rc := NewRateChecker(DefaultLimits())
	if !rc.AllowPublish("urn:xmpp:something:else", "1") {
		t.Fatalf("non-bundle node should pass through")
	}
	if !rc.AllowPublish(NSBundle, "1") {
		t.Fatalf("first bundle publish should pass")
	}
	if rc.AllowPublish(NSBundle, "1") {
		t.Fatalf("second bundle publish within a minute should be denied")
	}
	if !rc.AllowPublish(NSBundle, "2") {
		t.Fatalf("different device-id should not share bucket")
	}
}

func TestParseVerifyDeviceIDIgnoresWrongElement(t *testing.T) {
	if _, ok := parseVerifyDeviceID([]byte(`<other xmlns='urn:xmppqr:x3dhpq:pair:0' device-id='1'/>`)); ok {
		t.Fatalf("non-verify-device element should be rejected")
	}
	if _, ok := parseVerifyDeviceID([]byte(`<verify-device xmlns='wrong-ns' device-id='1'/>`)); ok {
		t.Fatalf("wrong namespace should be rejected")
	}
	id, ok := parseVerifyDeviceID([]byte(`<verify-device xmlns='urn:xmppqr:x3dhpq:pair:0' device-id='123'/>`))
	if !ok || id != "123" {
		t.Fatalf("expected 123, got %q ok=%v", id, ok)
	}
}

func TestVerifyHeadlineEncodesFromBareJID(t *testing.T) {
	bare := mkJID("alice@example.org")
	peer := mkJID("alice@example.org/desktop")
	newRes := mkJID("alice@example.org/phone")
	out := buildVerifyHeadline(bare, peer, newRes, "42", "vd-1")
	if !bytes.Contains(out, []byte("from='alice@example.org'")) {
		t.Fatalf("expected from=bare jid; got: %s", out)
	}
	if !strings.Contains(string(out), "type='headline'") {
		t.Fatalf("expected type=headline; got: %s", out)
	}
}

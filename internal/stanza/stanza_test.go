package stanza

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"
)

func TestMessageRoundTrip(t *testing.T) {
	opaqueChild := []byte(`<x xmlns="urn:custom:ext">secret</x>`)
	raw := append([]byte(`<message id="1" type="chat" from="a@b" to="c@d"><body>hello</body>`), opaqueChild...)
	raw = append(raw, []byte(`</message>`)...)

	dec := xml.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.RawToken()
	if err != nil {
		t.Fatalf("decode start: %v", err)
	}
	start := tok.(xml.StartElement)

	m, err := ParseMessage(start, raw)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if m.ID != "1" || m.Body != "hello" || m.From != "a@b" {
		t.Errorf("fields: %+v", m)
	}
	if !bytes.Contains(m.Children, []byte("urn:custom:ext")) {
		t.Errorf("opaque child missing: %s", m.Children)
	}

	out, err := m.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Contains(out, []byte("secret")) {
		t.Errorf("opaque content missing after round-trip: %s", out)
	}
	if !bytes.Contains(out, []byte("urn:custom:ext")) {
		t.Errorf("opaque namespace missing after round-trip: %s", out)
	}
}

func TestIQResultHelper(t *testing.T) {
	raw := []byte(`<iq id="2" type="result"><query xmlns="jabber:iq:version"/></iq>`)
	dec := xml.NewDecoder(bytes.NewReader(raw))
	tok, _ := dec.RawToken()
	start := tok.(xml.StartElement)

	iq, err := ParseIQ(start, raw)
	if err != nil {
		t.Fatalf("ParseIQ: %v", err)
	}
	if !iq.IsResponse() {
		t.Error("expected IsResponse for type=result")
	}
}

func TestIQErrorHelper(t *testing.T) {
	raw := []byte(`<iq id="3" type="error"/>`)
	dec := xml.NewDecoder(bytes.NewReader(raw))
	tok, _ := dec.RawToken()
	start := tok.(xml.StartElement)

	iq, err := ParseIQ(start, raw)
	if err != nil {
		t.Fatalf("ParseIQ: %v", err)
	}
	if !iq.IsResponse() {
		t.Error("expected IsResponse for type=error")
	}
}

func TestIQGetNotResponse(t *testing.T) {
	raw := []byte(`<iq id="4" type="get"/>`)
	dec := xml.NewDecoder(bytes.NewReader(raw))
	tok, _ := dec.RawToken()
	start := tok.(xml.StartElement)

	iq, _ := ParseIQ(start, raw)
	if iq.IsResponse() {
		t.Error("type=get should not be a response")
	}
}

func TestStanzaErrorMarshal(t *testing.T) {
	se := &StanzaError{
		Type:      ErrorTypeCancel,
		Condition: ErrItemNotFound,
		Text:      "not found",
	}
	b, err := se.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, "cancel") {
		t.Errorf("type missing: %s", s)
	}
	if !strings.Contains(s, "item-not-found") {
		t.Errorf("condition missing: %s", s)
	}
	if !strings.Contains(s, "not found") {
		t.Errorf("text missing: %s", s)
	}
}

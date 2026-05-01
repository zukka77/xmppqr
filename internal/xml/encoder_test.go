package xml

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"
)

func TestEncoderOpenStream(t *testing.T) {
	var buf bytes.Buffer
	e := NewEncoder(&buf)
	h := StreamHeader{From: "server.example", To: "client.example", ID: "s1", Version: "1.0"}
	if err := e.OpenStream(h); err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `xmlns:stream="http://etherx.jabber.org/streams"`) {
		t.Errorf("stream namespace missing: %s", out)
	}
	if !strings.Contains(out, `id="s1"`) {
		t.Errorf("id missing: %s", out)
	}
}

func TestWriteElementRoundTrip(t *testing.T) {
	// X3DHPQ opacity contract: unknown child bytes must survive the round-trip.
	opaqueChild := []byte(`<x xmlns='urn:custom'>opaque-data</x>`)

	start := xml.StartElement{
		Name: xml.Name{Local: "iq"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "id"}, Value: "42"},
			{Name: xml.Name{Local: "type"}, Value: "result"},
		},
	}

	var buf bytes.Buffer
	e := NewEncoder(&buf)
	if err := e.WriteElement(start, opaqueChild); err != nil {
		t.Fatalf("WriteElement: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "urn:custom") {
		t.Errorf("opaque namespace missing: %s", out)
	}
	if !strings.Contains(out, "opaque-data") {
		t.Errorf("opaque content missing: %s", out)
	}
	if !strings.Contains(out, `id="42"`) {
		t.Errorf("id attr missing: %s", out)
	}
	// Must have closing </iq>
	if !strings.Contains(out, `</iq>`) {
		t.Errorf("closing tag missing: %s", out)
	}
}

func TestWriteRaw(t *testing.T) {
	var buf bytes.Buffer
	e := NewEncoder(&buf)
	raw := []byte(`<presence/>`)
	n, err := e.WriteRaw(raw)
	if err != nil {
		t.Fatalf("WriteRaw: %v", err)
	}
	if n != len(raw) {
		t.Errorf("n=%d want %d", n, len(raw))
	}
	if !bytes.Equal(buf.Bytes(), raw) {
		t.Errorf("got %s want %s", buf.Bytes(), raw)
	}
}

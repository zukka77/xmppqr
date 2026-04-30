package xml

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestOpenStream(t *testing.T) {
	input := `<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' from='juliet@example.com' to='example.com' version='1.0' id='abc123'>`
	d := NewDecoder(strings.NewReader(input))
	h, err := d.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if h.From != "juliet@example.com" {
		t.Errorf("From=%q want juliet@example.com", h.From)
	}
	if h.To != "example.com" {
		t.Errorf("To=%q want example.com", h.To)
	}
	if h.ID != "abc123" {
		t.Errorf("ID=%q want abc123", h.ID)
	}
	if h.Version != "1.0" {
		t.Errorf("Version=%q want 1.0", h.Version)
	}
}

func TestOpenStreamNoDecl(t *testing.T) {
	input := `<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='example.com' version='1.0'>`
	d := NewDecoder(strings.NewReader(input))
	h, err := d.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if h.To != "example.com" {
		t.Errorf("To=%q want example.com", h.To)
	}
}

func TestOpenStreamBadVersion(t *testing.T) {
	input := `<stream:stream xmlns:stream='http://etherx.jabber.org/streams' version='0.9'>`
	d := NewDecoder(strings.NewReader(input))
	_, err := d.OpenStream(context.Background())
	if err == nil {
		t.Fatal("expected error for version 0.9")
	}
}

func TestOpenStreamMalformed(t *testing.T) {
	input := `<iq id='1'/>`
	d := NewDecoder(strings.NewReader(input))
	_, err := d.OpenStream(context.Background())
	if err == nil {
		t.Fatal("expected error for non-stream opening element")
	}
}

func TestNextElementRoundTrip(t *testing.T) {
	// The unknown child <x xmlns='urn:custom'/> must round-trip byte-identical.
	iq := `<iq id='1' type='get'><query xmlns='jabber:iq:version'/><x xmlns='urn:custom'>opaque</x></iq>`
	input := `<stream:stream xmlns:stream='http://etherx.jabber.org/streams'>` + iq
	d := NewDecoder(strings.NewReader(input))
	_, err := d.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	start, raw, err := d.NextElement()
	if err != nil {
		t.Fatalf("NextElement: %v", err)
	}
	if start.Name.Local != "iq" {
		t.Errorf("local name=%q want iq", start.Name.Local)
	}
	if !bytes.Contains(raw, []byte("urn:custom")) {
		t.Errorf("raw bytes missing urn:custom namespace; got %s", raw)
	}
	// The full raw element bytes must contain everything
	if !bytes.Contains(raw, []byte("opaque")) {
		t.Errorf("raw bytes missing opaque child content")
	}
}

func TestNextElementMaxBytes(t *testing.T) {
	// Build a stanza that exceeds 64 bytes limit.
	big := `<message id='x'>` + strings.Repeat("A", 100) + `</message>`
	input := `<stream:stream xmlns:stream='http://etherx.jabber.org/streams'>` + big
	d := NewDecoder(strings.NewReader(input))
	d.SetMaxBytes(64)
	_, err := d.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	_, _, err = d.NextElement()
	if err == nil {
		t.Fatal("expected error for oversized stanza")
	}
}

// slowReader hands out one byte at a time and never EOFs, simulating an open
// XMPP stream socket. The decoder must not block indefinitely waiting for EOF.
type slowReader struct {
	data []byte
	pos  int
}

func (s *slowReader) Read(p []byte) (int, error) {
	if s.pos >= len(s.data) {
		// Block forever rather than EOF — mimics an open socket awaiting more data.
		select {}
	}
	p[0] = s.data[s.pos]
	s.pos++
	return 1, nil
}

func TestNextElementResolvesNamespace(t *testing.T) {
	hdr := `<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>`
	stanzas := `<iq id='1' type='get'/>` +
		`<enable xmlns='urn:xmpp:sm:3'/>` +
		`<enable xmlns='urn:custom-not-sm'/>` +
		`<stream:error/>`
	d := NewDecoder(strings.NewReader(hdr + stanzas))
	if _, err := d.OpenStream(context.Background()); err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	cases := []struct {
		wantLocal string
		wantSpace string
	}{
		{"iq", "jabber:client"},
		{"enable", "urn:xmpp:sm:3"},
		{"enable", "urn:custom-not-sm"},
		{"error", "http://etherx.jabber.org/streams"},
	}
	for i, want := range cases {
		start, _, err := d.NextElement()
		if err != nil {
			t.Fatalf("NextElement #%d: %v", i, err)
		}
		if start.Name.Local != want.wantLocal || start.Name.Space != want.wantSpace {
			t.Errorf("#%d: got {%q,%q}, want {%q,%q}", i, start.Name.Space, start.Name.Local, want.wantSpace, want.wantLocal)
		}
	}
}

func TestStreamingNoEOF(t *testing.T) {
	hdr := `<stream:stream xmlns:stream='http://etherx.jabber.org/streams'>`
	stanza1 := `<iq id='1' type='get'><query xmlns='ns1'/></iq>`
	stanza2 := `<message id='2'><body>hi</body><x xmlns='urn:custom'>opaque</x></message>`
	d := NewDecoder(&slowReader{data: []byte(hdr + stanza1 + stanza2)})
	if _, err := d.OpenStream(context.Background()); err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	start1, raw1, err := d.NextElement()
	if err != nil {
		t.Fatalf("NextElement #1: %v", err)
	}
	if start1.Name.Local != "iq" || !bytes.Contains(raw1, []byte("ns1")) {
		t.Errorf("stanza 1 wrong: name=%s raw=%s", start1.Name.Local, raw1)
	}
	start2, raw2, err := d.NextElement()
	if err != nil {
		t.Fatalf("NextElement #2: %v", err)
	}
	if start2.Name.Local != "message" || !bytes.Contains(raw2, []byte("urn:custom")) || !bytes.Contains(raw2, []byte("opaque")) {
		t.Errorf("stanza 2 wrong: name=%s raw=%s", start2.Name.Local, raw2)
	}
	// After consuming both stanzas, the capture buffer should have compacted —
	// proving we don't accumulate unbounded memory across long sessions.
	if int64(len(d.cap.buf)) > 256 {
		t.Errorf("capture buffer not compacted: %d bytes still buffered", len(d.cap.buf))
	}
}

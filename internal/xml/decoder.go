package xml

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
)

const DefaultMaxBytes = 1 << 20

type Decoder struct {
	cap      *captureReader
	dec      *xml.Decoder
	maxBytes int64

	// Namespace scope inherited from the stream-open element. encoding/xml's
	// RawToken() doesn't expand prefixes; we resolve top-level element names
	// ourselves so dispatchers can match on the URI rather than the prefix.
	streamDefaultNS string
	streamPrefixes  map[string]string
}

type captureReader struct {
	src    io.Reader
	buf    []byte
	origin int64
}

func (c *captureReader) Read(p []byte) (int, error) {
	n, err := c.src.Read(p)
	if n > 0 {
		c.buf = append(c.buf, p[:n]...)
	}
	return n, err
}

func (c *captureReader) sliceFromOffset(start, end int64) []byte {
	lo := start - c.origin
	hi := end - c.origin
	if lo < 0 || hi > int64(len(c.buf)) {
		return nil
	}
	out := make([]byte, hi-lo)
	copy(out, c.buf[lo:hi])
	return out
}

func (c *captureReader) compactTo(off int64) {
	drop := off - c.origin
	if drop <= 0 {
		return
	}
	if drop >= int64(len(c.buf)) {
		c.buf = c.buf[:0]
		c.origin = off
		return
	}
	c.buf = append(c.buf[:0], c.buf[drop:]...)
	c.origin = off
}

func NewDecoder(r io.Reader) *Decoder {
	cap := &captureReader{src: r}
	d := xml.NewDecoder(cap)
	d.Entity = map[string]string{}
	return &Decoder{
		cap:            cap,
		dec:            d,
		maxBytes:       DefaultMaxBytes,
		streamPrefixes: map[string]string{},
	}
}

func (d *Decoder) SetMaxBytes(n int64) {
	d.maxBytes = n
}

func (d *Decoder) OpenStream(_ context.Context) (StreamHeader, error) {
	tok, err := d.dec.RawToken()
	if err != nil {
		return StreamHeader{}, fmt.Errorf("%w: %v", ErrBadStream, err)
	}

	if _, ok := tok.(xml.ProcInst); ok {
		tok, err = d.dec.RawToken()
		if err != nil {
			return StreamHeader{}, fmt.Errorf("%w: %v", ErrBadStream, err)
		}
	}

	start, ok := tok.(xml.StartElement)
	if !ok {
		return StreamHeader{}, ErrBadStream
	}

	if start.Name.Local != "stream" {
		return StreamHeader{}, ErrBadStream
	}

	var h StreamHeader
	for _, attr := range start.Attr {
		if attr.Name.Space == "xmlns" {
			d.streamPrefixes[attr.Name.Local] = attr.Value
			continue
		}
		if attr.Name.Local == "xmlns" && attr.Name.Space == "" {
			d.streamDefaultNS = attr.Value
			continue
		}
		switch attr.Name.Local {
		case "from":
			h.From = attr.Value
		case "to":
			h.To = attr.Value
		case "id":
			h.ID = attr.Value
		case "version":
			h.Version = attr.Value
		case "lang":
			h.Lang = attr.Value
		}
	}

	if h.Version != "" && h.Version != "1.0" {
		return StreamHeader{}, ErrUnsupportedVersion
	}

	d.cap.compactTo(d.dec.InputOffset())
	return h, nil
}

func (d *Decoder) NextElement() (xml.StartElement, []byte, error) {
	var start xml.StartElement
	var startOffset int64
	for {
		startOffset = d.dec.InputOffset()
		tok, err := d.dec.RawToken()
		if err != nil {
			return xml.StartElement{}, nil, err
		}
		var ok bool
		start, ok = tok.(xml.StartElement)
		if ok {
			break
		}
	}

	d.resolveNamespace(&start)

	depth := 1
	for depth > 0 {
		tok, err := d.dec.RawToken()
		if err != nil {
			return xml.StartElement{}, nil, err
		}
		if d.dec.InputOffset()-startOffset > d.maxBytes {
			return xml.StartElement{}, nil, fmt.Errorf("stanza exceeds max size %d bytes", d.maxBytes)
		}
		switch tok.(type) {
		case xml.StartElement:
			depth++
		case xml.EndElement:
			depth--
		}
	}

	endOffset := d.dec.InputOffset()
	raw := d.cap.sliceFromOffset(startOffset, endOffset)
	if raw == nil {
		return xml.StartElement{}, nil, fmt.Errorf("internal: capture buffer missing range %d-%d (origin %d, len %d)", startOffset, endOffset, d.cap.origin, len(d.cap.buf))
	}
	d.cap.compactTo(endOffset)
	return start, raw, nil
}

func (d *Decoder) Close() {}

// resolveNamespace populates start.Name.Space with the namespace URI inherited
// from the stream-open element or declared on the element itself. Without this,
// RawToken leaves Space as either the empty string or the prefix literal —
// dispatchers that match by namespace URI would mis-classify elements.
func (d *Decoder) resolveNamespace(start *xml.StartElement) {
	defaultNS := d.streamDefaultNS
	prefixes := d.streamPrefixes
	var localPrefixes map[string]string
	for _, a := range start.Attr {
		if a.Name.Space == "xmlns" {
			if localPrefixes == nil {
				localPrefixes = map[string]string{}
			}
			localPrefixes[a.Name.Local] = a.Value
		} else if a.Name.Local == "xmlns" && a.Name.Space == "" {
			defaultNS = a.Value
		}
	}
	prefix := start.Name.Space
	if prefix == "" {
		start.Name.Space = defaultNS
		return
	}
	if localPrefixes != nil {
		if uri, ok := localPrefixes[prefix]; ok {
			start.Name.Space = uri
			return
		}
	}
	if uri, ok := prefixes[prefix]; ok {
		start.Name.Space = uri
		return
	}
	// Unknown prefix — leave the literal so callers can spot it.
}

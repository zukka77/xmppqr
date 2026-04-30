package xml

import (
	"encoding/xml"
	"fmt"
	"io"
)

type Encoder struct {
	w   io.Writer
	enc *xml.Encoder
}

func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w, enc: xml.NewEncoder(w)}
}

func (e *Encoder) OpenStream(h StreamHeader) error {
	attrs := []xml.Attr{
		{Name: xml.Name{Local: "xmlns"}, Value: NSClient},
		{Name: xml.Name{Local: "xmlns:stream"}, Value: NSStream},
	}
	if h.From != "" {
		attrs = append(attrs, xml.Attr{Name: xml.Name{Local: "from"}, Value: h.From})
	}
	if h.To != "" {
		attrs = append(attrs, xml.Attr{Name: xml.Name{Local: "to"}, Value: h.To})
	}
	if h.ID != "" {
		attrs = append(attrs, xml.Attr{Name: xml.Name{Local: "id"}, Value: h.ID})
	}
	if h.Version != "" {
		attrs = append(attrs, xml.Attr{Name: xml.Name{Local: "version"}, Value: h.Version})
	}
	if h.Lang != "" {
		attrs = append(attrs, xml.Attr{Name: xml.Name{Local: "xml:lang"}, Value: h.Lang})
	}

	_, err := fmt.Fprintf(e.w, `<?xml version='1.0'?><stream:stream`)
	if err != nil {
		return err
	}
	for _, a := range attrs {
		_, err = fmt.Fprintf(e.w, ` %s="%s"`, a.Name.Local, a.Value)
		if err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(e.w, `>`)
	return err
}

// WriteElement writes start tag, raw body bytes, and end tag.
func (e *Encoder) WriteElement(start xml.StartElement, body []byte) error {
	if err := e.enc.EncodeToken(start); err != nil {
		return err
	}
	if err := e.enc.Flush(); err != nil {
		return err
	}
	if len(body) > 0 {
		if _, err := e.w.Write(body); err != nil {
			return err
		}
	}
	if err := e.enc.EncodeToken(start.End()); err != nil {
		return err
	}
	return e.enc.Flush()
}

func (e *Encoder) WriteRaw(p []byte) (int, error) {
	return e.w.Write(p)
}

func (e *Encoder) Close() error {
	return e.enc.Flush()
}

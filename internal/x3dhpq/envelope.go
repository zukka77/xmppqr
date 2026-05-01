package x3dhpq

import (
	"bytes"
	"encoding/xml"
	"errors"
)

func ValidateEnvelope(envelopeXML []byte, msgMaxBytes int64) error {
	if int64(len(envelopeXML)) > msgMaxBytes {
		return errors.New("x3dhpq: envelope exceeds size limit")
	}
	dec := xml.NewDecoder(bytes.NewReader(envelopeXML))
	tok, err := dec.Token()
	if err != nil {
		return errors.New("x3dhpq: envelope is not valid XML")
	}
	start, ok := tok.(xml.StartElement)
	if !ok {
		return errors.New("x3dhpq: envelope: expected start element")
	}
	if start.Name.Local != "x3dhpq" {
		return errors.New("x3dhpq: envelope: root element must be <x3dhpq>")
	}
	ns := start.Name.Space
	if ns == "" {
		for _, a := range start.Attr {
			if a.Name.Local == "xmlns" {
				ns = a.Value
			}
		}
	}
	if ns != NSEnvelope {
		return errors.New("x3dhpq: envelope: wrong namespace")
	}
	return nil
}

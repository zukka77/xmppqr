package spqr

import (
	"bytes"
	"encoding/xml"
	"errors"
)

func ValidateEnvelope(envelopeXML []byte, msgMaxBytes int64) error {
	if int64(len(envelopeXML)) > msgMaxBytes {
		return errors.New("spqr: envelope exceeds size limit")
	}
	dec := xml.NewDecoder(bytes.NewReader(envelopeXML))
	tok, err := dec.Token()
	if err != nil {
		return errors.New("spqr: envelope is not valid XML")
	}
	start, ok := tok.(xml.StartElement)
	if !ok {
		return errors.New("spqr: envelope: expected start element")
	}
	if start.Name.Local != "spqr" {
		return errors.New("spqr: envelope: root element must be <spqr>")
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
		return errors.New("spqr: envelope: wrong namespace")
	}
	return nil
}

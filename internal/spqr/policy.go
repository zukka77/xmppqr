package spqr

import (
	"bytes"
	"encoding/xml"
	"errors"
)

type DomainPolicy struct {
	SPQROnlyMode bool
}

func EnforceMessagePolicy(messageXML []byte, policy DomainPolicy) error {
	if !policy.SPQROnlyMode {
		return nil
	}

	dec := xml.NewDecoder(bytes.NewReader(messageXML))
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth > 1 {
				ns := t.Name.Space
				if ns == "" {
					for _, a := range t.Attr {
						if a.Name.Local == "xmlns" {
							ns = a.Value
						}
					}
				}
				if t.Name.Local == "spqr" && ns == NSEnvelope {
					return nil
				}
			}
		case xml.EndElement:
			depth--
		}
	}
	return errors.New("<policy-violation>: SPQR-only mode requires <spqr> envelope")
}

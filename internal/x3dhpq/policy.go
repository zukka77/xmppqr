// Server is opaque transport for all x3dhpq namespaces; it does not interpret AIK signatures, DCs, audit chains, or pairing PAKE messages.
package x3dhpq

import (
	"bytes"
	"encoding/xml"
	"errors"
)

type DomainPolicy struct {
	X3DHPQOnlyMode bool
}

func EnforceMessagePolicy(messageXML []byte, policy DomainPolicy) error {
	if !policy.X3DHPQOnlyMode {
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
				if t.Name.Local == "x3dhpq" && ns == NSEnvelope {
					return nil
				}
			}
		case xml.EndElement:
			depth--
		}
	}
	return errors.New("<policy-violation>: X3DHPQ-only mode requires <x3dhpq> envelope")
}

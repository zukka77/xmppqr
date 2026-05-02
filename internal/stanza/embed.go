package stanza

import (
	"bytes"
	"encoding/xml"

	xmlstream "github.com/danielinux/xmppqr/internal/xml"
)

// EnsureClientNamespace makes sure an embedded top-level client stanza carries
// xmlns='jabber:client' so it does not inherit the surrounding wrapper
// namespace, such as urn:xmpp:forward:0.
func EnsureClientNamespace(raw []byte) []byte {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)
	rewrote := false

	for {
		tok, err := dec.RawToken()
		if err != nil {
			break
		}
		if !rewrote {
			if se, ok := tok.(xml.StartElement); ok {
				hasXMLNS := false
				for _, a := range se.Attr {
					if a.Name.Space == "" && a.Name.Local == "xmlns" {
						hasXMLNS = true
						break
					}
				}
				if !hasXMLNS && se.Name.Space == "" {
					se.Attr = append([]xml.Attr{{Name: xml.Name{Local: "xmlns"}, Value: xmlstream.NSClient}}, se.Attr...)
					tok = se
				}
				rewrote = true
			}
		}
		_ = enc.EncodeToken(tok)
	}
	_ = enc.Flush()
	if buf.Len() == 0 {
		return raw
	}
	return buf.Bytes()
}

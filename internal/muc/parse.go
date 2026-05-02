package muc

import (
	"bytes"
	"encoding/xml"
)

const (
	nsMUC      = "http://jabber.org/protocol/muc"
	nsMUCUser  = "http://jabber.org/protocol/muc#user"
	nsMUCOwner = "http://jabber.org/protocol/muc#owner"
	nsXData    = "jabber:x:data"
	nsPing     = "urn:xmpp:ping"
	nsGroup    = "urn:xmppqr:x3dhpq:group:0"
)

type joinElement struct {
	Password string
}

func parseJoinElement(raw []byte) (*joinElement, bool) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Local == "x" && se.Name.Space == nsMUC {
			je := &joinElement{}
			inner := dec
			for {
				t2, e2 := inner.Token()
				if e2 != nil {
					break
				}
				switch v := t2.(type) {
				case xml.StartElement:
					if v.Name.Local == "password" {
						var pw string
						if e3 := inner.DecodeElement(&pw, &v); e3 == nil {
							je.Password = pw
						}
					}
				case xml.EndElement:
					if v.Name.Local == "x" {
						return je, true
					}
				}
			}
			return je, true
		}
	}
	return nil, false
}

func extractSubject(raw []byte) (string, bool) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	inOuter := false
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch v := tok.(type) {
		case xml.StartElement:
			if !inOuter {
				inOuter = true
				continue
			}
			if v.Name.Local == "subject" {
				var s string
				if err2 := dec.DecodeElement(&s, &v); err2 == nil {
					return s, true
				}
			}
		}
	}
	return "", false
}

func isDiscoInfoIQ(payload []byte) bool {
	dec := xml.NewDecoder(bytes.NewReader(payload))
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Local == "query" && se.Name.Space == "http://jabber.org/protocol/disco#info" {
			return true
		}
	}
	return false
}

func isDiscoItemsIQ(payload []byte) bool {
	dec := xml.NewDecoder(bytes.NewReader(payload))
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Local == "query" && se.Name.Space == "http://jabber.org/protocol/disco#items" {
			return true
		}
	}
	return false
}

func parseAIKExtension(raw []byte) string {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Local == "aik" && se.Name.Space == nsGroup {
			for _, a := range se.Attr {
				if a.Name.Local == "fp" {
					return a.Value
				}
			}
		}
	}
	return ""
}

func isMUCOwnerIQ(payload []byte) bool {
	dec := xml.NewDecoder(bytes.NewReader(payload))
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Local == "query" && se.Name.Space == nsMUCOwner {
			return true
		}
	}
	return false
}

type ownerFormSubmit struct {
	Type   string
	Fields map[string]string
}

func parseMUCOwnerSubmit(payload []byte) (*ownerFormSubmit, bool) {
	dec := xml.NewDecoder(bytes.NewReader(payload))
	inOwner := false
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if !inOwner {
			if se.Name.Local == "query" && se.Name.Space == nsMUCOwner {
				inOwner = true
			}
			continue
		}
		if se.Name.Local == "x" && se.Name.Space == nsXData {
			form := &ownerFormSubmit{Fields: map[string]string{}}
			for _, a := range se.Attr {
				if a.Name.Local == "type" {
					form.Type = a.Value
				}
			}
			for {
				t2, e2 := dec.Token()
				if e2 != nil {
					return form, true
				}
				switch v := t2.(type) {
				case xml.StartElement:
					if v.Name.Local == "field" {
						var name string
						for _, a := range v.Attr {
							if a.Name.Local == "var" {
								name = a.Value
							}
						}
						val := readFieldValue(dec)
						if name != "" {
							form.Fields[name] = val
						}
					}
				case xml.EndElement:
					if v.Name.Local == "x" {
						return form, true
					}
				}
			}
		}
	}
	return nil, false
}

func readFieldValue(dec *xml.Decoder) string {
	for {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		switch v := tok.(type) {
		case xml.StartElement:
			if v.Name.Local == "value" {
				var s string
				if e := dec.DecodeElement(&s, &v); e == nil {
					skipToFieldEnd(dec)
					return s
				}
			}
		case xml.EndElement:
			if v.Name.Local == "field" {
				return ""
			}
		}
	}
}

func skipToFieldEnd(dec *xml.Decoder) {
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return
		}
		switch v := tok.(type) {
		case xml.StartElement:
			depth++
		case xml.EndElement:
			if depth == 0 && v.Name.Local == "field" {
				return
			}
			depth--
		}
	}
}

func isSelfPingIQ(payload []byte) bool {
	dec := xml.NewDecoder(bytes.NewReader(payload))
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Local == "ping" && se.Name.Space == nsPing {
			return true
		}
	}
	return false
}

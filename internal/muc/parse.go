package muc

import (
	"bytes"
	"encoding/xml"
)

const (
	nsMUC       = "http://jabber.org/protocol/muc"
	nsMUCUser   = "http://jabber.org/protocol/muc#user"
	nsMUCOwner  = "http://jabber.org/protocol/muc#owner"
	nsMUCAdmin  = "http://jabber.org/protocol/muc#admin"
	nsXData     = "jabber:x:data"
	nsPing      = "urn:xmpp:ping"
	nsGroup     = "urn:xmppqr:x3dhpq:group:0"
	nsMAM2      = "urn:xmpp:mam:2"
	nsPubSub    = "http://jabber.org/protocol/pubsub"
	nsPubSubOwner = "http://jabber.org/protocol/pubsub#owner"
)

// firstChildNS returns the XML namespace of the first child element of payload,
// or "" if payload is empty or not valid XML.
func firstChildNS(payload []byte) string {
	dec := xml.NewDecoder(bytes.NewReader(payload))
	for {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		if se, ok := tok.(xml.StartElement); ok {
			return se.Name.Space
		}
	}
}

// AdminItem represents one <item/> child of a muc#admin query.
type AdminItem struct {
	Affiliation string // "owner"|"admin"|"member"|"none"|"outcast"|""
	Role        string // "moderator"|"participant"|"visitor"|"none"|""
	JID         string // real bare/full JID; required for affiliation set
	Nick        string // required for role set
	Reason      string // optional <reason/> child text
	ActorJID    string // optional <actor jid='...'/> attribute
}

func isMUCAdminIQ(payload []byte) bool {
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
		if se.Name.Local == "query" && se.Name.Space == nsMUCAdmin {
			return true
		}
	}
	return false
}

func parseMUCAdminItems(payload []byte) ([]AdminItem, bool) {
	dec := xml.NewDecoder(bytes.NewReader(payload))
	inAdmin := false
	var items []AdminItem
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if !inAdmin {
			if se.Name.Local == "query" && se.Name.Space == nsMUCAdmin {
				inAdmin = true
			}
			continue
		}
		if se.Name.Local == "item" {
			item := AdminItem{}
			for _, a := range se.Attr {
				switch a.Name.Local {
				case "affiliation":
					item.Affiliation = a.Value
				case "role":
					item.Role = a.Value
				case "jid":
					item.JID = a.Value
				case "nick":
					item.Nick = a.Value
				}
			}
			// Parse child elements: <reason/> and <actor/>
			depth := 0
			for {
				t2, e2 := dec.Token()
				if e2 != nil {
					break
				}
				switch v := t2.(type) {
				case xml.StartElement:
					depth++
					switch v.Name.Local {
					case "reason":
						var s string
						if e3 := dec.DecodeElement(&s, &v); e3 == nil {
							item.Reason = s
						}
						depth-- // DecodeElement consumed the end token
					case "actor":
						for _, a := range v.Attr {
							if a.Name.Local == "jid" {
								item.ActorJID = a.Value
							}
						}
					}
				case xml.EndElement:
					depth--
					if depth < 0 {
						// End of <item/>
						goto itemDone
					}
				}
			}
		itemDone:
			items = append(items, item)
		}
	}
	return items, inAdmin
}

// MUCUserInvite is a parsed mediated-invite payload (XEP-0045 §7.8).
// Inviter sends `<message to='room'><x xmlns='muc#user'><invite to='invitee'><reason/></invite></x></message>`.
type MUCUserInvite struct {
	To     string // bare JID of invitee
	Reason string // optional human reason
	Thread string // optional <continue thread='...'/>
}

// parseMUCUserInvite extracts the first <invite/> child of <x xmlns='muc#user'>
// from a message stanza body. Returns nil if absent.
func parseMUCUserInvite(raw []byte) *MUCUserInvite {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Local != "x" || se.Name.Space != nsMUCUser {
			continue
		}
		// Inside <x xmlns='muc#user'>; look for <invite/>.
		for {
			t2, e2 := dec.Token()
			if e2 != nil {
				return nil
			}
			switch v := t2.(type) {
			case xml.StartElement:
				if v.Name.Local != "invite" {
					if err := dec.Skip(); err != nil {
						return nil
					}
					continue
				}
				inv := &MUCUserInvite{}
				for _, a := range v.Attr {
					if a.Name.Local == "to" {
						inv.To = a.Value
					}
				}
				for {
					t3, e3 := dec.Token()
					if e3 != nil {
						return inv
					}
					switch w := t3.(type) {
					case xml.StartElement:
						switch w.Name.Local {
						case "reason":
							var s string
							if e4 := dec.DecodeElement(&s, &w); e4 == nil {
								inv.Reason = s
							}
						case "continue":
							for _, a := range w.Attr {
								if a.Name.Local == "thread" {
									inv.Thread = a.Value
								}
							}
							_ = dec.Skip()
						default:
							_ = dec.Skip()
						}
					case xml.EndElement:
						if w.Name.Local == "invite" {
							return inv
						}
					}
				}
			case xml.EndElement:
				if v.Name.Local == "x" {
					return nil
				}
			}
		}
	}
}

// parseMUCUserPassword extracts the optional <password/> sibling of <invite/>
// inside <x xmlns='muc#user'>. Used when the inviter wants to convey the room
// password to the invitee.
func parseMUCUserPassword(raw []byte) string {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Local != "x" || se.Name.Space != nsMUCUser {
			continue
		}
		for {
			t2, e2 := dec.Token()
			if e2 != nil {
				return ""
			}
			switch v := t2.(type) {
			case xml.StartElement:
				if v.Name.Local == "password" {
					var s string
					if e3 := dec.DecodeElement(&s, &v); e3 == nil {
						return s
					}
				} else {
					_ = dec.Skip()
				}
			case xml.EndElement:
				if v.Name.Local == "x" {
					return ""
				}
			}
		}
	}
}

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

// ownerDestroy holds the parsed <destroy/> directive from a muc#owner IQ.
type ownerDestroy struct {
	AltJID   string // optional jid='alternative-room@conference' attribute
	Reason   string // optional <reason/> child text
	Password string // optional <password/> child text
}

// parseMUCOwnerDestroy returns the destroy directive if the muc#owner query
// contains a <destroy/> child. Returns (nil, false) if not present or malformed.
// Style mirrors parseMUCOwnerSubmit: walk tokens, find <query>, find <destroy>.
func parseMUCOwnerDestroy(payload []byte) (*ownerDestroy, bool) {
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
		if se.Name.Local == "destroy" {
			d := &ownerDestroy{}
			for _, a := range se.Attr {
				if a.Name.Local == "jid" {
					d.AltJID = a.Value
				}
			}
			// Walk children of <destroy/> for <reason/> and <password/>.
			for {
				t2, e2 := dec.Token()
				if e2 != nil {
					break
				}
				switch v := t2.(type) {
				case xml.StartElement:
					switch v.Name.Local {
					case "reason":
						var s string
						if e3 := dec.DecodeElement(&s, &v); e3 == nil {
							d.Reason = s
						}
					case "password":
						var s string
						if e3 := dec.DecodeElement(&s, &v); e3 == nil {
							d.Password = s
						}
					}
				case xml.EndElement:
					if v.Name.Local == "destroy" {
						return d, true
					}
				}
			}
			return d, true
		}
	}
	return nil, false
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

// pubsubPublishTargetsNode returns true if payload is a pubsub publish IQ
// targeting the named node.  Used to intercept node-specific policy checks
// before the IQ is delegated to the pubsub host.
func pubsubPublishTargetsNode(payload []byte, node string) bool {
	dec := xml.NewDecoder(bytes.NewReader(payload))
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Local == "publish" {
			for _, a := range se.Attr {
				if a.Name.Local == "node" {
					return a.Value == node
				}
			}
			return false
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

// isMAMQueryIQ returns true if payload contains a
// <query xmlns='urn:xmpp:mam:2'/> element, indicating a MAM archive
// query directed at a room JID.
func isMAMQueryIQ(payload []byte) bool {
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
		if se.Name.Local == "query" && se.Name.Space == nsMAM2 {
			return true
		}
	}
	return false
}

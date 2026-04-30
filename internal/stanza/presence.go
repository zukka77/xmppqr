package stanza

import (
	"bytes"
	"encoding/xml"
	"fmt"
)

const (
	PresenceSubscribe    = "subscribe"
	PresenceSubscribed   = "subscribed"
	PresenceUnsubscribe  = "unsubscribe"
	PresenceUnsubscribed = "unsubscribed"
	PresenceUnavailable  = "unavailable"
	PresenceProbe        = "probe"
	PresenceError        = "error"
)

type Presence struct {
	ID       string
	From     string
	To       string
	Type     string
	Lang     string
	Show     string
	Status   string
	Priority string
	Children []byte
}

func ParsePresence(start xml.StartElement, body []byte) (*Presence, error) {
	p := &Presence{}
	for _, a := range start.Attr {
		switch a.Name.Local {
		case "id":
			p.ID = a.Value
		case "from":
			p.From = a.Value
		case "to":
			p.To = a.Value
		case "type":
			p.Type = a.Value
		case "lang":
			p.Lang = a.Value
		}
	}

	dec := xml.NewDecoder(bytes.NewReader(body))
	var unknown bytes.Buffer
	enc := xml.NewEncoder(&unknown)
	inOuter := 0
	for {
		tok, err := dec.RawToken()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if inOuter == 0 {
				inOuter++
				continue
			}
			switch t.Name.Local {
			case "show":
				inner, ierr := innerText(dec)
				if ierr != nil {
					return nil, ierr
				}
				p.Show = inner
			case "status":
				inner, ierr := innerText(dec)
				if ierr != nil {
					return nil, ierr
				}
				p.Status = inner
			case "priority":
				inner, ierr := innerText(dec)
				if ierr != nil {
					return nil, ierr
				}
				p.Priority = inner
			default:
				enc.EncodeToken(t)
				captureInner(dec, enc)
				enc.EncodeToken(t.End())
			}
		case xml.EndElement:
			if inOuter == 1 {
				inOuter--
				continue
			}
		}
	}
	enc.Flush()
	if unknown.Len() > 0 {
		p.Children = unknown.Bytes()
	}
	return p, nil
}

func (p *Presence) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)

	start := xml.StartElement{Name: xml.Name{Local: "presence"}}
	if p.ID != "" {
		start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "id"}, Value: p.ID})
	}
	if p.From != "" {
		start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "from"}, Value: p.From})
	}
	if p.To != "" {
		start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "to"}, Value: p.To})
	}
	if p.Type != "" {
		start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "type"}, Value: p.Type})
	}

	enc.EncodeToken(start)
	if p.Show != "" {
		enc.EncodeToken(xml.StartElement{Name: xml.Name{Local: "show"}})
		enc.EncodeToken(xml.CharData(p.Show))
		enc.EncodeToken(xml.EndElement{Name: xml.Name{Local: "show"}})
	}
	if p.Status != "" {
		enc.EncodeToken(xml.StartElement{Name: xml.Name{Local: "status"}})
		enc.EncodeToken(xml.CharData(p.Status))
		enc.EncodeToken(xml.EndElement{Name: xml.Name{Local: "status"}})
	}
	if p.Priority != "" {
		enc.EncodeToken(xml.StartElement{Name: xml.Name{Local: "priority"}})
		enc.EncodeToken(xml.CharData(p.Priority))
		enc.EncodeToken(xml.EndElement{Name: xml.Name{Local: "priority"}})
	}
	if err := enc.Flush(); err != nil {
		return nil, fmt.Errorf("marshal presence: %w", err)
	}
	if len(p.Children) > 0 {
		buf.Write(p.Children)
	}
	enc.EncodeToken(start.End())
	if err := enc.Flush(); err != nil {
		return nil, fmt.Errorf("marshal presence: %w", err)
	}
	return buf.Bytes(), nil
}

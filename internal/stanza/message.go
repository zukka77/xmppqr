package stanza

import (
	"bytes"
	"encoding/xml"
	"fmt"
)

const (
	MessageChat      = "chat"
	MessageGroupchat = "groupchat"
	MessageNormal    = "normal"
	MessageHeadline  = "headline"
	MessageError     = "error"
)

type Message struct {
	ID      string
	From    string
	To      string
	Type    string
	Lang    string
	Body    string
	Subject string
	Thread  string
	Children []byte
}

func ParseMessage(start xml.StartElement, body []byte) (*Message, error) {
	m := &Message{}
	for _, a := range start.Attr {
		switch a.Name.Local {
		case "id":
			m.ID = a.Value
		case "from":
			m.From = a.Value
		case "to":
			m.To = a.Value
		case "type":
			m.Type = a.Value
		case "lang":
			m.Lang = a.Value
		}
	}

	dec := xml.NewDecoder(bytes.NewReader(body))
	// body contains full element bytes including outer tags; skip outer start/end.
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
				// outermost start element (the <message> itself)
				inOuter++
				continue
			}
			switch t.Name.Local {
			case "body":
				inner, ierr := innerText(dec)
				if ierr != nil {
					return nil, ierr
				}
				m.Body = inner
			case "subject":
				inner, ierr := innerText(dec)
				if ierr != nil {
					return nil, ierr
				}
				m.Subject = inner
			case "thread":
				inner, ierr := innerText(dec)
				if ierr != nil {
					return nil, ierr
				}
				m.Thread = inner
			default:
				// opaque child: re-encode verbatim
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
		m.Children = unknown.Bytes()
	}
	return m, nil
}

func innerText(dec *xml.Decoder) (string, error) {
	var buf bytes.Buffer
	for {
		tok, err := dec.RawToken()
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.CharData:
			buf.Write(t)
		case xml.EndElement:
			return buf.String(), nil
		case xml.StartElement:
			// skip nested elements
			captureInner(dec, nil)
		}
	}
}

func captureInner(dec *xml.Decoder, enc *xml.Encoder) {
	depth := 1
	for depth > 0 {
		tok, err := dec.RawToken()
		if err != nil {
			return
		}
		if enc != nil {
			enc.EncodeToken(tok)
		}
		switch tok.(type) {
		case xml.StartElement:
			depth++
		case xml.EndElement:
			depth--
		}
	}
}

func (m *Message) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)

	start := xml.StartElement{Name: xml.Name{Local: "message"}}
	if m.ID != "" {
		start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "id"}, Value: m.ID})
	}
	if m.From != "" {
		start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "from"}, Value: m.From})
	}
	if m.To != "" {
		start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "to"}, Value: m.To})
	}
	if m.Type != "" {
		start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "type"}, Value: m.Type})
	}
	if m.Lang != "" {
		start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "xml:lang"}, Value: m.Lang})
	}

	enc.EncodeToken(start)

	if m.Subject != "" {
		enc.EncodeToken(xml.StartElement{Name: xml.Name{Local: "subject"}})
		enc.EncodeToken(xml.CharData(m.Subject))
		enc.EncodeToken(xml.EndElement{Name: xml.Name{Local: "subject"}})
	}
	if m.Body != "" {
		enc.EncodeToken(xml.StartElement{Name: xml.Name{Local: "body"}})
		enc.EncodeToken(xml.CharData(m.Body))
		enc.EncodeToken(xml.EndElement{Name: xml.Name{Local: "body"}})
	}
	if m.Thread != "" {
		enc.EncodeToken(xml.StartElement{Name: xml.Name{Local: "thread"}})
		enc.EncodeToken(xml.CharData(m.Thread))
		enc.EncodeToken(xml.EndElement{Name: xml.Name{Local: "thread"}})
	}

	if err := enc.Flush(); err != nil {
		return nil, fmt.Errorf("marshal message: %w", err)
	}

	if len(m.Children) > 0 {
		buf.Write(m.Children)
	}

	enc.EncodeToken(start.End())
	if err := enc.Flush(); err != nil {
		return nil, fmt.Errorf("marshal message: %w", err)
	}
	return buf.Bytes(), nil
}

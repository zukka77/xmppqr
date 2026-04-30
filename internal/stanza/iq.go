package stanza

import (
	"bytes"
	"encoding/xml"
	"fmt"
)

const (
	IQGet    = "get"
	IQSet    = "set"
	IQResult = "result"
	IQError  = "error"
)

type IQ struct {
	ID      string
	From    string
	To      string
	Type    string
	Lang    string
	Payload []byte
}

func ParseIQ(start xml.StartElement, body []byte) (*IQ, error) {
	iq := &IQ{}
	for _, a := range start.Attr {
		switch a.Name.Local {
		case "id":
			iq.ID = a.Value
		case "from":
			iq.From = a.Value
		case "to":
			iq.To = a.Value
		case "type":
			iq.Type = a.Value
		case "lang":
			iq.Lang = a.Value
		}
	}

	// Extract inner bytes (everything between outer start and end tags).
	dec := xml.NewDecoder(bytes.NewReader(body))
	var payload bytes.Buffer
	enc := xml.NewEncoder(&payload)
	depth := 0
	for {
		tok, err := dec.RawToken()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 1 {
				continue
			}
			enc.EncodeToken(t)
		case xml.EndElement:
			if depth == 1 {
				depth--
				continue
			}
			depth--
			enc.EncodeToken(t)
		case xml.CharData:
			if depth > 0 {
				enc.EncodeToken(t)
			}
		}
	}
	enc.Flush()
	if payload.Len() > 0 {
		iq.Payload = payload.Bytes()
	}
	return iq, nil
}

func (iq *IQ) IsResponse() bool {
	return iq.Type == IQResult || iq.Type == IQError
}

func (iq *IQ) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)

	start := xml.StartElement{Name: xml.Name{Local: "iq"}}
	if iq.ID != "" {
		start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "id"}, Value: iq.ID})
	}
	if iq.From != "" {
		start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "from"}, Value: iq.From})
	}
	if iq.To != "" {
		start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "to"}, Value: iq.To})
	}
	if iq.Type != "" {
		start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "type"}, Value: iq.Type})
	}

	enc.EncodeToken(start)
	if err := enc.Flush(); err != nil {
		return nil, fmt.Errorf("marshal iq: %w", err)
	}
	if len(iq.Payload) > 0 {
		buf.Write(iq.Payload)
	}
	enc.EncodeToken(start.End())
	if err := enc.Flush(); err != nil {
		return nil, fmt.Errorf("marshal iq: %w", err)
	}
	return buf.Bytes(), nil
}

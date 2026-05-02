package pubsub

import (
	"encoding/xml"
	"io"
	"strings"
)

const (
	nsPubSub = "http://jabber.org/protocol/pubsub"
)

type rawItem struct {
	ID      string
	Payload []byte
}

type pubsubRequest struct {
	op      string
	node    string
	items   []rawItem
	itemID  string
	max     int
	subJID  string
}

func parseRequest(payload []byte) (*pubsubRequest, error) {
	dec := xml.NewDecoder(strings.NewReader(string(payload)))
	req := &pubsubRequest{}

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}

		switch se.Name.Local {
		case "pubsub":
			// outer wrapper; continue
		case "publish":
			req.op = "publish"
			req.node = attrVal(se, "node")
			if err := parsePublishItems(dec, req); err != nil {
				return nil, err
			}
		case "retract":
			req.op = "retract"
			req.node = attrVal(se, "node")
			if err := parseRetractItems(dec, req); err != nil {
				return nil, err
			}
		case "items":
			req.op = "items"
			req.node = attrVal(se, "node")
			req.max = attrInt(se, "max_items")
			if err := parseRequestedItems(dec, req); err != nil {
				return nil, err
			}
		case "subscribe":
			req.op = "subscribe"
			req.node = attrVal(se, "node")
			req.subJID = attrVal(se, "jid")
		case "unsubscribe":
			req.op = "unsubscribe"
			req.node = attrVal(se, "node")
			req.subJID = attrVal(se, "jid")
		case "create":
			req.op = "create"
			req.node = attrVal(se, "node")
		case "delete":
			req.op = "delete"
			req.node = attrVal(se, "node")
		}
	}
	return req, nil
}

func parsePublishItems(dec *xml.Decoder, req *pubsubRequest) error {
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "item" {
				id := attrVal(t, "id")
				payload, err := captureInnerXML(dec)
				if err != nil {
					return err
				}
				req.items = append(req.items, rawItem{ID: id, Payload: payload})
			}
		case xml.EndElement:
			if t.Name.Local == "publish" {
				return nil
			}
		}
	}
}

func parseRetractItems(dec *xml.Decoder, req *pubsubRequest) error {
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "item" {
				req.itemID = attrVal(t, "id")
				dec.Skip()
			}
		case xml.EndElement:
			if t.Name.Local == "retract" {
				return nil
			}
		}
	}
}

func parseRequestedItems(dec *xml.Decoder, req *pubsubRequest) error {
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "item" && req.itemID == "" {
				req.itemID = attrVal(t, "id")
			}
			if err := dec.Skip(); err != nil {
				return err
			}
		case xml.EndElement:
			if t.Name.Local == "items" {
				return nil
			}
		}
	}
}

func captureInnerXML(dec *xml.Decoder) ([]byte, error) {
	var buf strings.Builder
	enc := xml.NewEncoder(&buf)
	depth := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			enc.EncodeToken(t)
		case xml.EndElement:
			if depth == 0 {
				enc.Flush()
				b := buf.String()
				if b == "" {
					return nil, nil
				}
				return []byte(b), nil
			}
			depth--
			enc.EncodeToken(t)
		case xml.CharData:
			enc.EncodeToken(t)
		}
	}
	enc.Flush()
	b := buf.String()
	if b == "" {
		return nil, nil
	}
	return []byte(b), nil
}

func attrVal(se xml.StartElement, name string) string {
	for _, a := range se.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func attrInt(se xml.StartElement, name string) int {
	v := attrVal(se, name)
	if v == "" {
		return 0
	}
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

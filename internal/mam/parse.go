package mam

import (
	"bytes"
	"encoding/xml"
	"time"
)

const (
	nsMAM  = "urn:xmpp:mam:2"
	nsRSM  = "http://jabber.org/protocol/rsm"
	nsData = "jabber:x:data"
)

type queryFilter struct {
	withJID string
	start   *time.Time
	end     *time.Time
	queryID string
}

type rsmSet struct {
	max    int
	before *string
	after  *string
	index  *int
	last   bool
}

type parsedQuery struct {
	filter queryFilter
	rsm    rsmSet
}

func attrNS(attrs []xml.Attr, local string) string {
	for _, a := range attrs {
		if a.Name.Local == local && (a.Name.Space == "xmlns" || a.Name.Space == "") {
			return a.Value
		}
	}
	return ""
}

func elemNS(t xml.StartElement) string {
	// xml.Token() resolves namespaces into Space.
	return t.Name.Space
}

func parseQueryPayload(payload []byte) (*parsedQuery, error) {
	pq := &parsedQuery{}
	pq.rsm.max = -1

	dec := xml.NewDecoder(bytes.NewReader(payload))
	// Use Token (not RawToken) so namespace resolution works.
	var inQuery, inX, inRSM bool
	var currentField string

	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case t.Name.Local == "query" && elemNS(t) == nsMAM:
				inQuery = true
				for _, a := range t.Attr {
					if a.Name.Local == "queryid" {
						pq.filter.queryID = a.Value
					}
				}
			case inQuery && t.Name.Local == "x" && elemNS(t) == nsData:
				inX = true
			case inX && t.Name.Local == "field":
				for _, a := range t.Attr {
					if a.Name.Local == "var" {
						currentField = a.Value
					}
				}
			case inX && t.Name.Local == "value":
				var val string
				dec.DecodeElement(&val, &t)
				switch currentField {
				case "with":
					pq.filter.withJID = val
				case "start":
					ts, err := time.Parse(time.RFC3339, val)
					if err == nil {
						pq.filter.start = &ts
					}
				case "end":
					ts, err := time.Parse(time.RFC3339, val)
					if err == nil {
						pq.filter.end = &ts
					}
				}
				currentField = ""
				continue
			case inQuery && t.Name.Local == "set" && elemNS(t) == nsRSM:
				inRSM = true
			case inRSM && t.Name.Local == "max":
				var v int
				dec.DecodeElement(&v, &t)
				pq.rsm.max = v
				continue
			case inRSM && t.Name.Local == "before":
				var v string
				dec.DecodeElement(&v, &t)
				pq.rsm.before = &v
				continue
			case inRSM && t.Name.Local == "after":
				var v string
				dec.DecodeElement(&v, &t)
				pq.rsm.after = &v
				continue
			case inRSM && t.Name.Local == "last":
				pq.rsm.last = true
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "query":
				inQuery = false
			case "x":
				inX = false
			case "set":
				inRSM = false
			case "field":
				currentField = ""
			}
		}
	}
	return pq, nil
}

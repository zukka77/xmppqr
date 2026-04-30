package roster

import (
	"encoding/xml"

	"github.com/danielinux/xmppqr/internal/stanza"
)

func ParsePresenceFromTo(raw []byte) (from, to stanza.JID, type_ string, err error) {
	dec := xml.NewDecoder(bytesReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return
	}
	se, ok := tok.(xml.StartElement)
	if !ok {
		err = errMissingFrom
		return
	}
	var fromStr, toStr string
	for _, a := range se.Attr {
		switch a.Name.Local {
		case "from":
			fromStr = a.Value
		case "to":
			toStr = a.Value
		case "type":
			type_ = a.Value
		}
	}
	if fromStr == "" {
		err = errMissingFrom
		return
	}
	if toStr == "" {
		err = errMissingTo
		return
	}
	from, err = stanza.Parse(fromStr)
	if err != nil {
		return
	}
	to, err = stanza.Parse(toStr)
	return
}

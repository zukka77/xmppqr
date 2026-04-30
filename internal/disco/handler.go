package disco

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"

	"github.com/danielinux/xmppqr/internal/stanza"
)

const (
	nsDiscoInfo  = "http://jabber.org/protocol/disco#info"
	nsDiscoItems = "http://jabber.org/protocol/disco#items"
)

func HandleDiscoInfo(iq *stanza.IQ, f *Features) ([]byte, error) {
	if iq.Type != stanza.IQGet {
		return nil, errors.New("disco: not a get")
	}
	node, err := queryNode(iq.Payload, nsDiscoInfo)
	if err != nil {
		return nil, err
	}
	result := &stanza.IQ{
		ID:      iq.ID,
		From:    iq.To,
		To:      iq.From,
		Type:    stanza.IQResult,
		Payload: f.MarshalDiscoInfo(node),
	}
	return result.Marshal()
}

func HandleDiscoItems(iq *stanza.IQ, items ...string) ([]byte, error) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "<query xmlns='%s'>", nsDiscoItems)
	for _, jid := range items {
		fmt.Fprintf(&sb, "<item jid='%s'/>", escapeAttr(jid))
	}
	sb.WriteString("</query>")
	result := &stanza.IQ{
		ID:      iq.ID,
		From:    iq.To,
		To:      iq.From,
		Type:    stanza.IQResult,
		Payload: []byte(sb.String()),
	}
	return result.Marshal()
}

func queryNode(payload []byte, ns string) (string, error) {
	if len(payload) == 0 {
		return "", nil
	}
	dec := xml.NewDecoder(bytesReader(payload))
	tok, err := dec.Token()
	if err != nil {
		return "", nil
	}
	se, ok := tok.(xml.StartElement)
	if !ok {
		return "", nil
	}
	if se.Name.Space != ns && se.Name.Local != "query" {
		return "", nil
	}
	for _, a := range se.Attr {
		if a.Name.Local == "node" {
			return a.Value, nil
		}
	}
	return "", nil
}

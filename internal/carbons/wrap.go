package carbons

import (
	"bytes"
	"encoding/xml"

	"github.com/danielinux/xmppqr/internal/stanza"
)

const (
	nsCarbons = "urn:xmpp:carbons:2"
	nsForward  = "urn:xmpp:forward:0"
)

func (m *Manager) WrapReceived(ownerFull stanza.JID, _ stanza.JID, original []byte) []byte {
	return wrapCarbon(ownerFull.String(), "received", original)
}

func (m *Manager) WrapSent(ownerFull stanza.JID, _ stanza.JID, original []byte) []byte {
	return wrapCarbon(ownerFull.String(), "sent", original)
}

func wrapCarbon(to, direction string, original []byte) []byte {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)

	msgStart := xml.StartElement{
		Name: xml.Name{Local: "message"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "to"}, Value: to},
		},
	}
	enc.EncodeToken(msgStart)

	dirStart := xml.StartElement{
		Name: xml.Name{Local: direction},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "xmlns"}, Value: nsCarbons},
		},
	}
	enc.EncodeToken(dirStart)

	fwdStart := xml.StartElement{
		Name: xml.Name{Local: "forwarded"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "xmlns"}, Value: nsForward},
		},
	}
	enc.EncodeToken(fwdStart)
	enc.Flush()

	buf.Write(stanza.EnsureClientNamespace(original))

	enc.EncodeToken(fwdStart.End())
	enc.EncodeToken(dirStart.End())
	enc.EncodeToken(msgStart.End())
	enc.Flush()

	return buf.Bytes()
}

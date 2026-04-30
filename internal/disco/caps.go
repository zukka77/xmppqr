package disco

import "fmt"

const discoNode = "https://xmppqr.org/caps"

func DiscoNode() string {
	return discoNode
}

func CapsElement(f *Features) []byte {
	ver := f.VerHash()
	return []byte(fmt.Sprintf(
		`<c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='%s' ver='%s'/>`,
		escapeAttr(discoNode), escapeAttr(ver),
	))
}

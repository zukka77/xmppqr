// Package disco implements XEP-0030 service discovery and XEP-0115 entity caps.
package disco

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

type Identity struct {
	Category string
	Type     string
	Name     string
	Lang     string
}

type Features struct {
	Categories []Identity
	Vars       []string
}

func DefaultServer() *Features {
	return &Features{
		Categories: []Identity{
			{Category: "server", Type: "im", Name: "xmppqr"},
		},
		Vars: []string{
			"urn:xmpp:ping",
			"urn:xmpp:carbons:2",
			"urn:xmpp:mam:2",
			"urn:xmpp:sm:3",
			"urn:xmpp:csi:0",
			"urn:xmpp:bind:0",
			"urn:xmpp:sasl:2",
			"urn:xmpp:push:0",
			"http://jabber.org/protocol/disco#info",
			"http://jabber.org/protocol/disco#items",
			"http://jabber.org/protocol/pubsub",
			"urn:xmpp:blocking",
			"vcard-temp",
			"urn:xmppqr:x3dhpq:0",
			"urn:ietf:params:xml:ns:xmpp-session",
			"jabber:iq:version",
			"jabber:iq:last",
			"urn:xmpp:time",
		},
	}
}

func (f *Features) MarshalDiscoInfo(node string) []byte {
	var sb strings.Builder
	if node != "" {
		fmt.Fprintf(&sb, "<query xmlns='http://jabber.org/protocol/disco#info' node='%s'>", escapeAttr(node))
	} else {
		sb.WriteString("<query xmlns='http://jabber.org/protocol/disco#info'>")
	}
	for _, id := range f.Categories {
		fmt.Fprintf(&sb, "<identity category='%s' type='%s' name='%s'",
			escapeAttr(id.Category), escapeAttr(id.Type), escapeAttr(id.Name))
		if id.Lang != "" {
			fmt.Fprintf(&sb, " xml:lang='%s'", escapeAttr(id.Lang))
		}
		sb.WriteString("/>")
	}
	for _, v := range f.Vars {
		fmt.Fprintf(&sb, "<feature var='%s'/>", escapeAttr(v))
	}
	sb.WriteString("</query>")
	return []byte(sb.String())
}

// VerHash computes the XEP-0115 ver hash per §5.1.
func (f *Features) VerHash() string {
	var sb strings.Builder

	// Sort identities: category/type/lang/name
	ids := make([]Identity, len(f.Categories))
	copy(ids, f.Categories)
	sort.Slice(ids, func(i, j int) bool {
		a, b := ids[i], ids[j]
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Lang != b.Lang {
			return a.Lang < b.Lang
		}
		return a.Name < b.Name
	})
	for _, id := range ids {
		fmt.Fprintf(&sb, "%s/%s/%s/%s<", id.Category, id.Type, id.Lang, id.Name)
	}

	vars := make([]string, len(f.Vars))
	copy(vars, f.Vars)
	sort.Strings(vars)
	for _, v := range vars {
		sb.WriteString(v)
		sb.WriteByte('<')
	}

	sum := wolfcrypt.SHA1([]byte(sb.String()))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func escapeAttr(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

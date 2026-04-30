package c2s

import (
	"fmt"
	"strings"

	"github.com/danielinux/xmppqr/internal/auth"
)

const (
	nsSASL2    = "urn:xmpp:sasl:2"
	nsBind2    = "urn:xmpp:bind:0"
	nsSM       = "urn:xmpp:sm:3"
	nsCSI      = "urn:xmpp:csi:0"
	nsSASL     = "urn:ietf:params:xml:ns:xmpp-sasl"
	nsDowngrade = "urn:xmpp:sasl-channel-binding:0"
	nsStream    = "http://etherx.jabber.org/streams"
	nsStreamErr = "http://etherx.jabber.org/streams"
)

var preferredMechs = []string{
	string(auth.SCRAMSHA512Plus),
	string(auth.SCRAMSHA256Plus),
	string(auth.SCRAMSHA512),
	string(auth.SCRAMSHA256),
}

var legacyMechs = []string{
	string(auth.SCRAMSHA512Plus),
	string(auth.SCRAMSHA256Plus),
	string(auth.SCRAMSHA512),
	string(auth.SCRAMSHA256),
	string(auth.Plain),
}

func buildFeatures(s *Session, sasl bool, bind bool) []byte {
	var b strings.Builder
	b.WriteString(`<stream:features>`)

	if sasl {
		b.WriteString(fmt.Sprintf(`<mechanisms xmlns='%s'>`, nsSASL))
		for _, m := range legacyMechs {
			b.WriteString(fmt.Sprintf(`<mechanism>%s</mechanism>`, m))
		}
		b.WriteString(`</mechanisms>`)
	}

	if bind {
		b.WriteString(fmt.Sprintf(`<bind xmlns='%s'/>`, nsBind2))
		b.WriteString(fmt.Sprintf(`<sm xmlns='%s'/>`, nsSM))
		b.WriteString(fmt.Sprintf(`<csi xmlns='%s'/>`, nsCSI))
	}

	b.WriteString(`</stream:features>`)
	return []byte(b.String())
}

func buildLegacyPostAuthFeatures() []byte {
	var b strings.Builder
	b.WriteString(`<stream:features>`)
	b.WriteString(`<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>`)
	b.WriteString(fmt.Sprintf(`<sm xmlns='%s'/>`, nsSM))
	b.WriteString(fmt.Sprintf(`<csi xmlns='%s'/>`, nsCSI))
	b.WriteString(`</stream:features>`)
	return []byte(b.String())
}

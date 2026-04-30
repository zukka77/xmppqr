package c2s

import (
	"encoding/base64"
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

func buildFeatures(s *Session, sasl bool, bind bool) []byte {
	var b strings.Builder
	b.WriteString(`<stream:features>`)

	if sasl {
		// XEP-0388 SASL2
		b.WriteString(fmt.Sprintf(`<authentication xmlns='%s'>`, nsSASL2))
		for _, m := range preferredMechs {
			b.WriteString(fmt.Sprintf(`<mechanism>%s</mechanism>`, m))
		}
		// XEP-0474 downgrade protection
		hash := auth.ComputeMechanismListHash(preferredMechs)
		hashB64 := base64.StdEncoding.EncodeToString(hash)
		b.WriteString(fmt.Sprintf(`<inline><mechanisms xmlns='%s'><mechanism>%s</mechanism></mechanisms></inline>`,
			nsDowngrade, hashB64))
		b.WriteString(`</authentication>`)

		// Classical XEP-0086 SASL <mechanisms>
		b.WriteString(fmt.Sprintf(`<mechanisms xmlns='%s'>`, nsSASL))
		for _, m := range preferredMechs {
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

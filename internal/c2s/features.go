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
	// XEP-0440 channel-binding type capability advertisement.
	// The session is always TLS-wrapped so tls-exporter is unconditionally available.
	nsSASLCB = "urn:xmpp:sasl-cb:0"
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

		// XEP-0440: announce which channel-binding types we accept so SCRAM-PLUS
		// clients know what to feed into their auth proof. Without this, modern
		// clients (Conversations) fall through to a "guess" path and the SCRAM
		// proof's channel-binding bytes mismatch what the server computes,
		// producing not-authorized.
		b.WriteString(fmt.Sprintf(`<sasl-channel-binding xmlns='%s'>`, nsSASLCB))
		b.WriteString(`<channel-binding type='tls-exporter'/>`)
		b.WriteString(`</sasl-channel-binding>`)
	}

	if bind {
		b.WriteString(fmt.Sprintf(`<bind xmlns='%s'/>`, nsBind2))
		b.WriteString(fmt.Sprintf(`<sm xmlns='%s'/>`, nsSM))
		b.WriteString(fmt.Sprintf(`<csi xmlns='%s'/>`, nsCSI))
	}

	if s.cfg.Modules != nil && s.cfg.Modules.IBR != nil && s.cfg.Modules.IBR.Allowed() {
		b.WriteString(`<register xmlns='http://jabber.org/features/iq-register'/>`)
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

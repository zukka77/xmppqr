package c2s

import (
	"context"
	"encoding/base32"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/danielinux/xmppqr/internal/sm"
	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

// handleBind2 processes the bind element (inline in authenticate or standalone).
// It sets s.jid and optionally enables SM and CSI.
// Returns the XML to inline in the success/bound response.
func handleBind2(ctx context.Context, s *Session, bindRaw []byte) (string, error) {
	tag, smEnable, csiActive := parseBind2(bindRaw)

	resource := tag
	if resource == "" {
		resource = randomResource()
	}

	s.jid = stanza.JID{
		Local:    s.jid.Local,
		Domain:   s.cfg.Domain,
		Resource: resource,
	}

	var extras strings.Builder

	if smEnable {
		q := sm.New(512)
		s.smQueue = q
		if s.cfg.ResumeStore != nil {
			tok, err := s.cfg.ResumeStore.Issue(ctx, s.jid)
			if err == nil {
				extras.WriteString(fmt.Sprintf(`<enabled xmlns='%s' resume='true' id='%s'/>`, nsSM, string(tok)))
			}
		} else {
			extras.WriteString(fmt.Sprintf(`<enabled xmlns='%s'/>`, nsSM))
		}
	}

	if csiActive {
		s.csiF.SetActive(true)
	}

	return extras.String(), nil
}

func parseBind2(raw []byte) (tag string, smEnable bool, csiActive bool) {
	dec := xml.NewDecoder(strings.NewReader(string(raw)))
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 2 && t.Name.Local == "tag" {
				var text string
				if err2 := dec.DecodeElement(&text, &t); err2 == nil {
					tag = strings.TrimSpace(text)
				}
				depth-- // DecodeElement consumed end token
			}
			if t.Name.Local == "enable" && t.Name.Space == nsSM {
				smEnable = true
			}
			if t.Name.Local == "active" && t.Name.Space == nsCSI {
				csiActive = true
			}
		case xml.EndElement:
			depth--
		}
	}
	return
}

func randomResource() string {
	b := make([]byte, 10)
	_, _ = wolfcrypt.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

func sendBound(s *Session, fullJID string, extras string) error {
	msg := fmt.Sprintf(`<bound xmlns='%s'><jid>%s</jid>%s</bound>`, nsBind2, fullJID, extras)
	_, err := s.enc.WriteRaw([]byte(msg))
	return err
}

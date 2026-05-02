// Package pep implements XEP-0163 Personal Eventing Protocol by layering on pubsub.Service.
package pep

import (
	"bytes"
	"context"
	"encoding/xml"
	"log/slog"

	"github.com/danielinux/xmppqr/internal/pubsub"
	"github.com/danielinux/xmppqr/internal/stanza"
)

type Service struct {
	ps     *pubsub.Service
	logger *slog.Logger
}

func New(ps *pubsub.Service, logger *slog.Logger) *Service {
	return &Service{ps: ps, logger: logger}
}

func (svc *Service) HandleIQ(ctx context.Context, from stanza.JID, iq *stanza.IQ) ([]byte, error) {
	target := from.Bare()
	if iq.To != "" {
		j, err := stanza.Parse(iq.To)
		if err != nil {
			return nil, &stanza.StanzaError{Type: stanza.ErrorTypeModify, Condition: stanza.ErrJIDMalformed}
		}
		target = j.Bare()
		if iq.Type != stanza.IQGet && target.String() != from.Bare().String() {
			se := &stanza.StanzaError{Type: stanza.ErrorTypeAuth, Condition: stanza.ErrForbidden}
			errBytes, err := se.Marshal()
			if err != nil {
				return nil, err
			}
			resp := &stanza.IQ{
				ID:      iq.ID,
				From:    iq.To,
				To:      iq.From,
				Type:    stanza.IQError,
				Payload: errBytes,
			}
			return resp.Marshal()
		}
	}

	// Auto-create node on publish if it doesn't exist yet.
	if node := publishNode(iq.Payload); node != "" {
		if err := svc.ps.EnsureNode(ctx, from.Bare(), node); err != nil {
			svc.logger.Error("pep ensure node", "err", err)
		}
	}

	return svc.ps.HandleIQ(ctx, target, iq)
}

// publishNode extracts the node attribute from a publish element in the payload,
// returning "" if the payload is not a publish operation.
func publishNode(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	dec := xml.NewDecoder(bytes.NewReader(payload))
	for {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Local == "publish" {
			for _, a := range se.Attr {
				if a.Name.Local == "node" {
					return a.Value
				}
			}
			return ""
		}
	}
}

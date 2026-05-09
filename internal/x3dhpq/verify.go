package x3dhpq

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"log/slog"

	"github.com/danielinux/xmppqr/internal/stanza"
)

// Router is the subset of router.Router used by VerifyDevice. Defined here to
// avoid an import cycle (internal/router → internal/x3dhpq is undesirable; the
// other direction is fine but pulls c2s alongside it). The c2s module wires
// the real router in.
type Router interface {
	SessionsFor(bareJID string) []RouterSession
	RouteToFull(ctx context.Context, full stanza.JID, raw []byte) error
}

// RouterSession mirrors router.Session so callers can pass the real type
// without forcing this package to import router.
type RouterSession interface {
	JID() stanza.JID
}

// VerifyDevice handles the project-internal `<verify-device>` IQ-set sent by a
// freshly-bound resource to ask the server to fan out a headline message to
// the user's other authenticated resources, prompting them to start a pairing
// flow with the new resource. The server never inspects pairing payload bytes;
// this verb only relays addressing information.
type VerifyDevice struct {
	router Router
	limit  *PairLimiter
	logger *slog.Logger
}

func NewVerifyDevice(router Router, limit *PairLimiter, logger *slog.Logger) *VerifyDevice {
	return &VerifyDevice{router: router, limit: limit, logger: logger}
}

// HandleIQ processes a `<verify-device>` IQ-set. The caller MUST have already
// authenticated `from` (which must equal the originator session's full JID).
// On success it returns a marshalled IQ result with a `<peers count='N'/>`
// child. On policy failure it returns a stanza.StanzaError as the err return.
func (v *VerifyDevice) HandleIQ(ctx context.Context, from stanza.JID, iq *stanza.IQ) ([]byte, error) {
	if iq.Type != stanza.IQSet {
		return nil, &stanza.StanzaError{Type: stanza.ErrorTypeCancel, Condition: stanza.ErrFeatureNotImplemented}
	}
	if from.Resource == "" {
		return nil, &stanza.StanzaError{Type: stanza.ErrorTypeAuth, Condition: stanza.ErrForbidden, Text: "verify-device requires a full JID"}
	}
	if iq.To != "" {
		toJID, err := stanza.Parse(iq.To)
		if err != nil {
			return nil, &stanza.StanzaError{Type: stanza.ErrorTypeModify, Condition: stanza.ErrJIDMalformed}
		}
		if !toJID.Bare().Equal(from.Bare()) {
			return nil, &stanza.StanzaError{Type: stanza.ErrorTypeAuth, Condition: stanza.ErrForbidden}
		}
	}

	deviceID, ok := parseVerifyDeviceID(iq.Payload)
	if !ok {
		return nil, &stanza.StanzaError{Type: stanza.ErrorTypeModify, Condition: stanza.ErrBadRequest, Text: "verify-device: missing or malformed device-id"}
	}

	if v.limit != nil && !v.limit.AllowVerify(from.String()) {
		return nil, &stanza.StanzaError{Type: stanza.ErrorTypeWait, Condition: stanza.ErrPolicyViolation, Text: "verify-device rate limit"}
	}

	bare := from.Bare()
	sessions := v.router.SessionsFor(bare.String())

	peers := make([]stanza.JID, 0, len(sessions))
	for _, s := range sessions {
		j := s.JID()
		if j.Equal(from) {
			continue
		}
		peers = append(peers, j)
	}

	if len(peers) == 0 {
		return nil, &stanza.StanzaError{Type: stanza.ErrorTypeCancel, Condition: stanza.ErrNotAcceptable, Text: "no peer resources"}
	}

	for _, peer := range peers {
		body := buildVerifyHeadline(bare, peer, from, deviceID, iq.ID)
		if err := v.router.RouteToFull(ctx, peer, body); err != nil && v.logger != nil {
			v.logger.Warn("verify-device fan-out failed", "to", peer.String(), "err", err)
		}
	}

	resultPayload := fmt.Sprintf(`<peers xmlns='%s' count='%d'/>`, NSPair, len(peers))
	result := &stanza.IQ{
		ID:      iq.ID,
		From:    bare.String(),
		To:      from.String(),
		Type:    stanza.IQResult,
		Payload: []byte(resultPayload),
	}
	return result.Marshal()
}

func parseVerifyDeviceID(payload []byte) (string, bool) {
	if len(payload) == 0 {
		return "", false
	}
	dec := xml.NewDecoder(bytes.NewReader(payload))
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", false
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		ns := se.Name.Space
		if ns == "" {
			for _, a := range se.Attr {
				if a.Name.Local == "xmlns" {
					ns = a.Value
				}
			}
		}
		if se.Name.Local != ElemVerifyDevice || ns != NSPair {
			return "", false
		}
		for _, a := range se.Attr {
			if a.Name.Local == "device-id" && a.Value != "" {
				return a.Value, true
			}
		}
		return "", false
	}
}

func buildVerifyHeadline(from, to, newResource stanza.JID, deviceID, correlationID string) []byte {
	idAttr := ""
	if correlationID != "" {
		idAttr = fmt.Sprintf(` id='%s'`, xmlAttrEscape(correlationID))
	}
	return []byte(fmt.Sprintf(
		`<message type='headline' from='%s' to='%s'%s><verify-device xmlns='%s' new-resource='%s' device-id='%s'/></message>`,
		xmlAttrEscape(from.String()),
		xmlAttrEscape(to.String()),
		idAttr,
		NSPair,
		xmlAttrEscape(newResource.String()),
		xmlAttrEscape(deviceID),
	))
}

func xmlAttrEscape(s string) string {
	var buf bytes.Buffer
	xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

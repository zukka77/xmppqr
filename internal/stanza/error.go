package stanza

import (
	"bytes"
	"encoding/xml"
	"fmt"
)

const (
	ErrorTypeAuth     = "auth"
	ErrorTypeCancel   = "cancel"
	ErrorTypeContinue = "continue"
	ErrorTypeModify   = "modify"
	ErrorTypeWait     = "wait"

	ErrBadRequest            = "bad-request"
	ErrConflict              = "conflict"
	ErrFeatureNotImplemented = "feature-not-implemented"
	ErrForbidden             = "forbidden"
	ErrInternalServerError   = "internal-server-error"
	ErrItemNotFound          = "item-not-found"
	ErrJIDMalformed          = "jid-malformed"
	ErrNotAcceptable         = "not-acceptable"
	ErrNotAuthorized         = "not-authorized"
	ErrPolicyViolation       = "policy-violation"
	ErrServiceUnavailable    = "service-unavailable"
	ErrRecipientUnavailable  = "recipient-unavailable"
	ErrRemoteServerNotFound  = "remote-server-not-found"
	ErrRemoteServerTimeout   = "remote-server-timeout"
	ErrResourceConstraint    = "resource-constraint"
	ErrUnexpectedRequest     = "unexpected-request"
)

const nsStanzaError = "urn:ietf:params:xml:ns:xmpp-stanzas"

type StanzaError struct {
	Type      string
	Condition string
	Text      string
	By        JID
}

func (e *StanzaError) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)

	errStart := xml.StartElement{
		Name: xml.Name{Local: "error"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "type"}, Value: e.Type},
		},
	}
	if !e.By.Equal((JID{})) {
		errStart.Attr = append(errStart.Attr, xml.Attr{
			Name:  xml.Name{Local: "by"},
			Value: e.By.String(),
		})
	}
	enc.EncodeToken(errStart)

	if e.Condition != "" {
		cond := xml.StartElement{Name: xml.Name{Space: nsStanzaError, Local: e.Condition}}
		enc.EncodeToken(cond)
		enc.EncodeToken(cond.End())
	}

	if e.Text != "" {
		textEl := xml.StartElement{Name: xml.Name{Space: nsStanzaError, Local: "text"}}
		enc.EncodeToken(textEl)
		enc.EncodeToken(xml.CharData(e.Text))
		enc.EncodeToken(textEl.End())
	}

	enc.EncodeToken(errStart.End())
	if err := enc.Flush(); err != nil {
		return nil, fmt.Errorf("marshal stanza error: %w", err)
	}
	return buf.Bytes(), nil
}

func (e *StanzaError) Error() string {
	return fmt.Sprintf("xmpp stanza error: type=%s condition=%s", e.Type, e.Condition)
}

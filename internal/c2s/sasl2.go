package c2s

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/danielinux/xmppqr/internal/auth"
	"github.com/danielinux/xmppqr/internal/storage"
)

type authStyle int

const (
	authStyleSASL2 authStyle = iota
	authStyleLegacy
)

type authResult struct {
	Username    string
	ServerFinal []byte
	Style       authStyle
}

type tlsExporterCB struct {
	conn    tlsConnIface
	cbType  string
}

func (cb *tlsExporterCB) Type() string { return cb.cbType }
func (cb *tlsExporterCB) Data() []byte {
	data, err := cb.conn.Exporter("exporter", nil, 32)
	if err != nil {
		return nil
	}
	return data
}

// handleAuthenticate drives SASL2 authentication.
// Returns the authenticated username on success, or an error.
func handleAuthenticate(ctx context.Context, s *Session, start xml.StartElement, raw []byte) (*authResult, error) {
	mechName := ""
	for _, a := range start.Attr {
		if a.Name.Local == "mechanism" {
			mechName = a.Value
			break
		}
	}

	mech := auth.Mechanism(mechName)
	var cb auth.ChannelBinding
	switch mech {
	case auth.SCRAMSHA256Plus, auth.SCRAMSHA512Plus:
		cb = &tlsExporterCB{conn: s.conn, cbType: "tls-exporter"}
	case auth.SCRAMSHA256, auth.SCRAMSHA512:
	default:
		_, _ = s.enc.WriteRaw(sasl2Failure("invalid-mechanism"))
		return nil, fmt.Errorf("unsupported mechanism: %s", mechName)
	}

	lookup := func(username string) (*auth.StoredCreds, error) {
		u, err := s.cfg.Stores.Users.Get(ctx, username)
		if err != nil {
			return nil, err
		}
		return userToCreds(u, mech)
	}

	srv, err := newAuthServer(mech, lookup, cb)
	if err != nil {
		_, _ = s.enc.WriteRaw(sasl2Failure("temporary-auth-failure"))
		return nil, err
	}

	// Parse initial-response from <authenticate>
	initial := extractSASL2Field(raw, "initial-response")
	var inBytes []byte
	if initial != "" {
		inBytes, err = base64.StdEncoding.DecodeString(initial)
		if err != nil {
			_, _ = s.enc.WriteRaw(sasl2Failure("malformed-request"))
			return nil, err
		}
	}

	out, _, err := stepAuthExchange(s, srv, inBytes, nsSASL2, "challenge", "response", sasl2Failure)
	if err != nil {
		return nil, err
	}

	return &authResult{Username: srv.Username(), ServerFinal: out, Style: authStyleSASL2}, nil
}

func sasl2Failure(condition string) []byte {
	return []byte(fmt.Sprintf(`<failure xmlns='%s'><%s/></failure>`, nsSASL2, condition))
}

func handleLegacyAuth(ctx context.Context, s *Session, start xml.StartElement, raw []byte) (*authResult, error) {
	mechName := ""
	for _, a := range start.Attr {
		if a.Name.Local == "mechanism" {
			mechName = a.Value
			break
		}
	}

	mech := auth.Mechanism(mechName)
	var cb auth.ChannelBinding
	switch mech {
	case auth.SCRAMSHA256Plus, auth.SCRAMSHA512Plus:
		cb = &tlsExporterCB{conn: s.conn, cbType: "tls-exporter"}
	case auth.SCRAMSHA256, auth.SCRAMSHA512:
	case auth.Plain:
		return handleLegacyPlainAuth(ctx, s, raw)
	default:
		_, _ = s.enc.WriteRaw(legacySASLFailure("invalid-mechanism"))
		return nil, fmt.Errorf("unsupported mechanism: %s", mechName)
	}

	lookup := func(username string) (*auth.StoredCreds, error) {
		u, err := s.cfg.Stores.Users.Get(ctx, username)
		if err != nil {
			return nil, err
		}
		return userToCreds(u, mech)
	}

	srv, err := newAuthServer(mech, lookup, cb)
	if err != nil {
		_, _ = s.enc.WriteRaw(legacySASLFailure("temporary-auth-failure"))
		return nil, err
	}

	initialText := extractElementText(raw)
	var inBytes []byte
	if strings.TrimSpace(initialText) != "" {
		inBytes, err = base64.StdEncoding.DecodeString(strings.TrimSpace(initialText))
		if err != nil {
			_, _ = s.enc.WriteRaw(legacySASLFailure("malformed-request"))
			return nil, err
		}
	}

	out, _, err := stepAuthExchange(s, srv, inBytes, nsSASL, "challenge", "response", legacySASLFailure)
	if err != nil {
		return nil, err
	}

	return &authResult{Username: srv.Username(), ServerFinal: out, Style: authStyleLegacy}, nil
}

func legacySASLFailure(condition string) []byte {
	return []byte(fmt.Sprintf(`<failure xmlns='%s'><%s/></failure>`, nsSASL, condition))
}

func handleLegacyPlainAuth(ctx context.Context, s *Session, raw []byte) (*authResult, error) {
	initialText := strings.TrimSpace(extractElementText(raw))
	if initialText == "" {
		_, _ = s.enc.WriteRaw(legacySASLFailure("malformed-request"))
		return nil, fmt.Errorf("plain: empty initial response")
	}

	payload, err := base64.StdEncoding.DecodeString(initialText)
	if err != nil {
		_, _ = s.enc.WriteRaw(legacySASLFailure("malformed-request"))
		return nil, err
	}

	parts := bytes.Split(payload, []byte{0})
	if len(parts) != 3 {
		_, _ = s.enc.WriteRaw(legacySASLFailure("malformed-request"))
		return nil, fmt.Errorf("plain: expected 3 fields, got %d", len(parts))
	}

	authzid := string(parts[0])
	authcid := string(parts[1])
	password := parts[2]
	if authcid == "" {
		_, _ = s.enc.WriteRaw(legacySASLFailure("malformed-request"))
		return nil, fmt.Errorf("plain: empty authcid")
	}
	if authzid != "" && authzid != authcid && authzid != authcid+"@"+s.cfg.Domain {
		_, _ = s.enc.WriteRaw(legacySASLFailure("invalid-authzid"))
		return nil, fmt.Errorf("plain: unsupported authzid %q", authzid)
	}

	u, err := s.cfg.Stores.Users.Get(ctx, authcid)
	if err != nil {
		_, _ = s.enc.WriteRaw(legacySASLFailure("not-authorized"))
		return nil, err
	}
	ok, err := auth.VerifyStoredPassword(u.Argon2Params, password)
	if err != nil {
		_, _ = s.enc.WriteRaw(legacySASLFailure("temporary-auth-failure"))
		return nil, err
	}
	if !ok {
		_, _ = s.enc.WriteRaw(legacySASLFailure("not-authorized"))
		return nil, fmt.Errorf("plain: password verification failed")
	}

	return &authResult{Username: authcid, Style: authStyleLegacy}, nil
}

func newAuthServer(mech auth.Mechanism, lookup func(username string) (*auth.StoredCreds, error), cb auth.ChannelBinding) (*auth.Server, error) {
	return auth.NewServer(mech, lookup, cb)
}

func stepAuthExchange(
	s *Session,
	srv *auth.Server,
	inBytes []byte,
	ns string,
	challengeEl string,
	responseEl string,
	failureFn func(string) []byte,
) ([]byte, bool, error) {
	out, done, err := srv.Step(inBytes)
	if err != nil {
		_, _ = s.enc.WriteRaw(failureFn("not-authorized"))
		return nil, false, err
	}

	if !done {
		challenge := base64.StdEncoding.EncodeToString(out)
		_, _ = s.enc.WriteRaw([]byte(fmt.Sprintf(`<%s xmlns='%s'>%s</%s>`, challengeEl, ns, challenge, challengeEl)))

		respStart, respRaw, err2 := s.dec.NextElement()
		if err2 != nil {
			return nil, false, err2
		}
		if respStart.Name.Local != responseEl || respStart.Name.Space != ns {
			_, _ = s.enc.WriteRaw(failureFn("malformed-request"))
			return nil, false, fmt.Errorf("sasl: expected <%s xmlns='%s'>, got %s in %s", responseEl, ns, respStart.Name.Local, respStart.Name.Space)
		}

		respB64 := extractElementText(respRaw)
		respBytes, err2 := base64.StdEncoding.DecodeString(respB64)
		if err2 != nil {
			_, _ = s.enc.WriteRaw(failureFn("malformed-request"))
			return nil, false, err2
		}

		out, done, err = srv.Step(respBytes)
		if err != nil {
			_, _ = s.enc.WriteRaw(failureFn("not-authorized"))
			return nil, false, err
		}
	}

	if !done {
		_, _ = s.enc.WriteRaw(failureFn("not-authorized"))
		return nil, false, fmt.Errorf("sasl: exchange not complete")
	}

	return out, true, nil
}

func userToCreds(u *storage.User, mech auth.Mechanism) (*auth.StoredCreds, error) {
	switch mech {
	case auth.SCRAMSHA512, auth.SCRAMSHA512Plus:
		if len(u.StoredKey512) == 0 {
			return nil, fmt.Errorf("no SHA-512 credentials stored for user")
		}
		return &auth.StoredCreds{
			Salt:      u.ScramSalt,
			Iter:      u.ScramIter,
			StoredKey: u.StoredKey512,
			ServerKey: u.ServerKey512,
		}, nil
	default:
		if len(u.StoredKey256) == 0 {
			return nil, fmt.Errorf("no SHA-256 credentials stored for user")
		}
		return &auth.StoredCreds{
			Salt:      u.ScramSalt,
			Iter:      u.ScramIter,
			StoredKey: u.StoredKey256,
			ServerKey: u.ServerKey256,
		}, nil
	}
}

// extractSASL2Field extracts a named child element's text content from raw XML.
func extractSASL2Field(raw []byte, localName string) string {
	dec := xml.NewDecoder(strings.NewReader(string(raw)))
	inTarget := false
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == localName {
				inTarget = true
			}
		case xml.EndElement:
			if t.Name.Local == localName {
				inTarget = false
			}
		case xml.CharData:
			if inTarget {
				return strings.TrimSpace(string(t))
			}
		}
	}
	return ""
}

// extractElementText returns the text content of the root element in raw.
func extractElementText(raw []byte) string {
	dec := xml.NewDecoder(strings.NewReader(string(raw)))
	depth := 0
	var sb strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
		case xml.EndElement:
			depth--
			if depth == 0 {
				return strings.TrimSpace(sb.String())
			}
		case xml.CharData:
			if depth == 1 {
				sb.Write(t)
			}
		}
	}
	return strings.TrimSpace(sb.String())
}

package c2s

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/danielinux/xmppqr/internal/auth"
	"github.com/danielinux/xmppqr/internal/storage"
)

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
func handleAuthenticate(ctx context.Context, s *Session, start xml.StartElement, raw []byte) (string, error) {
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
		return "", fmt.Errorf("unsupported mechanism: %s", mechName)
	}

	lookup := func(username string) (*auth.StoredCreds, error) {
		u, err := s.cfg.Stores.Users.Get(ctx, username)
		if err != nil {
			return nil, err
		}
		return userToCreds(u, mech)
	}

	srv, err := auth.NewServer(mech, lookup, cb)
	if err != nil {
		_, _ = s.enc.WriteRaw(sasl2Failure("temporary-auth-failure"))
		return "", err
	}

	// Parse initial-response from <authenticate>
	initial := extractSASL2Field(raw, "initial-response")
	var inBytes []byte
	if initial != "" {
		inBytes, err = base64.StdEncoding.DecodeString(initial)
		if err != nil {
			_, _ = s.enc.WriteRaw(sasl2Failure("malformed-request"))
			return "", err
		}
	}

	out, done, err := srv.Step(inBytes)
	if err != nil {
		_, _ = s.enc.WriteRaw(sasl2Failure("not-authorized"))
		return "", err
	}

	if !done {
		// Send challenge and read response
		challenge := base64.StdEncoding.EncodeToString(out)
		_, _ = s.enc.WriteRaw([]byte(fmt.Sprintf(`<challenge xmlns='%s'>%s</challenge>`, nsSASL2, challenge)))

		_, respRaw, err2 := s.dec.NextElement()
		if err2 != nil {
			return "", err2
		}
		respB64 := extractElementText(respRaw)
		respBytes, err2 := base64.StdEncoding.DecodeString(respB64)
		if err2 != nil {
			_, _ = s.enc.WriteRaw(sasl2Failure("malformed-request"))
			return "", err2
		}

		out, done, err = srv.Step(respBytes)
		if err != nil {
			_, _ = s.enc.WriteRaw(sasl2Failure("not-authorized"))
			return "", err
		}
	}

	if !done {
		_, _ = s.enc.WriteRaw(sasl2Failure("not-authorized"))
		return "", fmt.Errorf("sasl: exchange not complete")
	}

	return srv.Username(), nil
}

func sasl2Failure(condition string) []byte {
	return []byte(fmt.Sprintf(`<failure xmlns='%s'><%s/></failure>`, nsSASL2, condition))
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

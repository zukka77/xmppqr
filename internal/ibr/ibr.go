package ibr

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/danielinux/xmppqr/internal/accountjid"
	"github.com/danielinux/xmppqr/internal/auth"
	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage"
	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

const nsRegister = "jabber:iq:register"

var reservedPrefixes = []string{"admin", "root", "_"}

type Service struct {
	stores         *storage.Stores
	domain         string
	allowed        bool
	minPasswordLen int
}

func New(stores *storage.Stores, domain string, allowed bool) *Service {
	return &Service{stores: stores, domain: domain, allowed: allowed, minPasswordLen: 8}
}

func (s *Service) Allowed() bool {
	return s.allowed
}

func (s *Service) HandleIQ(ctx context.Context, iq *stanza.IQ) ([]byte, error) {
	if !s.allowed {
		return nil, &stanza.StanzaError{Type: stanza.ErrorTypeCancel, Condition: stanza.ErrNotAllowed}
	}

	switch iq.Type {
	case stanza.IQGet:
		payload := `<query xmlns='jabber:iq:register'><instructions>Choose a username and password.</instructions><username/><password/></query>`
		result := &stanza.IQ{ID: iq.ID, From: iq.To, To: iq.From, Type: stanza.IQResult, Payload: []byte(payload)}
		return result.Marshal()

	case stanza.IQSet:
		return s.handleSet(ctx, iq)
	}

	return nil, &stanza.StanzaError{Type: stanza.ErrorTypeCancel, Condition: stanza.ErrFeatureNotImplemented}
}

func (s *Service) handleSet(ctx context.Context, iq *stanza.IQ) ([]byte, error) {
	username, password, err := parseRegisterQuery(iq.Payload)
	if err != nil {
		return nil, &stanza.StanzaError{Type: stanza.ErrorTypeModify, Condition: stanza.ErrBadRequest}
	}

	if err := validateUsername(username); err != nil {
		return nil, err
	}

	if _, parseErr := stanza.Parse(username + "@" + s.domain); parseErr != nil {
		return nil, &stanza.StanzaError{Type: stanza.ErrorTypeModify, Condition: stanza.ErrJIDMalformed}
	}
	accountJID, _, normErr := accountjid.Normalize(username, s.domain)
	if normErr != nil {
		return nil, &stanza.StanzaError{Type: stanza.ErrorTypeModify, Condition: stanza.ErrJIDMalformed}
	}

	if len(password) < s.minPasswordLen {
		return nil, &stanza.StanzaError{Type: stanza.ErrorTypeModify, Condition: stanza.ErrNotAcceptable}
	}

	existing, _ := s.stores.Users.Get(ctx, accountJID)
	if existing != nil {
		return nil, &stanza.StanzaError{Type: stanza.ErrorTypeCancel, Condition: stanza.ErrConflict}
	}

	salt := make([]byte, 16)
	if _, rerr := wolfcrypt.Read(salt); rerr != nil {
		return nil, &stanza.StanzaError{Type: stanza.ErrorTypeCancel, Condition: stanza.ErrInternalServerError}
	}

	const iter = 4096

	creds256, cerr := auth.DeriveSCRAMCreds([]byte(password), salt, iter, auth.SCRAMSHA256)
	if cerr != nil {
		return nil, &stanza.StanzaError{Type: stanza.ErrorTypeCancel, Condition: stanza.ErrInternalServerError}
	}
	creds512, cerr := auth.DeriveSCRAMCreds([]byte(password), salt, iter, auth.SCRAMSHA512)
	if cerr != nil {
		return nil, &stanza.StanzaError{Type: stanza.ErrorTypeCancel, Condition: stanza.ErrInternalServerError}
	}
	encoded, cerr := auth.HashPasswordForStorage([]byte(password))
	if cerr != nil {
		return nil, &stanza.StanzaError{Type: stanza.ErrorTypeCancel, Condition: stanza.ErrInternalServerError}
	}

	u := &storage.User{
		Username:     accountJID,
		ScramSalt:    salt,
		ScramIter:    iter,
		Argon2Params: encoded,
		StoredKey256: creds256.StoredKey,
		ServerKey256: creds256.ServerKey,
		StoredKey512: creds512.StoredKey,
		ServerKey512: creds512.ServerKey,
		CreatedAt:    time.Now(),
	}
	if perr := s.stores.Users.Put(ctx, u); perr != nil {
		return nil, &stanza.StanzaError{Type: stanza.ErrorTypeCancel, Condition: stanza.ErrInternalServerError}
	}

	result := &stanza.IQ{ID: iq.ID, From: iq.To, To: iq.From, Type: stanza.IQResult}
	return result.Marshal()
}

func validateUsername(username string) error {
	if username == "" {
		return &stanza.StanzaError{Type: stanza.ErrorTypeModify, Condition: stanza.ErrBadRequest}
	}
	for _, r := range username {
		if unicode.IsSpace(r) {
			return &stanza.StanzaError{Type: stanza.ErrorTypeModify, Condition: stanza.ErrJIDMalformed}
		}
	}
	lower := strings.ToLower(username)
	for _, prefix := range reservedPrefixes {
		if lower == prefix || strings.HasPrefix(lower, prefix) {
			return &stanza.StanzaError{Type: stanza.ErrorTypeCancel, Condition: stanza.ErrNotAllowed}
		}
	}
	return nil
}

func parseRegisterQuery(payload []byte) (username, password string, err error) {
	dec := xml.NewDecoder(bytes.NewReader(payload))
	inQuery := false
	for {
		tok, terr := dec.Token()
		if terr != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "query" && t.Name.Space == nsRegister {
				inQuery = true
				continue
			}
			if !inQuery {
				continue
			}
			switch t.Name.Local {
			case "username":
				var v string
				if decErr := dec.DecodeElement(&v, &t); decErr == nil {
					username = v
				}
			case "password":
				var v string
				if decErr := dec.DecodeElement(&v, &t); decErr == nil {
					password = v
				}
			}
		}
	}
	if username == "" && password == "" && !inQuery {
		return "", "", fmt.Errorf("ibr: no register query found")
	}
	return username, password, nil
}

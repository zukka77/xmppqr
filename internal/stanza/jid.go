// Package stanza provides typed XMPP stanza models.
package stanza

import (
	"errors"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/secure/precis"
)

const maxPartBytes = 1023

var (
	errEmptyDomain  = errors.New("jid: domain must not be empty")
	errPartTooLong  = errors.New("jid: part exceeds 1023 bytes")
	errInvalidLocal = errors.New("jid: invalid local part")
	errInvalidRes   = errors.New("jid: invalid resource part")
)

type JID struct {
	Local, Domain, Resource string
}

func Parse(s string) (JID, error) {
	var j JID

	// Split resource first (everything after first '/').
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		j.Resource = s[idx+1:]
		s = s[:idx]
	}

	// Split local.
	if idx := strings.IndexByte(s, '@'); idx >= 0 {
		j.Local = s[:idx]
		j.Domain = s[idx+1:]
	} else {
		j.Domain = s
	}

	if j.Domain == "" {
		return JID{}, errEmptyDomain
	}

	// Apply PRECIS UsernameCasePreserved for local part.
	if j.Local != "" {
		if !utf8.ValidString(j.Local) {
			return JID{}, errInvalidLocal
		}
		normed, err := precis.UsernameCasePreserved.String(j.Local)
		if err != nil {
			return JID{}, errInvalidLocal
		}
		if len(normed) > maxPartBytes {
			return JID{}, errPartTooLong
		}
		j.Local = normed
	}

	if len(j.Domain) > maxPartBytes {
		return JID{}, errPartTooLong
	}

	// Apply PRECIS OpaqueString for resource.
	if j.Resource != "" {
		if !utf8.ValidString(j.Resource) {
			return JID{}, errInvalidRes
		}
		normed, err := precis.OpaqueString.String(j.Resource)
		if err != nil {
			return JID{}, errInvalidRes
		}
		if len(normed) > maxPartBytes {
			return JID{}, errPartTooLong
		}
		j.Resource = normed
	}

	return j, nil
}

func (j JID) String() string {
	var sb strings.Builder
	if j.Local != "" {
		sb.WriteString(j.Local)
		sb.WriteByte('@')
	}
	sb.WriteString(j.Domain)
	if j.Resource != "" {
		sb.WriteByte('/')
		sb.WriteString(j.Resource)
	}
	return sb.String()
}

func (j JID) Bare() JID {
	return JID{Local: j.Local, Domain: j.Domain}
}

func (j JID) Equal(other JID) bool {
	return j.Local == other.Local && j.Domain == other.Domain && j.Resource == other.Resource
}

func (j JID) IsBare() bool {
	return j.Resource == ""
}

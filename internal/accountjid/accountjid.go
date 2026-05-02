package accountjid

import (
	"errors"
	"strings"

	"github.com/danielinux/xmppqr/internal/stanza"
)

var ErrDomainRequired = errors.New("accountjid: domain is required for local usernames")

func Normalize(input, defaultDomain string) (bare string, local string, err error) {
	if strings.Contains(input, "@") || strings.Contains(input, "/") {
		j, err := stanza.Parse(input)
		if err != nil {
			return "", "", err
		}
		if j.Local == "" {
			return "", "", errors.New("accountjid: local part is required")
		}
		return j.Bare().String(), j.Local, nil
	}
	if defaultDomain == "" {
		return "", "", ErrDomainRequired
	}
	j, err := stanza.Parse(input + "@" + defaultDomain)
	if err != nil {
		return "", "", err
	}
	return j.Bare().String(), j.Local, nil
}

func LookupCandidates(input, defaultDomain string) ([]string, string, error) {
	bare, local, err := Normalize(input, defaultDomain)
	if err != nil {
		return nil, "", err
	}
	candidates := []string{bare}
	if input == local {
		candidates = append(candidates, local)
	}
	return candidates, local, nil
}

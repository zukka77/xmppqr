package xml

import "errors"

var (
	ErrBadStream           = errors.New("xmpp: bad stream header")
	ErrUnsupportedVersion  = errors.New("xmpp: unsupported stream version")
	ErrEntityExpansion     = errors.New("xmpp: entity expansion rejected")
)

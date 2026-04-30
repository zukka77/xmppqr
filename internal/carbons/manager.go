// Package carbons implements XEP-0280 Message Carbons.
package carbons

import (
	"log/slog"
	"sync"

	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/stanza"
)

type Manager struct {
	router  *router.Router
	logger  *slog.Logger
	enabled sync.Map // fullJID string -> bool
}

func New(r *router.Router, l *slog.Logger) *Manager {
	return &Manager{router: r, logger: l}
}

func (m *Manager) EnableForSession(fullJID stanza.JID) {
	m.enabled.Store(fullJID.String(), true)
}

func (m *Manager) DisableForSession(fullJID stanza.JID) {
	m.enabled.Delete(fullJID.String())
}

func (m *Manager) IsEnabled(fullJID stanza.JID) bool {
	v, ok := m.enabled.Load(fullJID.String())
	return ok && v.(bool)
}

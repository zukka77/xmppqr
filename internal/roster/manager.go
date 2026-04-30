// Package roster implements RFC 6121 §2 roster management.
package roster

import (
	"context"
	"errors"
	"log/slog"

	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage"
)

const (
	subNone = 0
	subFrom = 1
	subTo   = 2
	subBoth = 3

	askNone        = 0
	askSubscribe   = 1
	askUnsubscribe = 2
)

type Session interface {
	Deliver(ctx context.Context, raw []byte) error
}

type Manager struct {
	store  storage.RosterStore
	logger *slog.Logger
}

func New(store storage.RosterStore, logger *slog.Logger) *Manager {
	return &Manager{store: store, logger: logger}
}

func (m *Manager) Get(ctx context.Context, owner string) ([]*storage.RosterItem, int64, error) {
	return m.store.Get(ctx, owner)
}

func (m *Manager) Set(ctx context.Context, owner string, contact stanza.JID, name string, groups []string) (int64, error) {
	existing, err := m.findItem(ctx, owner, contact.String())
	if err != nil {
		return 0, err
	}

	item := &storage.RosterItem{
		Owner:   owner,
		Contact: contact.String(),
		Name:    name,
		Groups:  groups,
	}
	if existing != nil {
		item.Subscription = existing.Subscription
		item.Ask = existing.Ask
	}
	return m.store.Put(ctx, item)
}

func (m *Manager) Remove(ctx context.Context, owner string, contact stanza.JID) (int64, error) {
	return m.store.Delete(ctx, owner, contact.String())
}

func (m *Manager) HandlePush(ctx context.Context, ownerSession Session, item *storage.RosterItem) {
	// placeholder — c2s layer wires the actual push stanza
}

// Subscribe sets ask=subscribe for the owner→contact relationship (RFC 6121 §3.1.2).
func (m *Manager) Subscribe(ctx context.Context, owner string, contact stanza.JID) (int, error) {
	item, err := m.findItem(ctx, owner, contact.String())
	if err != nil {
		return 0, err
	}
	if item == nil {
		item = &storage.RosterItem{
			Owner:   owner,
			Contact: contact.String(),
		}
	}
	item.Ask = askSubscribe
	if _, err := m.store.Put(ctx, item); err != nil {
		return 0, err
	}
	return item.Ask, nil
}

// Subscribed updates subscription state when owner approves contact's subscription
// request (RFC 6121 §3.1.5 table).
func (m *Manager) Subscribed(ctx context.Context, owner string, contact stanza.JID) error {
	item, err := m.findItem(ctx, owner, contact.String())
	if err != nil {
		return err
	}
	if item == nil {
		item = &storage.RosterItem{
			Owner:   owner,
			Contact: contact.String(),
		}
	}
	// Owner is approving a subscription from contact, so contact gets "from" on owner's roster.
	switch item.Subscription {
	case subNone:
		item.Subscription = subFrom
	case subTo:
		item.Subscription = subBoth
	}
	item.Ask = askNone
	_, err = m.store.Put(ctx, item)
	return err
}

func (m *Manager) findItem(ctx context.Context, owner, contact string) (*storage.RosterItem, error) {
	items, _, err := m.store.Get(ctx, owner)
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		if it.Contact == contact {
			cp := *it
			return &cp, nil
		}
	}
	return nil, nil
}

var errMissingFrom = errors.New("presence: missing from")
var errMissingTo = errors.New("presence: missing to")

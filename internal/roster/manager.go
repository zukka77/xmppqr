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
// Returns the updated item so callers can build roster pushes.
func (m *Manager) Subscribe(ctx context.Context, owner string, contact stanza.JID) (*storage.RosterItem, error) {
	item, err := m.findItem(ctx, owner, contact.String())
	if err != nil {
		return nil, err
	}
	if item == nil {
		item = &storage.RosterItem{
			Owner:        owner,
			Contact:      contact.String(),
			Subscription: subNone,
		}
	}
	item.Ask = askSubscribe
	if _, err := m.store.Put(ctx, item); err != nil {
		return nil, err
	}
	return item, nil
}

// Subscribed updates subscription state when owner approves contact's inbound
// subscription request (RFC 6121 §3.1.5 table, outbound 'subscribed').
// Returns the updated item.
func (m *Manager) Subscribed(ctx context.Context, owner string, contact stanza.JID) (*storage.RosterItem, error) {
	item, err := m.findItem(ctx, owner, contact.String())
	if err != nil {
		return nil, err
	}
	if item == nil {
		item = &storage.RosterItem{
			Owner:   owner,
			Contact: contact.String(),
		}
	}
	switch item.Subscription {
	case subNone:
		item.Subscription = subFrom
	case subTo:
		item.Subscription = subBoth
	}
	item.Ask = askNone
	_, err = m.store.Put(ctx, item)
	return item, err
}

// Unsubscribe updates state when owner withdraws their subscription to contact
// (RFC 6121 §3.3.2, outbound 'unsubscribe').
func (m *Manager) Unsubscribe(ctx context.Context, owner string, contact stanza.JID) (*storage.RosterItem, error) {
	item, err := m.findItem(ctx, owner, contact.String())
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	switch item.Subscription {
	case subTo:
		item.Subscription = subNone
	case subBoth:
		item.Subscription = subFrom
	}
	item.Ask = askUnsubscribe
	_, err = m.store.Put(ctx, item)
	return item, err
}

// Unsubscribed updates state when owner cancels contact's subscription to owner
// (RFC 6121 §3.2.2, outbound 'unsubscribed').
func (m *Manager) Unsubscribed(ctx context.Context, owner string, contact stanza.JID) (*storage.RosterItem, error) {
	item, err := m.findItem(ctx, owner, contact.String())
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	switch item.Subscription {
	case subFrom:
		item.Subscription = subNone
	case subBoth:
		item.Subscription = subTo
	}
	item.Ask = askNone
	_, err = m.store.Put(ctx, item)
	return item, err
}

// InboundSubscribed handles an inbound 'subscribed' stanza arriving at owner
// from contact (RFC 6121 §3.1.5, inbound). Clears ask, promotes subscription.
func (m *Manager) InboundSubscribed(ctx context.Context, owner string, contact stanza.JID) (*storage.RosterItem, error) {
	item, err := m.findItem(ctx, owner, contact.String())
	if err != nil {
		return nil, err
	}
	if item == nil {
		item = &storage.RosterItem{
			Owner:   owner,
			Contact: contact.String(),
		}
	}
	switch item.Subscription {
	case subNone:
		item.Subscription = subTo
	case subFrom:
		item.Subscription = subBoth
	}
	item.Ask = askNone
	_, err = m.store.Put(ctx, item)
	return item, err
}

// InboundUnsubscribed handles an inbound 'unsubscribed' from contact arriving at owner
// (RFC 6121 §3.3.4). Demotes subscription by removing the 'to' bit.
func (m *Manager) InboundUnsubscribed(ctx context.Context, owner string, contact stanza.JID) (*storage.RosterItem, error) {
	item, err := m.findItem(ctx, owner, contact.String())
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	switch item.Subscription {
	case subTo:
		item.Subscription = subNone
	case subBoth:
		item.Subscription = subFrom
	}
	item.Ask = askNone
	_, err = m.store.Put(ctx, item)
	return item, err
}

// GetItem returns the roster item for a specific contact, or nil if not present.
func (m *Manager) GetItem(ctx context.Context, owner string, contact stanza.JID) (*storage.RosterItem, error) {
	return m.findItem(ctx, owner, contact.String())
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

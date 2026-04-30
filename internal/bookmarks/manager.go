// Package bookmarks implements XEP-0402 PEP native bookmarks.
package bookmarks

import (
	"context"
	"time"

	"github.com/danielinux/xmppqr/internal/storage"
)

const bookmarksNode = "urn:xmpp:bookmarks:1"

type Manager struct {
	pep storage.PEPStore
}

func New(pep storage.PEPStore) *Manager {
	return &Manager{pep: pep}
}

func (m *Manager) List(ctx context.Context, owner string) ([]*storage.PEPItem, error) {
	return m.pep.ListItems(ctx, owner, bookmarksNode, 0)
}

func (m *Manager) Set(ctx context.Context, owner, conferenceJID string, conferenceXML []byte) error {
	return m.pep.PutItem(ctx, &storage.PEPItem{
		Owner:       owner,
		Node:        bookmarksNode,
		ItemID:      conferenceJID,
		PublishedAt: time.Now(),
		Payload:     conferenceXML,
	})
}

func (m *Manager) Remove(ctx context.Context, owner, conferenceJID string) error {
	return m.pep.DeleteItem(ctx, owner, bookmarksNode, conferenceJID)
}

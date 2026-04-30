// Package pubsub implements a subset of XEP-0060 sufficient for PEP (XEP-0163).
package pubsub

import (
	"context"
	"log/slog"

	"github.com/danielinux/xmppqr/internal/caps"
	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/storage"
)

const defaultItemMaxBytes = 256 * 1024

type rosterGetter interface {
	Get(ctx context.Context, owner string) ([]*storage.RosterItem, int64, error)
}

type Service struct {
	store        storage.PEPStore
	router       *router.Router
	logger       *slog.Logger
	itemMaxBytes int64
	roster       rosterGetter
	caps         *caps.Cache
}

func New(store storage.PEPStore, r *router.Router, logger *slog.Logger, itemMaxBytes int64) *Service {
	if itemMaxBytes <= 0 {
		itemMaxBytes = defaultItemMaxBytes
	}
	return &Service{
		store:        store,
		router:       r,
		logger:       logger,
		itemMaxBytes: itemMaxBytes,
	}
}

func (svc *Service) WithContactNotify(roster rosterGetter, c *caps.Cache) {
	svc.roster = roster
	svc.caps = c
}

func (svc *Service) contactNotifyEnabled() bool {
	return svc.roster != nil && svc.caps != nil
}

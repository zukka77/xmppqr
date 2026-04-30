// Package pubsub implements a subset of XEP-0060 sufficient for PEP (XEP-0163).
package pubsub

import (
	"log/slog"

	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/storage"
)

const defaultItemMaxBytes = 256 * 1024

type Service struct {
	store        storage.PEPStore
	router       *router.Router
	logger       *slog.Logger
	itemMaxBytes int64
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

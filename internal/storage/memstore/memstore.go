// Package memstore provides in-memory implementations of all storage interfaces,
// suitable for testing and single-node deployments that do not require persistence.
package memstore

import (
	"github.com/danielinux/xmppqr/internal/storage"
)

func New() *storage.Stores {
	return &storage.Stores{
		Users:   newUserStore(),
		Roster:  newRosterStore(),
		MAM:     newMAMStore(),
		PEP:     newPEPStore(),
		MUC:     newMUCStore(),
		Push:    newPushStore(),
		Block:   newBlockStore(),
		Offline: newOfflineStore(),
	}
}

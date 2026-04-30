package pg

import "github.com/danielinux/xmppqr/internal/storage"

var _ storage.UserStore   = (*pgUsers)(nil)
var _ storage.RosterStore = (*pgRoster)(nil)
var _ storage.MAMStore    = (*pgMAM)(nil)
var _ storage.PEPStore    = (*pgPEP)(nil)
var _ storage.MUCStore    = (*pgMUC)(nil)
var _ storage.PushStore   = (*pgPush)(nil)
var _ storage.BlockStore  = (*pgBlock)(nil)
var _ storage.OfflineStore = (*pgOffline)(nil)

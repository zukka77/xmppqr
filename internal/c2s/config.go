package c2s

import (
	"log/slog"
	"time"

	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/sm"
	"github.com/danielinux/xmppqr/internal/storage"
)

type SessionConfig struct {
	Domain         string
	Stores         *storage.Stores
	Router         *router.Router
	ResumeStore    *sm.Store
	ResumeTimeout  time.Duration
	Logger         *slog.Logger
	MaxStanzaBytes int64
	Modules        *Modules
}

// TLSConn is the public alias used by callers. Identical to the internal tlsConnIface.
type TLSConn = tlsConnIface

func NewSession(conn TLSConn, cfg SessionConfig) *Session {
	return newSession(conn, cfg)
}

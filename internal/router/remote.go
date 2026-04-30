package router

import "context"

import "github.com/danielinux/xmppqr/internal/stanza"

type RemoteRouter interface {
	Send(ctx context.Context, fromBare, toBare stanza.JID, raw []byte) error
}

func (r *Router) SetRemote(rr RemoteRouter) {
	r.mu.Lock()
	r.remote = rr
	r.mu.Unlock()
}

func (r *Router) SetLocalDomain(d string) {
	r.mu.Lock()
	r.localDomain = d
	r.mu.Unlock()
}

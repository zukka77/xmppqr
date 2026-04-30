package push

import (
	"context"

	"github.com/danielinux/xmppqr/internal/storage"
)

type Receipt struct {
	ID     string
	Status int
	Err    error
}

type Provider interface {
	Name() string
	Send(ctx context.Context, reg *storage.PushRegistration, p Payload) (Receipt, error)
}

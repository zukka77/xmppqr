package presence

import (
	"context"
)

func (b *Broadcaster) HandleProbe(ctx context.Context, sess Session, raw []byte) error {
	// v1 stub: probe handling is a no-op; c2s layer handles local delivery.
	return nil
}

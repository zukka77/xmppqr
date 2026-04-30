package router

import (
	"context"
	"log/slog"
	"testing"

	"github.com/danielinux/xmppqr/internal/stanza"
)

func TestInboundAdapterRoutesToFull(t *testing.T) {
	r := New()
	r.SetLocalDomain("a.test")

	target, _ := stanza.Parse("alice@a.test/laptop")
	sess := newMock("alice@a.test/laptop", 0, true)
	r.Register(sess)

	_ = target
	adapter := NewRouterInboundAdapter(r, slog.Default())

	raw := []byte(`<message to='alice@a.test/laptop' from='bob@b.test'><body>hi</body></message>`)
	if err := adapter.RouteInbound(context.Background(), raw); err != nil {
		t.Fatalf("RouteInbound error: %v", err)
	}

	select {
	case got := <-sess.queue:
		if string(got) != string(raw) {
			t.Fatalf("delivered stanza mismatch: got %q", got)
		}
	default:
		t.Fatal("session did not receive the stanza")
	}
}

func TestInboundAdapterNoToReturnsError(t *testing.T) {
	r := New()
	r.SetLocalDomain("a.test")
	adapter := NewRouterInboundAdapter(r, slog.Default())

	raw := []byte(`<message from='bob@b.test'><body>hi</body></message>`)
	if err := adapter.RouteInbound(context.Background(), raw); err != ErrNoSession {
		t.Fatalf("expected ErrNoSession for missing to=, got %v", err)
	}
}

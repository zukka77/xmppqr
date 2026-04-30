package push

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage"
	"log/slog"
	"os"
)

type mockStore struct {
	mu   sync.Mutex
	regs []*storage.PushRegistration
}

func (m *mockStore) Put(_ context.Context, reg *storage.PushRegistration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, r := range m.regs {
		if r.Owner == reg.Owner && r.ServiceJID == reg.ServiceJID && r.Node == reg.Node {
			m.regs[i] = reg
			return nil
		}
	}
	m.regs = append(m.regs, reg)
	return nil
}

func (m *mockStore) List(_ context.Context, owner string) ([]*storage.PushRegistration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*storage.PushRegistration
	for _, r := range m.regs {
		if r.Owner == owner {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *mockStore) Delete(_ context.Context, owner, serviceJID, node string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.regs[:0]
	for _, r := range m.regs {
		if !(r.Owner == owner && r.ServiceJID == serviceJID && r.Node == node) {
			kept = append(kept, r)
		}
	}
	m.regs = kept
	return nil
}

type mockProvider struct {
	mu    sync.Mutex
	calls []Payload
}

func (mp *mockProvider) Name() string { return "mock" }

func (mp *mockProvider) Send(_ context.Context, _ *storage.PushRegistration, p Payload) (Receipt, error) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.calls = append(mp.calls, p)
	return Receipt{ID: "ok", Status: 200}, nil
}

func newTestDispatcher(store storage.PushStore, domain string) (*Dispatcher, *mockProvider) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	r := router.New()
	d := New(store, r, domain, logger)
	mp := &mockProvider{}
	d.RegisterProvider(domain, mp)
	return d, mp
}

func mustJID(s string) stanza.JID {
	j, err := stanza.Parse(s)
	if err != nil {
		panic(err)
	}
	return j
}

func TestEnableList(t *testing.T) {
	store := &mockStore{}
	d, _ := newTestDispatcher(store, "push.example.com")
	ctx := context.Background()

	owner := mustJID("alice@example.com")
	svc := mustJID("push.example.com")

	if err := d.Enable(ctx, owner, svc, "node1", nil); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	regs, err := store.List(ctx, owner.Bare().String())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(regs) != 1 {
		t.Fatalf("expected 1 registration, got %d", len(regs))
	}
	if regs[0].Node != "node1" {
		t.Errorf("unexpected node: %s", regs[0].Node)
	}
}

func TestDisableRemoves(t *testing.T) {
	store := &mockStore{}
	d, _ := newTestDispatcher(store, "push.example.com")
	ctx := context.Background()

	owner := mustJID("alice@example.com")
	svc := mustJID("push.example.com")

	if err := d.Enable(ctx, owner, svc, "node1", nil); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if err := d.Disable(ctx, owner, svc, "node1"); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	regs, _ := store.List(ctx, owner.Bare().String())
	if len(regs) != 0 {
		t.Errorf("expected 0 registrations after disable, got %d", len(regs))
	}
}

func TestNotifyCallsProvider(t *testing.T) {
	store := &mockStore{}
	d, mp := newTestDispatcher(store, "push.example.com")
	ctx := context.Background()

	owner := mustJID("alice@example.com")
	svc := mustJID("push.example.com")

	d.Enable(ctx, owner, svc, "node1", nil)

	hint := Payload{MessageCount: 3, LastFromJID: "bob@example.com", LastBody: "hello"}
	d.Notify(ctx, owner, hint)

	mp.mu.Lock()
	count := len(mp.calls)
	mp.mu.Unlock()

	if count != 1 {
		t.Errorf("expected provider.Send called once, got %d", count)
	}
}

func TestBodySuppression(t *testing.T) {
	store := &mockStore{}
	d, mp := newTestDispatcher(store, "push.example.com")
	ctx := context.Background()

	owner := mustJID("alice@example.com")
	svc := mustJID("push.example.com")

	form := []byte(`<x xmlns='jabber:x:data' type='submit'><field var='include-body'><value>false</value></field></x>`)
	d.Enable(ctx, owner, svc, "node1", form)

	hint := Payload{MessageCount: 1, LastBody: "secret content"}
	d.Notify(ctx, owner, hint)

	mp.mu.Lock()
	calls := mp.calls
	mp.mu.Unlock()

	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	if calls[0].LastBody != "" {
		t.Errorf("expected LastBody suppressed, got %q", calls[0].LastBody)
	}
}

func TestRateLimit(t *testing.T) {
	store := &mockStore{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	r := router.New()
	d := New(store, r, "push.example.com", logger)
	d.rateLimiter = newRateLimiter(30, 5)

	mp := &mockProvider{}
	d.RegisterProvider("push.example.com", mp)

	ctx := context.Background()
	owner := mustJID("alice@example.com")
	svc := mustJID("push.example.com")
	d.Enable(ctx, owner, svc, "nodeX", nil)

	for i := 0; i < 100; i++ {
		d.Notify(ctx, owner, Payload{MessageCount: 1})
	}

	mp.mu.Lock()
	total := len(mp.calls)
	mp.mu.Unlock()

	if total >= 100 {
		t.Errorf("rate limiter did not apply: got %d/100 calls through", total)
	}

	_ = time.Second
}

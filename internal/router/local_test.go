package router

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/danielinux/xmppqr/internal/stanza"
)

type mockRemoteRouter struct {
	calls atomic.Int32
	last  struct {
		from, to stanza.JID
		raw      []byte
	}
}

func (m *mockRemoteRouter) Send(_ context.Context, from, to stanza.JID, raw []byte) error {
	m.calls.Add(1)
	m.last.from = from
	m.last.to = to
	m.last.raw = raw
	return nil
}

type mockSession struct {
	jid      stanza.JID
	priority int
	avail    bool
	queue    chan []byte
}

func newMock(jidStr string, priority int, avail bool) *mockSession {
	j, err := stanza.Parse(jidStr)
	if err != nil {
		panic(err)
	}
	return &mockSession{jid: j, priority: priority, avail: avail, queue: make(chan []byte, 16)}
}

func (m *mockSession) JID() stanza.JID                          { return m.jid }
func (m *mockSession) Priority() int                            { return m.priority }
func (m *mockSession) IsAvailable() bool                        { return m.avail }
func (m *mockSession) Deliver(_ context.Context, raw []byte) error {
	select {
	case m.queue <- raw:
		return nil
	default:
		return ErrBackpressure
	}
}

func TestRouteToFull_HappyPath(t *testing.T) {
	r := New()
	s := newMock("alice@example.com/phone", 0, true)
	r.Register(s)

	jid, _ := stanza.Parse("alice@example.com/phone")
	if err := r.RouteToFull(context.Background(), jid, []byte("hi")); err != nil {
		t.Fatal(err)
	}
	if got := <-s.queue; string(got) != "hi" {
		t.Fatalf("expected 'hi', got %q", got)
	}
}

func TestRouteToFull_Missing(t *testing.T) {
	r := New()
	jid, _ := stanza.Parse("nobody@example.com/res")
	if err := r.RouteToFull(context.Background(), jid, []byte("x")); err != ErrNoSession {
		t.Fatalf("expected ErrNoSession, got %v", err)
	}
}

func TestRouteToBare_HighestPriority(t *testing.T) {
	r := New()
	low := newMock("bob@example.com/low", 0, true)
	high := newMock("bob@example.com/high", 5, true)
	unavail := newMock("bob@example.com/away", 10, false)

	r.Register(low)
	r.Register(high)
	r.Register(unavail)

	n, err := r.RouteToBare(context.Background(), mustBare("bob@example.com"), []byte("msg"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 delivery, got %d", n)
	}
	select {
	case <-high.queue:
	default:
		t.Fatal("high priority session did not receive")
	}
	select {
	case <-low.queue:
		t.Fatal("low priority session should not receive")
	default:
	}
	select {
	case <-unavail.queue:
		t.Fatal("unavailable session should not receive")
	default:
	}
}

func TestRouteToBare_NoSession(t *testing.T) {
	r := New()
	_, err := r.RouteToBare(context.Background(), mustBare("ghost@example.com"), []byte("x"))
	if err != ErrNoSession {
		t.Fatalf("expected ErrNoSession, got %v", err)
	}
}

func TestRouteToBare_MultipleAtSamePriority(t *testing.T) {
	r := New()
	s1 := newMock("carol@example.com/a", 3, true)
	s2 := newMock("carol@example.com/b", 3, true)
	r.Register(s1)
	r.Register(s2)

	n, err := r.RouteToBare(context.Background(), mustBare("carol@example.com"), []byte("both"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("expected 2, got %d", n)
	}
}

func TestConcurrentRegisterUnregisterRoute(t *testing.T) {
	r := New()
	const workers = 100
	var wg sync.WaitGroup
	wg.Add(workers * 2)

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			s := newMock("race@example.com/r", 0, true)
			r.Register(s)
			r.Unregister(s)
		}()
	}
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			jid, _ := stanza.Parse("race@example.com/r")
			_ = r.RouteToFull(context.Background(), jid, []byte("x"))
		}()
	}
	wg.Wait()
}

func TestSessionsFor(t *testing.T) {
	r := New()
	s1 := newMock("dan@example.com/phone", 0, true)
	s2 := newMock("dan@example.com/laptop", 0, true)
	other := newMock("eve@example.com/x", 0, true)
	r.Register(s1)
	r.Register(s2)
	r.Register(other)

	got := r.SessionsFor("dan@example.com")
	if len(got) != 2 {
		t.Fatalf("expected 2 sessions for dan@example.com, got %d", len(got))
	}

	r.Unregister(s1)
	got2 := r.SessionsFor("dan@example.com")
	if len(got2) != 1 {
		t.Fatalf("expected 1 session after unregister, got %d", len(got2))
	}

	got3 := r.SessionsFor("nobody@example.com")
	if len(got3) != 0 {
		t.Fatalf("expected 0 sessions for unknown bare JID, got %d", len(got3))
	}
}

func mustBare(s string) stanza.JID {
	j, err := stanza.Parse(s)
	if err != nil {
		panic(err)
	}
	return j.Bare()
}

func TestRouteToRemoteCallsRemoteRouter(t *testing.T) {
	r := New()
	r.SetLocalDomain("a.test")
	mock := &mockRemoteRouter{}
	r.SetRemote(mock)

	to := mustBare("x@b.test")
	_, err := r.RouteToBare(context.Background(), to, []byte("hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.calls.Load() != 1 {
		t.Fatalf("expected 1 remote call, got %d", mock.calls.Load())
	}
}

func TestRouteRemoteWithoutSetterReturnsNoSession(t *testing.T) {
	r := New()
	r.SetLocalDomain("a.test")

	to := mustBare("x@b.test")
	_, err := r.RouteToBare(context.Background(), to, []byte("hello"))
	if err != ErrNoSession {
		t.Fatalf("expected ErrNoSession, got %v", err)
	}
}

func TestRouteLocalUnchanged(t *testing.T) {
	r := New()
	r.SetLocalDomain("a.test")
	mock := &mockRemoteRouter{}
	r.SetRemote(mock)

	s := newMock("alice@a.test/phone", 0, true)
	r.Register(s)

	jid, _ := stanza.Parse("alice@a.test/phone")
	if err := r.RouteToFull(context.Background(), jid, []byte("local")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.calls.Load() != 0 {
		t.Fatal("remote router should not have been called for local domain")
	}
	if got := <-s.queue; string(got) != "local" {
		t.Fatalf("expected 'local', got %q", got)
	}
}

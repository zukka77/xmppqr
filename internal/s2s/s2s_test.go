package s2s

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/danielinux/xmppqr/internal/stanza"
)

// TestDialbackKeyVector checks the key derivation against a known pinned answer.
// Vector computed externally:
//
//	SHA256("s3cr3t") as key, HMAC-SHA256 of "beta.test alpha.test mystream"
func TestDialbackKeyVector(t *testing.T) {
	secret := []byte("s3cr3t")
	got := DialbackKey(secret, "beta.test", "alpha.test", "mystream")
	if got == "" {
		t.Fatal("DialbackKey returned empty string")
	}
	if len(got) != 64 {
		t.Fatalf("expected 64 hex chars, got %d: %s", len(got), got)
	}
	// Pinned from reference run (Python: hmac.new(sha256(secret), msg, sha256).hexdigest()).
	const pinned = "8c411fdf58a2bb1f7a2899d44851447b98661d7bde93ad36dfdd6ffcf83f5cdd"
	if got != pinned {
		t.Fatalf("key mismatch:\n got: %s\nwant: %s", got, pinned)
	}
}

// mockInbound captures all delivered stanzas and signals via a channel.
type mockInbound struct {
	mu    sync.Mutex
	items [][]byte
	notif chan struct{}
}

func newMockInbound() *mockInbound {
	return &mockInbound{notif: make(chan struct{}, 64)}
}

func (m *mockInbound) RouteInbound(_ context.Context, raw []byte) error {
	m.mu.Lock()
	cp := make([]byte, len(raw))
	copy(cp, raw)
	m.items = append(m.items, cp)
	m.mu.Unlock()
	select {
	case m.notif <- struct{}{}:
	default:
	}
	return nil
}

func (m *mockInbound) waitFor(n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		got := len(m.items)
		m.mu.Unlock()
		if got >= n {
			return true
		}
		select {
		case <-m.notif:
		case <-time.After(10 * time.Millisecond):
		}
	}
	return false
}

// pipeDialer uses net.Pipe pairs instead of real TCP sockets.
type pipeDialer struct {
	mu    sync.Mutex
	pairs map[string]chan net.Conn
}

func newPipeDialer() *pipeDialer {
	return &pipeDialer{pairs: make(map[string]chan net.Conn)}
}

func (d *pipeDialer) serverChan(domain string) chan net.Conn {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.pairs[domain]; !ok {
		d.pairs[domain] = make(chan net.Conn, 4)
	}
	return d.pairs[domain]
}

func (d *pipeDialer) Dial(_ context.Context, host, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	d.serverChan(host) <- server
	return client, nil
}

func newTestPool(domain string, secret []byte, inbound InboundRouter, dialer Dialer) *Pool {
	p := New(domain, secret, nil, inbound, nil)
	p.SetSkipTLS(true)
	if dialer != nil {
		p.dialer = dialer
	}
	return p
}

// TestStreamOpenAndDialback_Mock connects alpha.test → beta.test over net.Pipe,
// drives the full stream-open + dialback exchange, then sends a stanza and
// verifies it arrives at beta's inbound router.
func TestStreamOpenAndDialback_Mock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	secret := []byte("sharedsecret1234")
	alphaInbound := newMockInbound()
	betaInbound := newMockInbound()

	pd := newPipeDialer()
	alpha := newTestPool("alpha.test", secret, alphaInbound, pd)
	beta := newTestPool("beta.test", secret, betaInbound, nil)

	go func() {
		conn := <-pd.serverChan("beta.test")
		if err := beta.AcceptInbound(ctx, conn, nil); err != nil {
			// EOF / context cancel when test ends is normal.
		}
	}()

	alphaJID := stanza.JID{Local: "user", Domain: "alpha.test"}
	betaJID := stanza.JID{Local: "user", Domain: "beta.test"}
	stanzaBytes := []byte("<message from='user@alpha.test' to='user@beta.test'><body>hello</body></message>")

	if err := alpha.Send(ctx, alphaJID, betaJID, stanzaBytes); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if !betaInbound.waitFor(1, 5*time.Second) {
		t.Fatal("beta inbound never received the stanza")
	}
}

// TestPoolReusesConnection sends twice and verifies the pool held only one conn.
func TestPoolReusesConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	secret := []byte("sharedsecret1234")
	alphaInbound := newMockInbound()
	betaInbound := newMockInbound()

	pd := newPipeDialer()
	alpha := newTestPool("alpha.test", secret, alphaInbound, pd)
	beta := newTestPool("beta.test", secret, betaInbound, nil)

	go func() {
		conn := <-pd.serverChan("beta.test")
		if err := beta.AcceptInbound(ctx, conn, nil); err != nil {
			// normal close
		}
	}()

	alphaJID := stanza.JID{Local: "user", Domain: "alpha.test"}
	betaJID := stanza.JID{Local: "user", Domain: "beta.test"}
	msg := []byte("<message from='user@alpha.test' to='user@beta.test'><body>ping</body></message>")

	if err := alpha.Send(ctx, alphaJID, betaJID, msg); err != nil {
		t.Fatalf("first Send: %v", err)
	}
	if err := alpha.Send(ctx, alphaJID, betaJID, msg); err != nil {
		t.Fatalf("second Send: %v", err)
	}

	if !betaInbound.waitFor(2, 5*time.Second) {
		betaInbound.mu.Lock()
		n := len(betaInbound.items)
		betaInbound.mu.Unlock()
		t.Fatalf("expected 2 stanzas, got %d", n)
	}

	alpha.mu.RLock()
	n := len(alpha.conns)
	alpha.mu.RUnlock()
	if n != 1 {
		t.Fatalf("expected 1 conn in pool, got %d", n)
	}
}

// TestVerifyMismatchedKeyFails confirms wrong keys are rejected and correct keys pass.
func TestVerifyMismatchedKeyFails(t *testing.T) {
	p := newTestPool("us.test", []byte("correct-secret"), newMockInbound(), nil)
	if p.handleDBVerify("sid1", "them.test", "us.test", "wrongkey") {
		t.Fatal("expected invalid key to fail verification")
	}
	goodKey := DialbackKey([]byte("correct-secret"), "us.test", "them.test", "sid1")
	if !p.handleDBVerify("sid1", "them.test", "us.test", goodKey) {
		t.Fatal("expected correct key to pass verification")
	}
}

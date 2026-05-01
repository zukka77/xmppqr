package s2s

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/danielinux/xmppqr/internal/stanza"
	xmldec "github.com/danielinux/xmppqr/internal/xml"
)

// domainDialer routes Dial(host, ...) calls to a channel keyed by host.
// All pools in a test share one instance so each Dial lands on the right acceptLoop.
type domainDialer struct {
	mu    sync.Mutex
	chans map[string]chan net.Conn
}

func newDomainDialer() *domainDialer {
	return &domainDialer{chans: make(map[string]chan net.Conn)}
}

func (d *domainDialer) getChan(domain string) chan net.Conn {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.chans[domain]; !ok {
		d.chans[domain] = make(chan net.Conn, 8)
	}
	return d.chans[domain]
}

func (d *domainDialer) Dial(_ context.Context, host, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	d.getChan(host) <- server
	return client, nil
}

func runAcceptLoop(ctx context.Context, pool *Pool, domain string, d *domainDialer) {
	ch := d.getChan(domain)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case conn := <-ch:
				go func(c net.Conn) {
					_ = pool.AcceptInbound(ctx, c, nil)
				}(conn)
			}
		}
	}()
}

// TestDialbackBackChannelVerifyValid exercises the full XEP-0220 back-channel
// between two pools with DIFFERENT secrets. Alpha→beta triggers beta to open a
// back-channel to alpha; alpha re-derives the key from its own secret and
// replies valid; beta accepts and routes the stanza.
func TestDialbackBackChannelVerifyValid(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pd := newDomainDialer()

	alpha := newTestPool("alpha.test", []byte("alpha-secret-XYZ"), newMockInbound(), pd)
	alpha.SetVerifyMode(VerifyBackChannel)
	alpha.PinTarget("beta.test", "beta.test:0")

	betaInbound := newMockInbound()
	beta := newTestPool("beta.test", []byte("beta-secret-ABC"), betaInbound, pd)
	beta.SetVerifyMode(VerifyBackChannel)
	beta.PinTarget("alpha.test", "alpha.test:0")

	runAcceptLoop(ctx, alpha, "alpha.test", pd)
	runAcceptLoop(ctx, beta, "beta.test", pd)

	alphaJID := stanza.JID{Local: "user", Domain: "alpha.test"}
	betaJID := stanza.JID{Local: "user", Domain: "beta.test"}
	msg := []byte("<message from='user@alpha.test' to='user@beta.test'><body>backchannel</body></message>")

	if err := alpha.Send(ctx, alphaJID, betaJID, msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !betaInbound.waitFor(1, 10*time.Second) {
		t.Fatal("beta never received the stanza")
	}
}

// TestDialbackBackChannelVerifyInvalid wires a fake "alpha" verifier that always
// returns type='invalid'; beta must reject the inbound connection.
func TestDialbackBackChannelVerifyInvalid(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pd := newDomainDialer()

	// Fake alpha: serves the verify back-channel and always replies invalid.
	go func() {
		ch := pd.getChan("alpha.test")
		for {
			select {
			case <-ctx.Done():
				return
			case conn := <-ch:
				go serveVerifyAlwaysInvalid(ctx, conn)
			}
		}
	}()

	betaInbound := newMockInbound()
	beta := newTestPool("beta.test", []byte("beta-secret"), betaInbound, pd)
	beta.SetVerifyMode(VerifyBackChannel)
	beta.PinTarget("alpha.test", "alpha.test:0")

	// Fake alpha outbound side: dials beta using pd (goes to beta's acceptLoop).
	// Runs in a goroutine because Send blocks until dialback completes.
	runAcceptLoop(ctx, beta, "beta.test", pd)

	// "Real alpha" dials beta — use a second domainDialer that routes
	// beta.test to beta's acceptLoop but alpha.test to the invalid verifier.
	alphaDialer := newDomainDialer()
	alphaDialer.chans["beta.test"] = pd.getChan("beta.test")

	alpha := newTestPool("alpha.test", []byte("alpha-secret"), newMockInbound(), alphaDialer)
	alpha.PinTarget("beta.test", "beta.test:0")

	alphaJID := stanza.JID{Local: "user", Domain: "alpha.test"}
	betaJID := stanza.JID{Local: "user", Domain: "beta.test"}
	msg := []byte("<message from='user@alpha.test' to='user@beta.test'><body>fail</body></message>")

	err := alpha.Send(ctx, alphaJID, betaJID, msg)
	if err == nil {
		t.Fatal("expected Send to fail when back-channel verification returns invalid")
	}
}

// serveVerifyAlwaysInvalid is a minimal XMPP server that reads the client's
// stream open, replies with a stream open + features, then reads a <db:verify>
// and replies type='invalid'.
func serveVerifyAlwaysInvalid(ctx context.Context, nc net.Conn) {
	defer nc.Close()

	dec := xmldec.NewDecoder(nc)
	if _, err := dec.OpenStream(ctx); err != nil {
		return
	}

	streamOpen := fmt.Sprintf(
		"<?xml version='1.0'?><stream:stream xmlns='jabber:server' "+
			"xmlns:stream='http://etherx.jabber.org/streams' "+
			"xmlns:db='%s' from='alpha.test' to='beta.test' id='fakeid' version='1.0'>",
		nsDialback,
	)
	if _, err := nc.Write([]byte(streamOpen)); err != nil {
		return
	}
	features := "<stream:features><dialback xmlns='urn:xmpp:features:dialback'/></stream:features>"
	if _, err := nc.Write([]byte(features)); err != nil {
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		start, _, err := dec.NextElement()
		if err != nil {
			return
		}
		if start.Name.Local == "verify" && start.Name.Space == nsDB {
			id := attrVal(start, "id")
			from := attrVal(start, "from")
			to := attrVal(start, "to")
			reply := fmt.Sprintf(
				"<db:verify xmlns:db='%s' from='%s' to='%s' id='%s' type='invalid'/>",
				nsDialback, to, from, id,
			)
			_, _ = nc.Write([]byte(reply))
			return
		}
	}
}

// TestRateLimiterBlocks confirms that 12 requests within the window drops the last 2.
func TestRateLimiterBlocks(t *testing.T) {
	rl := newRateLimiter(10, time.Minute)
	allowed := 0
	for i := 0; i < 12; i++ {
		if rl.Allow("10.0.0.1") {
			allowed++
		}
	}
	if allowed != 10 {
		t.Fatalf("expected 10 allowed, got %d", allowed)
	}
}

// TestDBVerifyKeyMismatch confirms handleDBVerify rejects wrong keys.
func TestDBVerifyKeyMismatch(t *testing.T) {
	p := newTestPool("receiver.test", []byte("secret"), newMockInbound(), nil)

	good := DialbackKey([]byte("secret"), "receiver.test", "sender.test", "sid1")
	if !p.handleDBVerify("sid1", "sender.test", "receiver.test", good) {
		t.Fatal("correct key should pass")
	}
	if p.handleDBVerify("sid1", "sender.test", "receiver.test", "badkey") {
		t.Fatal("wrong key should fail")
	}
	if p.handleDBVerify("other-sid", "sender.test", "receiver.test", good) {
		t.Fatal("key with wrong streamID should fail")
	}
}

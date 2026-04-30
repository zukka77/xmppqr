//go:build integ

package integ_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

func TestFederationTwoXmppqrInstances(t *testing.T) {
	var sharedSecret [32]byte
	if _, err := rand.Read(sharedSecret[:]); err != nil {
		t.Fatalf("shared secret: %v", err)
	}

	aH := NewHarnessOpts(t, HarnessOpts{Domain: "a.test", EnableS2S: true, DialbackSecret: sharedSecret[:]})
	defer aH.Close()
	bH := NewHarnessOpts(t, HarnessOpts{Domain: "b.test", EnableS2S: true, DialbackSecret: sharedSecret[:]})
	defer bH.Close()

	aH.AddS2SPeer("b.test", bH.S2SAddr())
	bH.AddS2SPeer("a.test", aH.S2SAddr())

	aH.AddUser(t, "alice", "pw")
	bH.AddUser(t, "bob", "pw")

	a := MustDial(t, aH.TLSAddr(), "a.test", "alice", "pw")
	defer a.Close()
	b := MustDial(t, bH.TLSAddr(), "b.test", "bob", "pw")
	defer b.Close()

	if err := a.Send([]byte(`<presence/>`)); err != nil {
		t.Fatalf("alice presence: %v", err)
	}
	if err := b.Send([]byte(`<presence/>`)); err != nil {
		t.Fatalf("bob presence: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	msg := fmt.Sprintf(
		`<message to='%s' type='chat' id='fed1'><body>hello across federation</body></message>`,
		b.JID().String(),
	)
	if err := a.Send([]byte(msg)); err != nil {
		t.Fatalf("alice send: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		start, raw, err := b.NextStanzaWithTimeout(500 * time.Millisecond)
		if err == ErrTimeout {
			continue
		}
		if err != nil {
			t.Fatalf("bob read: %v", err)
		}
		if start.Name.Local == "message" && bytes.Contains(raw, []byte("hello across federation")) {
			return
		}
	}
	t.Fatal("federated message did not arrive")
}

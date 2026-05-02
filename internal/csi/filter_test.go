package csi

import (
	"testing"
)

func TestDefaultIsActivePerXEP0352(t *testing.T) {
	f := New()
	if !f.IsActive() {
		t.Fatal("XEP-0352: client without indication MUST be treated as active")
	}
}

func TestActivePassesAll(t *testing.T) {
	f := New()
	f.SetActive(true)

	cases := []StanzaInfo{
		{Kind: KindMessage, HasBody: true},
		{Kind: KindPresence},
		{Kind: KindIQ},
		{Kind: KindMessage, HasChatState: true},
	}
	for _, si := range cases {
		deliver, hold := f.ShouldDeliver(si)
		if !deliver || hold {
			t.Fatalf("active: expected deliver=true,hold=false for %+v", si)
		}
	}
}

func TestInactiveCoalescesPresence(t *testing.T) {
	f := New()
	f.SetActive(false)

	si := StanzaInfo{Kind: KindPresence, FromJID: "alice@example.com"}
	deliver, hold := f.ShouldDeliver(si)
	if deliver || !hold {
		t.Fatal("inactive presence should not deliver and should hold")
	}

	f.HoldPresence("alice@example.com", []byte("<presence from='alice' n='1'/>"))
	f.HoldPresence("alice@example.com", []byte("<presence from='alice' n='2'/>"))

	held := f.FlushHeld()
	if len(held) != 1 {
		t.Fatalf("expected 1 coalesced presence, got %d", len(held))
	}
	if string(held[0]) != "<presence from='alice' n='2'/>" {
		t.Fatalf("expected last presence, got %q", held[0])
	}
}

func TestInactiveDropsChatState(t *testing.T) {
	f := New()
	f.SetActive(false)

	si := StanzaInfo{Kind: KindMessage, HasChatState: true, HasBody: false}
	deliver, hold := f.ShouldDeliver(si)
	if deliver || hold {
		t.Fatal("chat-state-only message should be dropped (not delivered, not held)")
	}
}

func TestInactiveDeliversMessageWithBody(t *testing.T) {
	f := New()
	f.SetActive(false)

	si := StanzaInfo{Kind: KindMessage, HasBody: true}
	deliver, hold := f.ShouldDeliver(si)
	if !deliver || hold {
		t.Fatal("message with body should always deliver")
	}
}

func TestTransitionFlushesPresence(t *testing.T) {
	f := New()
	f.SetActive(false)

	f.HoldPresence("bob@example.com", []byte("<presence from='bob'/>"))
	f.HoldPresence("carol@example.com", []byte("<presence from='carol'/>"))

	flushed := f.SetActive(true)
	if len(flushed) != 2 {
		t.Fatalf("expected 2 flushed on transition to active, got %d", len(flushed))
	}

	held := f.FlushHeld()
	if len(held) != 0 {
		t.Fatal("pending should be empty after SetActive(true)")
	}
}

func TestIQAlwaysDelivered(t *testing.T) {
	f := New()

	si := StanzaInfo{Kind: KindIQ}
	deliver, hold := f.ShouldDeliver(si)
	if !deliver || hold {
		t.Fatal("IQ should always deliver")
	}
}

func TestErrorStanzaAlwaysDelivered(t *testing.T) {
	f := New()

	si := StanzaInfo{Kind: KindMessage, IsError: true}
	deliver, hold := f.ShouldDeliver(si)
	if !deliver || hold {
		t.Fatal("error stanza should always deliver")
	}
}

func TestMUCSubjectAlwaysDelivered(t *testing.T) {
	f := New()

	si := StanzaInfo{Kind: KindMessage, IsMUCSubject: true}
	deliver, hold := f.ShouldDeliver(si)
	if !deliver || hold {
		t.Fatal("MUC subject change should always deliver")
	}
}

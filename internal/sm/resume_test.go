package sm

import (
	"context"
	"testing"
	"time"

	"github.com/danielinux/xmppqr/internal/stanza"
)

func mustJID(s string) stanza.JID {
	j, err := stanza.Parse(s)
	if err != nil {
		panic(err)
	}
	return j
}

func TestIssueLookup(t *testing.T) {
	st := NewStore(10)
	jid := mustJID("alice@example.com/phone")
	tok, err := st.Issue(context.Background(), jid, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := st.Lookup(tok)
	if !ok {
		t.Fatal("expected found")
	}
	if !got.Equal(jid) {
		t.Fatalf("jid mismatch: %v != %v", got, jid)
	}
	_, ok2 := st.Lookup(tok)
	if ok2 {
		t.Fatal("second lookup should return false (one-shot)")
	}
}

func TestCapacityEvictsOldest(t *testing.T) {
	st := NewStore(2)
	jid := mustJID("bob@example.com/x")
	t1, _ := st.Issue(context.Background(), jid, time.Hour)
	t2, _ := st.Issue(context.Background(), jid, time.Hour)
	t3, _ := st.Issue(context.Background(), jid, time.Hour)

	_, ok1 := st.Lookup(t1)
	if ok1 {
		t.Fatal("t1 should have been evicted")
	}
	_, ok2 := st.Lookup(t2)
	if !ok2 {
		t.Fatal("t2 should still be present")
	}
	_, ok3 := st.Lookup(t3)
	if !ok3 {
		t.Fatal("t3 should still be present")
	}
}

func TestEvict(t *testing.T) {
	st := NewStore(10)
	jid := mustJID("carol@example.com/y")
	tok, _ := st.Issue(context.Background(), jid, time.Hour)
	st.Evict(tok)
	_, ok := st.Lookup(tok)
	if ok {
		t.Fatal("evicted token should not be found")
	}
}

func TestParkAndTake(t *testing.T) {
	st := NewStore(10)
	jid := mustJID("dave@example.com/mobile")
	tok, err := st.Issue(context.Background(), jid, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	state := &ResumableState{
		JID:       jid,
		LastInH:   5,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := st.Park(tok, state); err != nil {
		t.Fatalf("Park: %v", err)
	}
	lookTok, ok := st.LookupByJID(jid)
	if !ok || lookTok != tok {
		t.Fatalf("LookupByJID: got %v %v", lookTok, ok)
	}
	got, ok2 := st.Take(tok)
	if !ok2 {
		t.Fatal("Take: expected found")
	}
	if got.LastInH != 5 {
		t.Fatalf("Take: LastInH=%d want 5", got.LastInH)
	}
	_, ok3 := st.Take(tok)
	if ok3 {
		t.Fatal("second Take should return false")
	}
}

func TestTakeExpired(t *testing.T) {
	st := NewStore(10)
	jid := mustJID("eve@example.com/phone")
	tok, err := st.Issue(context.Background(), jid, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	state := &ResumableState{
		JID:       jid,
		ExpiresAt: time.Now().Add(50 * time.Millisecond),
	}
	if err := st.Park(tok, state); err != nil {
		t.Fatalf("Park: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	_, ok := st.Take(tok)
	if ok {
		t.Fatal("expired token should not be returned by Take")
	}
}

func TestIssueExpiresBeforePark(t *testing.T) {
	st := NewStore(10)
	jid := mustJID("frank@example.com/phone")
	tok, err := st.Issue(context.Background(), jid, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	_, ok := st.Take(tok)
	if ok {
		t.Fatal("expired token (never parked) should not be returned by Take")
	}
}

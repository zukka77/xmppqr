package sm

import (
	"context"
	"testing"

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
	tok, err := st.Issue(context.Background(), jid)
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
	t1, _ := st.Issue(context.Background(), jid)
	t2, _ := st.Issue(context.Background(), jid)
	t3, _ := st.Issue(context.Background(), jid)

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
	tok, _ := st.Issue(context.Background(), jid)
	st.Evict(tok)
	_, ok := st.Lookup(tok)
	if ok {
		t.Fatal("evicted token should not be found")
	}
}

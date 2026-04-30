package block

import (
	"context"
	"strings"
	"testing"

	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage"
)

type memBlock struct {
	data map[string][]storage.JID
}

func newMemBlock() *memBlock {
	return &memBlock{data: make(map[string][]storage.JID)}
}

func (b *memBlock) List(_ context.Context, owner string) ([]storage.JID, error) {
	return append([]storage.JID(nil), b.data[owner]...), nil
}
func (b *memBlock) Add(_ context.Context, owner string, blocked storage.JID) error {
	for _, j := range b.data[owner] {
		if j == blocked {
			return nil
		}
	}
	b.data[owner] = append(b.data[owner], blocked)
	return nil
}
func (b *memBlock) Remove(_ context.Context, owner string, blocked storage.JID) error {
	list := b.data[owner]
	for i, j := range list {
		if j == blocked {
			b.data[owner] = append(list[:i], list[i+1:]...)
			return nil
		}
	}
	return nil
}
func (b *memBlock) Clear(_ context.Context, owner string) error {
	b.data[owner] = nil
	return nil
}

func TestIsBlocked(t *testing.T) {
	mgr := New(newMemBlock())
	ctx := context.Background()

	peer, _ := stanza.Parse("evil@example.com")

	blocked, err := mgr.IsBlocked(ctx, "alice", peer)
	if err != nil {
		t.Fatal(err)
	}
	if blocked {
		t.Fatal("should not be blocked yet")
	}

	if err := mgr.store.Add(ctx, "alice", "evil@example.com"); err != nil {
		t.Fatal(err)
	}

	blocked, err = mgr.IsBlocked(ctx, "alice", peer)
	if err != nil {
		t.Fatal(err)
	}
	if !blocked {
		t.Fatal("should be blocked after add")
	}

	if err := mgr.store.Remove(ctx, "alice", "evil@example.com"); err != nil {
		t.Fatal(err)
	}

	blocked, err = mgr.IsBlocked(ctx, "alice", peer)
	if err != nil {
		t.Fatal(err)
	}
	if blocked {
		t.Fatal("should not be blocked after remove")
	}
}

func TestIQBlockAndList(t *testing.T) {
	mgr := New(newMemBlock())
	ctx := context.Background()

	blockIQ := &stanza.IQ{
		ID:   "b1",
		From: "alice",
		Type: stanza.IQSet,
		Payload: []byte(`<block xmlns='urn:xmpp:blocking'><item jid='spammer@example.com'/></block>`),
	}
	result, err := mgr.HandleIQ(ctx, blockIQ)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil && strings.Contains(string(result), "error") {
		t.Fatalf("unexpected error: %s", result)
	}

	getIQ := &stanza.IQ{
		ID:   "g1",
		From: "alice",
		Type: stanza.IQGet,
	}
	listResult, err := mgr.HandleIQ(ctx, getIQ)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(listResult), "spammer@example.com") {
		t.Fatalf("expected spammer in blocklist, got: %s", listResult)
	}
}

func TestIQUnblockAll(t *testing.T) {
	mgr := New(newMemBlock())
	ctx := context.Background()

	_ = mgr.store.Add(ctx, "bob", "a@example.com")
	_ = mgr.store.Add(ctx, "bob", "b@example.com")

	unblockIQ := &stanza.IQ{
		ID:      "u1",
		From:    "bob",
		Type:    stanza.IQSet,
		Payload: []byte(`<unblock xmlns='urn:xmpp:blocking'/>`),
	}
	result, err := mgr.HandleIQ(ctx, unblockIQ)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil && strings.Contains(string(result), "error") {
		t.Fatalf("unexpected error: %s", result)
	}

	list, err := mgr.List(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("expected empty blocklist, got %v", list)
	}
}

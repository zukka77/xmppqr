package bookmarks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/danielinux/xmppqr/internal/storage"
)

type memPEP struct {
	items map[string]*storage.PEPItem
}

func newMemPEP() *memPEP {
	return &memPEP{items: make(map[string]*storage.PEPItem)}
}

func key(owner, node, item string) string { return owner + "\x00" + node + "\x00" + item }
func nodeKey(owner, node string) string   { return owner + "\x00" + node + "\x00" }

func (m *memPEP) PutNode(_ context.Context, n *storage.PEPNode) error  { return nil }
func (m *memPEP) GetNode(_ context.Context, o, n string) (*storage.PEPNode, error) {
	return nil, nil
}
func (m *memPEP) DeleteNode(_ context.Context, o, n string) error { return nil }
func (m *memPEP) PutItem(_ context.Context, item *storage.PEPItem) error {
	cp := *item
	cp.PublishedAt = time.Now()
	m.items[key(item.Owner, item.Node, item.ItemID)] = &cp
	return nil
}
func (m *memPEP) GetItem(_ context.Context, owner, node, itemID string) (*storage.PEPItem, error) {
	return m.items[key(owner, node, itemID)], nil
}
func (m *memPEP) ListItems(_ context.Context, owner, node string, limit int) ([]*storage.PEPItem, error) {
	prefix := nodeKey(owner, node)
	var out []*storage.PEPItem
	for k, v := range m.items {
		if strings.HasPrefix(k, prefix) {
			out = append(out, v)
		}
	}
	return out, nil
}
func (m *memPEP) DeleteItem(_ context.Context, owner, node, itemID string) error {
	delete(m.items, key(owner, node, itemID))
	return nil
}

func TestAddAndList(t *testing.T) {
	mgr := New(newMemPEP())
	ctx := context.Background()

	if err := mgr.Set(ctx, "alice", "room1@conf.example", []byte(`<conference/>`)); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Set(ctx, "alice", "room2@conf.example", []byte(`<conference/>`)); err != nil {
		t.Fatal(err)
	}

	items, err := mgr.List(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
}

func TestRemove(t *testing.T) {
	mgr := New(newMemPEP())
	ctx := context.Background()

	if err := mgr.Set(ctx, "alice", "room1@conf.example", []byte(`<conference/>`)); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Set(ctx, "alice", "room2@conf.example", []byte(`<conference/>`)); err != nil {
		t.Fatal(err)
	}

	if err := mgr.Remove(ctx, "alice", "room1@conf.example"); err != nil {
		t.Fatal(err)
	}

	items, err := mgr.List(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item after remove, got %d", len(items))
	}
	if items[0].ItemID != "room2@conf.example" {
		t.Fatalf("expected room2, got %s", items[0].ItemID)
	}
}

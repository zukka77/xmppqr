package vcard

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage"
)

// memPEP is a minimal in-memory PEPStore for tests.
type memPEP struct {
	nodes map[string]*storage.PEPNode
	items map[string]*storage.PEPItem
}

func newMemPEP() *memPEP {
	return &memPEP{
		nodes: make(map[string]*storage.PEPNode),
		items: make(map[string]*storage.PEPItem),
	}
}

func pepKey(owner, node, item string) string { return owner + "\x00" + node + "\x00" + item }
func nodeKey(owner, node string) string       { return owner + "\x00" + node }

func (m *memPEP) PutNode(_ context.Context, n *storage.PEPNode) error {
	m.nodes[nodeKey(n.Owner, n.Node)] = n
	return nil
}
func (m *memPEP) GetNode(_ context.Context, owner, node string) (*storage.PEPNode, error) {
	return m.nodes[nodeKey(owner, node)], nil
}
func (m *memPEP) DeleteNode(_ context.Context, owner, node string) error {
	delete(m.nodes, nodeKey(owner, node))
	return nil
}
func (m *memPEP) PutItem(_ context.Context, item *storage.PEPItem) error {
	cp := *item
	cp.PublishedAt = time.Now()
	m.items[pepKey(item.Owner, item.Node, item.ItemID)] = &cp
	return nil
}
func (m *memPEP) GetItem(_ context.Context, owner, node, itemID string) (*storage.PEPItem, error) {
	return m.items[pepKey(owner, node, itemID)], nil
}
func (m *memPEP) ListItems(_ context.Context, owner, node string, limit int) ([]*storage.PEPItem, error) {
	prefix := owner + "\x00" + node + "\x00"
	var out []*storage.PEPItem
	for k, v := range m.items {
		if strings.HasPrefix(k, prefix) {
			out = append(out, v)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}
func (m *memPEP) DeleteItem(_ context.Context, owner, node, itemID string) error {
	delete(m.items, pepKey(owner, node, itemID))
	return nil
}

func (m *memPEP) PutSubscription(_ context.Context, _ *storage.PEPSubscription) error  { return nil }
func (m *memPEP) DeleteSubscription(_ context.Context, _, _, _ string) error            { return nil }
func (m *memPEP) DeleteSubscriptionsForSubscriber(_ context.Context, _, _ string) error { return nil }
func (m *memPEP) ListSubscribers(_ context.Context, _, _ string) ([]string, error)      { return nil, nil }
func (m *memPEP) DeleteNodesForOwner(_ context.Context, _ string) error                 { return nil }

func TestSetGet(t *testing.T) {
	mgr := New(newMemPEP())
	ctx := context.Background()

	vcard := []byte(`<vCard xmlns='vcard-temp'><FN>Alice</FN></vCard>`)
	if err := mgr.Set(ctx, "alice", vcard); err != nil {
		t.Fatal(err)
	}
	got, err := mgr.Get(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(vcard) {
		t.Fatalf("got %q want %q", got, vcard)
	}
}

func TestIQGet_Stored(t *testing.T) {
	mgr := New(newMemPEP())
	ctx := context.Background()

	vcard := []byte(`<vCard xmlns='vcard-temp'><FN>Bob</FN></vCard>`)
	if err := mgr.Set(ctx, "bob", vcard); err != nil {
		t.Fatal(err)
	}

	iq := &stanza.IQ{ID: "g1", From: "bob", Type: stanza.IQGet}
	result, err := mgr.HandleIQ(ctx, iq)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(result), "Bob") {
		t.Fatalf("expected vCard with Bob, got %s", result)
	}
}

func TestIQGet_Unset(t *testing.T) {
	mgr := New(newMemPEP())
	ctx := context.Background()

	iq := &stanza.IQ{ID: "g2", From: "nobody", Type: stanza.IQGet}
	result, err := mgr.HandleIQ(ctx, iq)
	if err != nil {
		t.Fatal(err)
	}
	body := string(result)
	if !strings.Contains(body, "vCard") {
		t.Fatalf("expected empty vCard element, got %s", body)
	}
	if strings.Contains(body, "error") {
		t.Fatalf("unexpected error in response: %s", body)
	}
}

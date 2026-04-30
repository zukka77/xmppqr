package sm

import (
	"testing"
)

func TestEnqueueAckUnacked(t *testing.T) {
	q := New(10)
	for i := 0; i < 5; i++ {
		q.Enqueue([]byte{byte(i)})
	}
	q.Ack(3)
	unacked := q.Unacked()
	if len(unacked) != 2 {
		t.Fatalf("expected 2 unacked, got %d", len(unacked))
	}
	if unacked[0][0] != 3 || unacked[1][0] != 4 {
		t.Fatalf("unexpected unacked content: %v %v", unacked[0], unacked[1])
	}
}

func TestEnqueueFull(t *testing.T) {
	q := New(3)
	q.Enqueue([]byte("a"))
	q.Enqueue([]byte("b"))
	q.Enqueue([]byte("c"))
	_, err := q.Enqueue([]byte("d"))
	if err != ErrFull {
		t.Fatalf("expected ErrFull, got %v", err)
	}
}

func TestAckStale(t *testing.T) {
	q := New(10)
	q.Enqueue([]byte("a"))
	q.Enqueue([]byte("b"))
	q.Enqueue([]byte("c"))
	q.Ack(2)
	q.Ack(1)
	unacked := q.Unacked()
	if len(unacked) != 1 {
		t.Fatalf("stale ack should be no-op; expected 1 unacked, got %d", len(unacked))
	}
}

func TestHCounter(t *testing.T) {
	q := New(10)
	if q.H() != 0 {
		t.Fatal("initial H should be 0")
	}
	h1, _ := q.Enqueue([]byte("x"))
	h2, _ := q.Enqueue([]byte("y"))
	if h1 != 1 || h2 != 2 {
		t.Fatalf("unexpected h values: %d %d", h1, h2)
	}
	if q.H() != 2 {
		t.Fatalf("H() should be 2, got %d", q.H())
	}
}

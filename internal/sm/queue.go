package sm

import (
	"errors"
	"sync"
)

var ErrFull = errors.New("sm: outbound queue full")

type OutQueue struct {
	mu       sync.Mutex
	buf      [][]byte
	capacity int
	h        uint32
	base     uint32
}

func New(capacity int) *OutQueue {
	return &OutQueue{capacity: capacity}
}

func (q *OutQueue) Enqueue(raw []byte) (uint32, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.buf) >= q.capacity {
		return 0, ErrFull
	}
	q.h++
	cp := make([]byte, len(raw))
	copy(cp, raw)
	q.buf = append(q.buf, cp)
	return q.h, nil
}

func (q *OutQueue) Ack(h uint32) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if h <= q.base || h > q.h {
		return
	}
	drop := int(h - q.base)
	if drop > len(q.buf) {
		drop = len(q.buf)
	}
	q.buf = q.buf[drop:]
	q.base = h
}

func (q *OutQueue) Unacked() [][]byte {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.buf) == 0 {
		return nil
	}
	cp := make([][]byte, len(q.buf))
	for i, b := range q.buf {
		c := make([]byte, len(b))
		copy(c, b)
		cp[i] = c
	}
	return cp
}

func (q *OutQueue) H() uint32 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.h
}

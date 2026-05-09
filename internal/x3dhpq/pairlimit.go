package x3dhpq

import (
	"sync"
	"time"
)

type PairLimiterConfig struct {
	Burst         int
	WindowSeconds int
}

func DefaultPairLimiterConfig() PairLimiterConfig {
	return PairLimiterConfig{Burst: 5, WindowSeconds: 10}
}

type pairBucket struct {
	tokens float64
	last   time.Time
}

// PairLimiter implements a per-(from,to) token bucket for stanzas in
// `urn:xmppqr:x3dhpq:pair:0` plus a per-(from-bareJID) bucket for the
// `<verify-device>` IQ verb. The verify bucket has a wider window since the
// verb is rare (typically once per fresh install).
type PairLimiter struct {
	mu     sync.Mutex
	pair   map[string]*pairBucket
	verify map[string]*pairBucket
	cfg    PairLimiterConfig
}

func NewPairLimiter(cfg PairLimiterConfig) *PairLimiter {
	if cfg.Burst <= 0 {
		cfg.Burst = 5
	}
	if cfg.WindowSeconds <= 0 {
		cfg.WindowSeconds = 10
	}
	return &PairLimiter{
		pair:   make(map[string]*pairBucket),
		verify: make(map[string]*pairBucket),
		cfg:    cfg,
	}
}

func (l *PairLimiter) AllowPair(fromFull, toFull string) bool {
	if l == nil {
		return true
	}
	return l.consume(l.pair, fromFull+"\x00"+toFull, float64(l.cfg.Burst), float64(l.cfg.WindowSeconds))
}

func (l *PairLimiter) AllowVerify(fromFull string) bool {
	if l == nil {
		return true
	}
	return l.consume(l.verify, fromFull, 3, 60)
}

func (l *PairLimiter) consume(table map[string]*pairBucket, key string, burst, windowSecs float64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := table[key]
	if !ok {
		b = &pairBucket{tokens: burst, last: now}
		table[key] = b
	}
	if !b.last.IsZero() {
		elapsed := now.Sub(b.last).Seconds()
		refill := elapsed * (burst / windowSecs)
		b.tokens += refill
		if b.tokens > burst {
			b.tokens = burst
		}
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

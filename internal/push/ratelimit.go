package push

import (
	"sync"
	"time"
)

const (
	defaultBurst    = 10
	defaultInterval = time.Minute
)

type deviceState struct {
	tokens   float64
	lastFill time.Time
}

type rateLimiter struct {
	mu       sync.Mutex
	devices  map[string]*deviceState
	rate     float64 // tokens per second
	maxBurst float64
}

func newRateLimiter(perMinute int, burst int) *rateLimiter {
	return &rateLimiter{
		devices:  make(map[string]*deviceState),
		rate:     float64(perMinute) / 60.0,
		maxBurst: float64(burst),
	}
}

func (rl *rateLimiter) Allow(deviceKey string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	ds, ok := rl.devices[deviceKey]
	if !ok {
		ds = &deviceState{tokens: rl.maxBurst, lastFill: now}
		rl.devices[deviceKey] = ds
	}

	elapsed := now.Sub(ds.lastFill).Seconds()
	ds.tokens += elapsed * rl.rate
	if ds.tokens > rl.maxBurst {
		ds.tokens = rl.maxBurst
	}
	ds.lastFill = now

	if ds.tokens < 1 {
		return false
	}
	ds.tokens--
	return true
}

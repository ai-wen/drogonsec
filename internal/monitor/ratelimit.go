package monitor

import (
	"sync"
	"time"
)

// tokenBucket is a simple in-process token-bucket rate limiter.
// It is safe for concurrent use.
type tokenBucket struct {
	mu       sync.Mutex
	tokens   int
	capacity int
	refillAt time.Time
	window   time.Duration
}

// newTokenBucket creates a bucket that allows up to capacity requests per window.
func newTokenBucket(capacity int, window time.Duration) *tokenBucket {
	return &tokenBucket{
		tokens:   capacity,
		capacity: capacity,
		refillAt: time.Now().Add(window),
		window:   window,
	}
}

// Allow returns true and consumes one token if the bucket is non-empty.
// When the window expires the bucket refills to capacity.
func (b *tokenBucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	if now.After(b.refillAt) {
		b.tokens = b.capacity
		b.refillAt = now.Add(b.window)
	}
	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

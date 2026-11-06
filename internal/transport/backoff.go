package transport

import (
	"math/rand/v2"
	"time"
)

// Backoff is exponential backoff with jitter: Min, Min*Factor, ... capped at
// Max, each multiplied by a random factor within 1 +/- Jitter.
type Backoff struct {
	Min, Max time.Duration
	Factor   float64
	Jitter   float64
	// Rand returns a value in [0,1); defaults to math/rand/v2.
	Rand func() float64

	cur time.Duration
}

// DefaultBackoff is the design's reconnect policy: 1 s to 60 s, factor 2,
// +/- 20 % jitter.
func DefaultBackoff() Backoff {
	return Backoff{Min: time.Second, Max: 60 * time.Second, Factor: 2, Jitter: 0.2}
}

// Next returns the delay before the next attempt and advances the sequence.
func (b *Backoff) Next() time.Duration {
	if b.cur == 0 {
		b.cur = b.Min
	}
	base := b.cur
	next := time.Duration(float64(b.cur) * b.Factor)
	if next > b.Max {
		next = b.Max
	}
	b.cur = next
	r := rand.Float64
	if b.Rand != nil {
		r = b.Rand
	}
	f := 1 + b.Jitter*(2*r()-1)
	return time.Duration(float64(base) * f)
}

// Reset restarts the sequence at Min.
func (b *Backoff) Reset() { b.cur = 0 }

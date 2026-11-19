// Package ratelimit bounds how often one caller may hit the endpoints that
// relay credentials or write: a token bucket per key, in memory, so a guess
// loop or a runaway client is slowed on each replica. The hook and the
// service-keyed routes are not limited: they are the hot path and the key
// already restricts who can call them.
package ratelimit

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type bucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// Limiter allows perMinute requests per key, with a burst of the same size.
type Limiter struct {
	perMinute int
	now       func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

// New returns a limiter; perMinute <= 0 disables it.
func New(perMinute int) *Limiter {
	return &Limiter{perMinute: perMinute, now: time.Now, buckets: map[string]*bucket{}}
}

// Allow reports whether key may proceed now and, when it may not, how long
// until it may.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	if l.perMinute <= 0 {
		return true, 0
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buckets) >= 10_000 {
		for k, b := range l.buckets {
			if now.Sub(b.lastSeen) > time.Minute {
				delete(l.buckets, k)
			}
		}
	}
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{limiter: rate.NewLimiter(rate.Limit(float64(l.perMinute)/60), l.perMinute)}
		l.buckets[key] = b
	}
	b.lastSeen = now
	r := b.limiter.ReserveN(now, 1)
	if delay := r.DelayFrom(now); delay > 0 {
		r.CancelAt(now)
		return false, delay
	}
	return true, 0
}

// Middleware answers 429 with Retry-After when keyFn(r) is over its budget.
func (l *Limiter) Middleware(keyFn func(*http.Request) string, reject func(http.ResponseWriter, *http.Request)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ok, wait := l.Allow(keyFn(r))
			if !ok {
				w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
				reject(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

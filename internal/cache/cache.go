// Package cache holds the service's short-lived lookups. Memory is one cache
// per replica; a shared implementation (Redis) only has to satisfy Cache, so
// the choice is made where the caches are built, not where they are used.
package cache

import (
	"context"
	"sync"
	"time"
)

// Cache stores values under a key for a bounded time. Values must be plain
// data: a shared implementation serializes them.
type Cache[T any] interface {
	// Get returns the value under key while it has not expired.
	Get(ctx context.Context, key string) (value T, ok bool, err error)
	Set(ctx context.Context, key string, value T, ttl time.Duration) error
}

type entry[T any] struct {
	value   T
	expires time.Time
}

// Memory is an in-process Cache. When it holds more than maxEntries, a Set
// first drops every expired entry.
type Memory[T any] struct {
	maxEntries int
	now        func() time.Time

	mu      sync.Mutex
	entries map[string]entry[T]
}

func NewMemory[T any](maxEntries int) *Memory[T] {
	return &Memory[T]{maxEntries: maxEntries, now: time.Now, entries: map[string]entry[T]{}}
}

func (m *Memory[T]) Get(_ context.Context, key string) (T, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	if !ok || !m.now().Before(e.expires) {
		var zero T
		return zero, false, nil
	}
	return e.value, true, nil
}

func (m *Memory[T]) Set(_ context.Context, key string, value T, ttl time.Duration) error {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.entries) >= m.maxEntries {
		for k, e := range m.entries {
			if !now.Before(e.expires) {
				delete(m.entries, k)
			}
		}
	}
	m.entries[key] = entry[T]{value, now.Add(ttl)}
	return nil
}

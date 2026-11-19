package cache

import (
	"context"
	"testing"
	"time"
)

func TestMemoryExpires(t *testing.T) {
	m := NewMemory[int](10)
	now := time.Unix(1000, 0)
	m.now = func() time.Time { return now }
	ctx := context.Background()

	if err := m.Set(ctx, "a", 1, time.Second); err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := m.Get(ctx, "a"); !ok || v != 1 {
		t.Fatalf("fresh: %v %v", v, ok)
	}
	now = now.Add(time.Second)
	if _, ok, _ := m.Get(ctx, "a"); ok {
		t.Fatal("an entry at its expiry is stale")
	}
}

func TestMemoryMissIsNotAnError(t *testing.T) {
	m := NewMemory[string](10)
	v, ok, err := m.Get(context.Background(), "nope")
	if ok || err != nil || v != "" {
		t.Fatalf("%q %v %v", v, ok, err)
	}
}

func TestMemorySweepsExpiredEntriesWhenFull(t *testing.T) {
	m := NewMemory[int](2)
	now := time.Unix(1000, 0)
	m.now = func() time.Time { return now }
	ctx := context.Background()

	_ = m.Set(ctx, "old", 1, time.Second)
	_ = m.Set(ctx, "live", 2, time.Minute)
	now = now.Add(2 * time.Second)
	_ = m.Set(ctx, "new", 3, time.Minute)

	if len(m.entries) != 2 {
		t.Fatalf("%d entries, want the expired one gone", len(m.entries))
	}
	if _, ok, _ := m.Get(ctx, "live"); !ok {
		t.Fatal("a live entry must survive the sweep")
	}
}

package ratelimit

import (
	"testing"
	"time"
)

func TestAllowsTheBurstThenWaits(t *testing.T) {
	l := New(3)
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("ip"); !ok {
			t.Fatalf("request %d refused inside the burst", i+1)
		}
	}
	ok, wait := l.Allow("ip")
	if ok || wait <= 0 {
		t.Fatalf("fourth request: ok=%v wait=%v", ok, wait)
	}
	if ok, _ := l.Allow("other"); !ok {
		t.Fatal("keys are independent")
	}
	now = now.Add(time.Minute)
	if ok, _ := l.Allow("ip"); !ok {
		t.Fatal("the budget refills")
	}
}

func TestDisabled(t *testing.T) {
	l := New(0)
	for i := 0; i < 100; i++ {
		if ok, _ := l.Allow("ip"); !ok {
			t.Fatal("a zero rate must disable the limiter")
		}
	}
}

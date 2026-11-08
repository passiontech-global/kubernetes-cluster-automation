package hostmetrics

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// TestRegister: nil registry is a no-op; a real registry accepts the
// collector; a second registration fails (DuplicateMetric) instead of
// panicking.
func TestRegister(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	if err := c.Register(nil); err != nil {
		t.Fatalf("nil reg err=%v", err)
	}
	reg := prometheus.NewRegistry()
	if err := c.Register(reg); err != nil {
		t.Fatalf("register err=%v", err)
	}
	if err := c.Register(reg); err == nil {
		t.Fatal("duplicate registration want error")
	}
}

// TestLatchesWrapper: the subsystem half wraps the same collector and
// Run returns promptly on a cancelled ctx (one refresh tick, no
// ticker, kmsg session released).
func TestLatchesWrapper(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	l := c.Latches()
	if l.Collector() != c {
		t.Fatal("Collector() not the wrapped collector")
	}
	if l.Name() != "hostmetrics" {
		t.Fatalf("name=%q", l.Name())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		l.Run(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return on a cancelled ctx")
	}
	if c.kf == nil {
		t.Fatal("kernel-failure engine missing")
	}
}

// TestLatchSeenBookPrev: zero stamp = still active, non-zero = seen
// cleared.
func TestLatchSeenBookPrev(t *testing.T) {
	b := &latchSeenBook{m: map[string]time.Time{
		"state-active":  {},
		"state-cleared": time.Now(),
	}}
	prev := b.prev()
	if len(prev) != 2 || !prev["state-active"] || prev["state-cleared"] {
		t.Fatalf("prev=%v", prev)
	}
}

// TestCPUDeliveredSetSink: the sink lands mu-guarded and reads back.
func TestCPUDeliveredSetSink(t *testing.T) {
	p := &cpuDeliveredProbe{}
	p.setSink(42)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sink != 42 {
		t.Fatalf("sink=%d want 42", p.sink)
	}
}

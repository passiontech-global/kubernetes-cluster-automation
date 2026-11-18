// dns_resolv_internal_test.go — Wave-5 P0: the resolv.conf readers
// are bounded (O_NONBLOCK + 64KiB LimitReader) so a hostile or
// bind-mounted path under a pause mount ns cannot pin the 60s check.
package pods

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestReadResolvLimitedCap(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "resolv.conf")
	// First nameserver is inside the 64KiB window; the second one is
	// deliberately pushed past it.
	body := "nameserver 1.1.1.1\n" + strings.Repeat("# pad\n", resolvReadLimit/6) + "nameserver 8.8.8.8\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	ns, clusterLocal := nameserverSet(p)
	if clusterLocal {
		t.Fatal("pad made it look ClusterFirst")
	}
	if len(ns) != 1 || ns[0] != "1.1.1.1" {
		t.Fatalf("ns=%v want only the in-window 1.1.1.1", ns)
	}
	// The bounded read also feeds the overflow census — no nameserver
	// count from beyond the cap.
	ov, _, ok := checkResolvOverflow(p)
	if !ok || ov {
		t.Fatalf("overflow=%v ok=%v want false/true", ov, ok)
	}
}

func TestReadResolvLimitedMissingFile(t *testing.T) {
	if _, ok := readResolvLimited(filepath.Join(t.TempDir(), "absent")); ok {
		t.Fatal("missing resolv.conf reported as readable")
	}
}

// TestReadResolvLimitedRejectsFIFO: an untrusted container can bind-
// mount a FIFO over its resolv.conf. O_NONBLOCK registers the fd with
// Go's epoll netpoller and io.ReadAll parks until CycleTimeout unless
// the regular-file guard rejects it BEFORE the read.
func TestReadResolvLimitedRejectsFIFO(t *testing.T) {
	p := filepath.Join(t.TempDir(), "resolv.conf")
	if err := unix.Mkfifo(p, 0o644); err != nil {
		t.Skipf("FIFO not supported here: %v", err)
	}
	type result struct{ ok bool }
	done := make(chan result, 1)
	go func() {
		_, ok := readResolvLimited(p)
		done <- result{ok: ok}
	}()
	select {
	case r := <-done:
		if r.ok {
			t.Fatal("FIFO reported as a readable resolv.conf")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("readResolvLimited blocked on a FIFO (epoll netpoller hang)")
	}
}

// TestIsLoopbackNS covers the whole 127/8 range plus IPv6 loopback,
// not just the three hardcoded strings the old version knew.
func TestIsLoopbackNS(t *testing.T) {
	for _, ip := range []string{
		"127.0.0.1", "127.0.0.53", "127.0.0.54", "127.42.1.7", "::1",
		" 127.0.0.99 ",
	} {
		if !isLoopbackNS(ip) {
			t.Errorf("isLoopbackNS(%q) = false, want true", ip)
		}
	}
	for _, ip := range []string{"1.1.1.1", "10.0.0.1", "::ffff:8.8.8.8", "", "not-an-ip"} {
		if isLoopbackNS(ip) {
			t.Errorf("isLoopbackNS(%q) = true, want false", ip)
		}
	}
}

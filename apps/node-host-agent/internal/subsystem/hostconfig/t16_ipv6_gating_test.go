package hostconfig

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// conntrack-arp-pressure: the IPv6 gc_thresh keys join the T16 pair list only when
// the kernel exposes the ndisc table — an unconditional key would
// fail sysctl --system on an IPv6-less host.
func TestT16PairsIPv6Gated(t *testing.T) {
	hr := t.TempDir()
	r := &Reconciler{}
	r.cfg.HostRoot = hr
	c := &cyc{r: r}
	has := func(k string) bool {
		for _, kv := range c.t16Pairs() {
			if kv[0] == k {
				return true
			}
		}
		return false
	}
	// Create the kernel knob under HostRoot — fileExists picks it up.
	p := filepath.Join(hr, "proc/sys/net/ipv6/neigh/default")
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "gc_thresh3"), []byte("1024\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{
		"net.ipv6.neigh.default.gc_thresh1",
		"net.ipv6.neigh.default.gc_thresh2",
		"net.ipv6.neigh.default.gc_thresh3",
	} {
		if !has(k) {
			t.Fatalf("%s missing from t16Pairs with gc_thresh3 present", k)
		}
	}
	// Absent HostRoot knob — ipv6 keys appear only if the REAL host
	// /proc exposes them (uncontrollable), so assert via the
	// HostRoot-prefixed path only when the real knob is absent too.
	if !fileExistsNoRoot("/proc/sys/net/ipv6/neigh/default/gc_thresh3") {
		if err := os.RemoveAll(filepath.Join(hr, "proc")); err != nil {
			t.Fatal(err)
		}
		if has("net.ipv6.neigh.default.gc_thresh3") {
			t.Fatal("ipv6 gc_thresh emitted without a kernel knob")
		}
	}
	// IPv4 keys are always present.
	if !slices.ContainsFunc(c.t16Pairs(),
		func(kv [2]string) bool { return kv[0] == "net.ipv4.neigh.default.gc_thresh3" }) {
		t.Fatal("ipv4 gc_thresh3 missing from t16Pairs")
	}
}

// conntrack-port-pressure: the sysctl drop-in must widen the ephemeral source-port
// range and allow TIME_WAIT reuse — the pair that prevents
// EADDRNOTAVAIL on gateway/proxy churn bursts.
func TestT16PairsEphemeralPortHygiene(t *testing.T) {
	c := &cyc{r: &Reconciler{}}
	pairs := map[string]string{}
	for _, kv := range c.t16Pairs() {
		pairs[kv[0]] = kv[1]
	}
	if got := pairs["net.ipv4.ip_local_port_range"]; got != "10240 65535" {
		t.Fatalf("ip_local_port_range = %q want \"10240 65535\"", got)
	}
	if got := pairs["net.ipv4.tcp_tw_reuse"]; got != "1" {
		t.Fatalf("tcp_tw_reuse = %q want \"1\"", got)
	}
}

// aio-pressure: fs.aio-max-nr joins the T16 pair list only when the
// kernel exposes the aio table — an unconditional key would fail
// sysctl --system on an aio-less kernel.
func TestT16PairsAIOMaxGated(t *testing.T) {
	hr := t.TempDir()
	r := &Reconciler{}
	r.cfg.HostRoot = hr
	c := &cyc{r: r}
	p := filepath.Join(hr, "proc/sys/fs")
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "aio-max-nr"), []byte("65536\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	found := ""
	for _, kv := range c.t16Pairs() {
		if kv[0] == "fs.aio-max-nr" {
			found = kv[1]
		}
	}
	if found != "4194304" {
		t.Fatalf("fs.aio-max-nr pair = %q want \"4194304\" with the knob present (kernel-resource-table-tuning)", found)
	}
	// Knob removed → the pair must drop (unless the REAL host /proc
	// exposes aio, which is out of the test's control).
	if err := os.Remove(filepath.Join(p, "aio-max-nr")); err != nil {
		t.Fatal(err)
	}
	if !fileExistsNoRoot("/proc/sys/fs/aio-max-nr") {
		for _, kv := range c.t16Pairs() {
			if kv[0] == "fs.aio-max-nr" {
				t.Fatal("fs.aio-max-nr emitted without a kernel knob")
			}
		}
	}
}

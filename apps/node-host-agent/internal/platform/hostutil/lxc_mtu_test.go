// lxc_mtu_test.go — W16-NM4 fixture sysfs coverage for
// MaxPodLxcMTU: hex-name matching, lxc_health exclusion and the
// MAX-wins aggregation.
package hostutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMaxPodLxcMTU(t *testing.T) {
	dir := t.TempDir()
	write := func(iface, mtu string) {
		t.Helper()
		d := filepath.Join(dir, iface)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "mtu"), []byte(mtu+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// No lxc* at all → no vote.
	if _, ok := MaxPodLxcMTU(dir); ok {
		t.Fatal("no lxc interface must yield ok=false")
	}
	write("lxc_health", "1500") // excluded by name, never votes
	write("lxcdead01", "1300")
	write("lxc2f", "1500")   // stale pod veth — the max
	write("eth0", "1500")    // not an lxc name
	write("lxcZZZZ", "9999") // non-hex suffix — not a pod veth
	write("lxc1234", "9999") // hex ok — would win; no mtu file below
	if err := os.Remove(filepath.Join(dir, "lxc1234", "mtu")); err != nil {
		t.Fatal(err)
	}
	max, ok := MaxPodLxcMTU(dir)
	if !ok || max != 1500 {
		t.Fatalf("MaxPodLxcMTU=%d,%v want 1500,true (max over lxcdead01/lxc2f)", max, ok)
	}
	// Aligned pods → still reports the (now lower) max.
	write("lxc2f", "1300")
	max, ok = MaxPodLxcMTU(dir)
	if !ok || max != 1300 {
		t.Fatalf("aligned: MaxPodLxcMTU=%d,%v want 1300,true", max, ok)
	}
	// Missing sysfs root → no vote, never an error.
	if _, ok := MaxPodLxcMTU(filepath.Join(dir, "no-such-net")); ok {
		t.Fatal("unreadable sysfs must yield ok=false")
	}
}

// nic_health_test.go — physical-NIC health coverage: the default-
// route uplink pick (virtual-iface exclusion, metric ordering), the
// carrier/CRC/TX-timeout window signatures, the two-clean-window
// exit hold and the inconclusive-input rule.
package kernelfail

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
)

// nicFixture lays out the route table + sysfs counters under the
// kfixture roots and returns the paths tests rewrite per tick.
type nicFixture struct {
	route   string
	carrier string
	crc     string
	frame   string
	now     time.Time
}

func seedNICFixture(t *testing.T, f *fixture) *nicFixture {
	t.Helper()
	// r.deps (post-New) carries the defaulted SysClassNetDir /
	// RouteFile — f.deps is the pre-New copy and leaves them empty.
	nf := &nicFixture{
		route:   f.r.deps.RouteFile,
		carrier: filepath.Join(f.r.deps.SysClassNetDir, "eth0", "carrier_changes"),
		crc:     filepath.Join(f.r.deps.SysClassNetDir, "eth0", "statistics", "rx_crc_errors"),
		frame:   filepath.Join(f.r.deps.SysClassNetDir, "eth0", "statistics", "rx_frame_errors"),
		now:     time.Now(),
	}
	for _, p := range []string{nf.route, nf.carrier, nf.crc, nf.frame} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Default route via eth0 (metric 100); a lower-metric virtual
	// default route must lose to the physical one.
	writePrefailFile(t, nf.route,
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"+
			"cali12345\t00000000\t010011AC\t0003\t0\t0\t50\t00000000\t0\t0\t0\n"+
			"eth0\t00000000\t010011AC\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"+
			"eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n")
	f.deps.Clock.Set(func() time.Time { return nf.now })
	return nf
}

// setNICCounters rewrites the eth0 counter files for the next tick.
func (nf *nicFixture) setCounters(t *testing.T, carrier, crc, frame uint64) {
	t.Helper()
	writePrefailFile(t, nf.carrier, fmt.Sprintf("%d\n", carrier))
	writePrefailFile(t, nf.crc, fmt.Sprintf("%d\n", crc))
	writePrefailFile(t, nf.frame, fmt.Sprintf("%d\n", frame))
}

// advance moves the fixture clock forward and runs one tick.
func (nf *nicFixture) advance(t *testing.T, f *fixture, d time.Duration) {
	t.Helper()
	nf.now = nf.now.Add(d)
	f.r.updateNICHealth()
}

func nicLatchSet(r *Runner) bool {
	_, err := os.Stat(r.deps.Store.Path(latchdefs.LatchHostNetworkProblems))
	return err == nil
}

func TestPhysicalUplinkIfacePicksPhysicalDefault(t *testing.T) {
	f := kfixture(t)
	nf := seedNICFixture(t, f)
	if got := physicalUplinkIface(nf.route); got != "eth0" {
		t.Fatalf("uplink=%q want eth0 (cali12345 is virtual despite lower metric)", got)
	}
}

func TestPhysicalUplinkIfaceMetricOrder(t *testing.T) {
	f := kfixture(t)
	nf := seedNICFixture(t, f)
	writePrefailFile(t, nf.route,
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"+
			"eth1\t00000000\t010011AC\t0003\t0\t0\t50\t00000000\t0\t0\t0\n"+
			"eth0\t00000000\t010011AC\t0003\t0\t0\t100\t00000000\t0\t0\t0\n")
	if got := physicalUplinkIface(nf.route); got != "eth1" {
		t.Fatalf("uplink=%q want eth1 (lowest metric)", got)
	}
	// No default route at all → inconclusive.
	writePrefailFile(t, nf.route,
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"+
			"eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n")
	if got := physicalUplinkIface(nf.route); got != "" {
		t.Fatalf("uplink=%q want empty (no default route)", got)
	}
}

func TestIsVirtualIface(t *testing.T) {
	for name, want := range map[string]bool{
		"eth0": false, "ens18": false, "eno1": false,
		"lo": true, "cali12345": true, "cilium_host": true,
		"lxc123": true, "veth456": true, "neb1": true, "wg0": true,
		"docker0": true, "cni0": true, "virbr0": true,
		"flannel.1": true, "tailscale0": true, "": true,
	} {
		if got := isVirtualIface(name); got != want {
			t.Fatalf("isVirtualIface(%q)=%v want %v", name, got, want)
		}
	}
}

func TestNICCarrierFlapLatches(t *testing.T) {
	f := kfixture(t)
	nf := seedNICFixture(t, f)
	nf.setCounters(t, 100, 0, 0)
	f.r.updateNICHealth() // baseline sample
	nf.advance(t, f, 6*time.Minute)
	// carrier_changes +5 over the trailing 5m (>= threshold 4).
	nf.setCounters(t, 105, 0, 0)
	f.r.updateNICHealth()
	if !nicLatchSet(f.r) {
		t.Fatal("carrier flap did not arm state-host-network-problems")
	}
	// Two clean 5m windows later the latch must Exit.
	nf.advance(t, f, 6*time.Minute) // now-lastSig = 6m — still held
	if !nicLatchSet(f.r) {
		t.Fatal("latch exited before the two-clean-window hold")
	}
	nf.advance(t, f, 5*time.Minute) // now-lastSig = 11m — release
	if nicLatchSet(f.r) {
		t.Fatal("latch held past the clean hold")
	}
}

func TestNICSubThresholdStaysClean(t *testing.T) {
	f := kfixture(t)
	nf := seedNICFixture(t, f)
	nf.setCounters(t, 100, 0, 0)
	f.r.updateNICHealth()
	nf.advance(t, f, 6*time.Minute)
	nf.setCounters(t, 103, 0, 0) // +3 < threshold 4
	f.r.updateNICHealth()
	if nicLatchSet(f.r) {
		t.Fatal("sub-threshold carrier delta armed the latch")
	}
}

func TestNICTXTimeoutSignature(t *testing.T) {
	f := kfixture(t)
	nf := seedNICFixture(t, f)
	nf.setCounters(t, 100, 0, 0)
	f.r.updateNICHealth()
	// Two watchdog timeouts on eth0 within 10m (threshold 2).
	f.r.noteNetdevTxTimeout("NETDEV WATCHDOG: eth0 (eth0): transmit queue 0 timed out")
	f.r.noteNetdevTxTimeout("NETDEV WATCHDOG: eth0 (eth0): transmit queue 0 timed out")
	// A timeout on a DIFFERENT iface must not count.
	f.r.noteNetdevTxTimeout("NETDEV WATCHDOG: wg0 (wg0): transmit queue 0 timed out")
	f.r.updateNICHealth()
	if !nicLatchSet(f.r) {
		t.Fatal("2 TX timeouts on the uplink did not arm the latch")
	}
}

func TestNICCRErrorsNeedTwoWindows(t *testing.T) {
	// Sub-threshold in BOTH windows — 30 errors per 5m never reaches
	// the 50 threshold, so no latch even though the total is 60.
	f := kfixture(t)
	nf := seedNICFixture(t, f)
	nf.setCounters(t, 100, 0, 0)
	f.r.updateNICHealth() // t0
	nf.advance(t, f, 5*time.Minute)
	nf.setCounters(t, 100, 30, 0) // +30 in window 1
	f.r.updateNICHealth()
	nf.advance(t, f, 5*time.Minute)
	nf.setCounters(t, 100, 60, 0) // +30 in window 2
	f.r.updateNICHealth()
	if nicLatchSet(f.r) {
		t.Fatal("sub-threshold CRC deltas armed the latch")
	}

	// Sustained: +60 in EACH of two consecutive 5m windows.
	f2 := kfixture(t)
	nf2 := seedNICFixture(t, f2)
	nf2.setCounters(t, 100, 0, 0)
	f2.r.updateNICHealth() // t0
	nf2.advance(t, f2, 5*time.Minute)
	nf2.setCounters(t, 100, 60, 0) // +60 window 1
	f2.r.updateNICHealth()
	if nicLatchSet(f2.r) {
		t.Fatal("single clean-then-dirty window armed the latch early")
	}
	nf2.advance(t, f2, 5*time.Minute)
	nf2.setCounters(t, 100, 120, 0) // +60 window 2
	f2.r.updateNICHealth()
	if !nicLatchSet(f2.r) {
		t.Fatal("sustained CRC errors did not arm the latch")
	}

	// One burst then quiet — the second window stays clean, so the
	// signature must NOT fire.
	f3 := kfixture(t)
	nf3 := seedNICFixture(t, f3)
	nf3.setCounters(t, 100, 0, 0)
	f3.r.updateNICHealth()
	nf3.advance(t, f3, 5*time.Minute)
	nf3.setCounters(t, 100, 120, 0) // +120 window 1
	f3.r.updateNICHealth()
	nf3.advance(t, f3, 5*time.Minute)
	nf3.setCounters(t, 100, 120, 0) // +0 window 2
	f3.r.updateNICHealth()
	if nicLatchSet(f3.r) {
		t.Fatal("single-window CRC burst armed the latch")
	}
}

func TestNICInconclusiveNeverMovesLatch(t *testing.T) {
	f := kfixture(t)
	nf := seedNICFixture(t, f)
	nf.setCounters(t, 100, 0, 0)
	f.r.updateNICHealth()
	// Remove the route table — no physical uplink → inconclusive.
	if err := os.Remove(nf.route); err != nil {
		t.Fatal(err)
	}
	// Even with a pending TX signature the latch must not arm.
	f.r.noteNetdevTxTimeout("NETDEV WATCHDOG: eth0 (eth0): transmit queue 0 timed out")
	f.r.noteNetdevTxTimeout("NETDEV WATCHDOG: eth0 (eth0): transmit queue 0 timed out")
	f.r.updateNICHealth()
	if nicLatchSet(f.r) {
		t.Fatal("missing route table armed the latch")
	}
	// Restore and let the events count.
	writePrefailFile(t, nf.route,
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"+
			"eth0\t00000000\t010011AC\t0003\t0\t0\t100\t00000000\t0\t0\t0\n")
	f.r.updateNICHealth()
	if !nicLatchSet(f.r) {
		t.Fatal("restored route did not evaluate pending TX timeouts")
	}
}

func TestNICCounterResetDoesNotFabricateDelta(t *testing.T) {
	f := kfixture(t)
	nf := seedNICFixture(t, f)
	nf.setCounters(t, 1000, 0, 0)
	f.r.updateNICHealth()
	nf.advance(t, f, 6*time.Minute)
	// Counters reset (iface re-created) — a negative delta must not
	// read as a flap.
	nf.setCounters(t, 2, 0, 0)
	f.r.updateNICHealth()
	if nicLatchSet(f.r) {
		t.Fatal("counter reset fabricated a carrier flap")
	}
}

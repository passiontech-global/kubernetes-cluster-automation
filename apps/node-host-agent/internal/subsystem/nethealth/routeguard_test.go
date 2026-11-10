package nethealth

import (
	"context"
	"encoding/binary"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/nethealth/routewatch"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// --- netlink message decoding ---

// nlmsg serializes a bare nlmsghdr of the given type — netlink is
// host byte order, binary.NativeEndian matches the decoder.
func nlmsg(typ uint16) []byte {
	return nlmsgBody(typ, nil)
}

// nlmsgBody serializes a full nlmsg: header + payload (nlmsg_len
// covers exactly both — no trailing pad, like the kernel's last
// message in a datagram).
func nlmsgBody(typ uint16, payload []byte) []byte {
	b := make([]byte, unix.NLMSG_HDRLEN+len(payload))
	binary.NativeEndian.PutUint32(b[0:4], uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:6], typ)
	copy(b[unix.NLMSG_HDRLEN:], payload)
	return b
}

// rtmsgBytes builds a struct rtmsg payload: the 12-byte fixed
// header (family at [0], table at [4]) followed by rtattrs.
func rtmsgBytes(family, table byte, attrs ...[]byte) []byte {
	b := make([]byte, unix.SizeofRtMsg)
	b[0] = family
	b[4] = table
	for _, a := range attrs {
		b = append(b, a...)
	}
	return b
}

// fibRuleBytes builds a struct fib_rule_hdr payload: same 12-byte
// fixed size, family at [0], then rtattrs.
func fibRuleBytes(family byte, attrs ...[]byte) []byte {
	b := make([]byte, routewatch.FibRuleHdrLen)
	b[0] = family
	for _, a := range attrs {
		b = append(b, a...)
	}
	return b
}

// rtattrU32 serializes one u32-valued rtattr (rta_len 8).
func rtattrU32(typ uint16, v uint32) []byte {
	b := make([]byte, unix.SizeofRtAttr+4)
	binary.NativeEndian.PutUint16(b[0:2], uint16(len(b)))
	binary.NativeEndian.PutUint16(b[2:4], typ)
	binary.NativeEndian.PutUint32(b[4:8], v)
	return b
}

// testRouteFilter is the fixture dataplane identity: pub table 100,
// marker table 101, the three nebula prefs, neb1 at ifindex 7.
func testRouteFilter() *routeEventFilter {
	return &routeEventFilter{
		tables: map[uint32]bool{100: true, 101: true},
		prefs:  map[uint32]bool{1400: true, 1490: true, 1500: true},
		nebIf:  7,
	}
}

func delRoute(family byte, table byte, attrs ...[]byte) []byte {
	return nlmsgBody(unix.RTM_DELROUTE, rtmsgBytes(family, table, attrs...))
}

func delRule(family byte, attrs ...[]byte) []byte {
	return nlmsgBody(unix.RTM_DELRULE, fibRuleBytes(family, attrs...))
}

func TestScanDeleteEvents(t *testing.T) {
	f := testRouteFilter()
	// tornAttr claims rta_len 32 but only 6 bytes follow — an
	// undecodable tail the scan must fail open on.
	tornAttr := []byte{0x20, 0x00, 0x0f, 0x00, 0xaa, 0xbb}
	for name, tc := range map[string]struct {
		buf  []byte
		want bool
	}{
		// The cicd noise — the whole point of the filter. A Calico
		// pod-route delete (main table, foreign oif) and a foreign
		// rule delete must NOT re-run nebula-up.sh.
		"calico pod-route delete": {
			delRoute(unix.AF_INET, unix.RT_TABLE_MAIN,
				rtattrU32(unix.RTA_OIF, 42)), false},
		"delrule foreign pref": {
			delRule(unix.AF_INET,
				rtattrU32(unix.FRA_PRIORITY, 9000)), false},
		"delroute big table nonmatch": {
			delRoute(unix.AF_INET, unix.RT_TABLE_COMPAT,
				rtattrU32(unix.RTA_TABLE, 300),
				rtattrU32(unix.RTA_OIF, 42)), false},
		// IPv6 sits in a different multicast group — but a v6
		// delete carrying OUR table/pref numbers still must not
		// count (the family check fires first).
		"delroute ipv6 same table": {
			delRoute(unix.AF_INET6, 100,
				rtattrU32(unix.RTA_OIF, 7)), false},
		"delrule ipv6 same pref": {
			delRule(unix.AF_INET6,
				rtattrU32(unix.FRA_PRIORITY, 1500)), false},
		// Converge's own writers — adds never trigger.
		"newroute": {nlmsg(unix.RTM_NEWROUTE), false},
		"newrule":  {nlmsg(unix.RTM_NEWRULE), false},
		"newaddr":  {nlmsg(unix.RTM_NEWADDR), false},
		"newlink":  {nlmsg(unix.RTM_NEWLINK), false},
		"newroute nebula table": {
			nlmsgBody(unix.RTM_NEWROUTE,
				rtmsgBytes(unix.AF_INET, 100)), false},

		// The nebula dataplane — every delete here re-runs the
		// script.
		"delroute pub table": {
			delRoute(unix.AF_INET, 100,
				rtattrU32(unix.RTA_OIF, 7)), true},
		"delroute mark table": {
			delRoute(unix.AF_INET, 101,
				rtattrU32(unix.RTA_OIF, 7)), true},
		// The marker-base /24 link route sits in table MAIN —
		// only the oif names it.
		"delroute neb dev main": {
			delRoute(unix.AF_INET, unix.RT_TABLE_MAIN,
				rtattrU32(unix.RTA_OIF, 7)), true},
		// Tables >255 travel in RTA_TABLE (rtm_table then reads
		// RT_TABLE_COMPAT=252) — the attribute wins.
		"delroute big table match": {
			delRoute(unix.AF_INET, unix.RT_TABLE_COMPAT,
				rtattrU32(unix.RTA_TABLE, 100),
				rtattrU32(unix.RTA_OIF, 42)), true},
		"delrule pref 1500": {
			delRule(unix.AF_INET,
				rtattrU32(unix.FRA_PRIORITY, 1500)), true},
		"delrule pref 1490": {
			delRule(unix.AF_INET,
				rtattrU32(unix.FRA_PRIORITY, 1490)), true},
		"delrule pref 1400": {
			delRule(unix.AF_INET,
				rtattrU32(unix.FRA_PRIORITY, 1400)), true},

		// Fail-open: anything too torn to classify counts — a
		// missed real delete costs minutes off-mesh, a spurious
		// trigger one idempotent script run.
		"delroute no payload":  {nlmsg(unix.RTM_DELROUTE), true},
		"delrule no payload":   {nlmsg(unix.RTM_DELRULE), true},
		"delroute torn rtmsg":  {nlmsgBody(unix.RTM_DELROUTE, []byte{1, 2, 3}), true},
		"delroute torn attr":   {delRoute(unix.AF_INET, unix.RT_TABLE_MAIN, tornAttr), true},
		"delrule missing prio": {delRule(unix.AF_INET, rtattrU32(unix.FRA_FWMARK, 0x1000)), true},
		"delrule torn attr":    {delRule(unix.AF_INET, tornAttr), true},
		"bad nlmsg length": {
			append([]byte{0xff, 0xff, 0xff, 0xff}, nlmsg(unix.RTM_DELROUTE)[4:]...), true},
		"undersize nlmsg": {
			[]byte{8, 0, 0, 0, 0x19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, true},
		"truncated datagram": {nlmsg(unix.RTM_DELROUTE)[:8], true},

		// Bursts: one match anywhere in the datagram fires; pure
		// noise bursts don't.
		"burst with match": {
			append(delRoute(unix.AF_INET, unix.RT_TABLE_MAIN,
				rtattrU32(unix.RTA_OIF, 42)),
				delRule(unix.AF_INET, rtattrU32(unix.FRA_PRIORITY, 1490))...), true},
		"burst all noise": {
			append(delRoute(unix.AF_INET, unix.RT_TABLE_MAIN,
				rtattrU32(unix.RTA_OIF, 42)),
				nlmsg(unix.RTM_NEWADDR)...), false},
		"empty": {nil, false},
	} {
		if got := f.scanDeleteEvents(tc.buf); got != tc.want {
			t.Fatalf("%s: scanDeleteEvents=%v want %v", name, got, tc.want)
		}
	}
}

// The neb-dev link route lives in table MAIN and is named only by
// its oif — an unresolved ifindex (dev absent when the filter
// armed) must not flip that match on (a 0 ifindex never equals a
// real one), while table matching keeps working regardless.
func TestScanDeleteEventsDevMissing(t *testing.T) {
	f := testRouteFilter()
	f.nebIf = 0
	linkRoute := delRoute(unix.AF_INET, unix.RT_TABLE_MAIN,
		rtattrU32(unix.RTA_OIF, 7))
	if f.scanDeleteEvents(linkRoute) {
		t.Fatal("neb-dev link route matched with ifindex unresolved")
	}
	if !f.scanDeleteEvents(delRoute(unix.AF_INET, 100)) {
		t.Fatal("pub-table delete ignored when ifindex unresolved")
	}
}

// nebulaIfindex reads the kernel ifindex netlink puts in RTA_OIF
// from sysfs; anything unreadable yields 0 (match inert, tables
// still work).
func TestNebulaIfindex(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteFile(t, filepath.Join(dir, "neb1", "ifindex"), "9\n")
	if got := nebulaIfindex(dir, "neb1"); got != 9 {
		t.Fatalf("ifindex=%d want 9", got)
	}
	testutil.WriteFile(t, filepath.Join(dir, "junk", "ifindex"), "abc\n")
	if got := nebulaIfindex(dir, "junk"); got != 0 {
		t.Fatalf("garbage ifindex=%d want 0", got)
	}
	if got := nebulaIfindex(dir, "no-such-dev"); got != 0 {
		t.Fatalf("missing dev ifindex=%d want 0", got)
	}
	if got := nebulaIfindex(dir, ""); got != 0 {
		t.Fatalf("empty dev ifindex=%d want 0", got)
	}
}

// nebulaRouteFilter wires the filter from watchdog conf: the pub
// table comes from OVERLAY_EGRESS_TABLE (hostconfig writes
// interdc_nebula_table_pub into the conf), the marker table + prefs
// are the nebula-up.sh constants, and the dev ifindex comes from
// sysfs.
func TestNebulaRouteFilterFromConf(t *testing.T) {
	e := fixture(t, &watchdogconf.Config{
		NebulaDev:          "neb9",
		OverlayEgressTable: 105,
	})
	sysdir := t.TempDir()
	testutil.WriteFile(t, filepath.Join(sysdir, "neb9", "ifindex"), "9\n")
	e.n.cfg.sysClassNet = sysdir
	f := e.n.nebulaRouteFilter()
	if f.nebIf != 9 {
		t.Fatalf("nebIf=%d want 9", f.nebIf)
	}
	if !f.tables[105] || !f.tables[routeGuardTableMark] ||
		len(f.tables) != 2 {
		t.Fatalf("tables=%v want {105,101}", f.tables)
	}
	for _, p := range []uint32{1400, 1490, 1500} {
		if !f.prefs[p] {
			t.Fatalf("pref %d missing: %v", p, f.prefs)
		}
	}
}

func TestNebulaRouteFilterDefaults(t *testing.T) {
	e := fixture(t, nil) // empty conf → Normalize defaults pub=100/neb1
	e.n.cfg.sysClassNet = t.TempDir()
	f := e.n.nebulaRouteFilter()
	if !f.tables[100] || !f.tables[101] || len(f.tables) != 2 {
		t.Fatalf("tables=%v want {100,101}", f.tables)
	}
	if f.nebIf != 0 {
		t.Fatalf("nebIf=%d want 0 (no devices in fixture sysfs)", f.nebIf)
	}
}

// --- debounce batching ---

func TestRouteGuardDebounceLoopBatches(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan struct{}, 16)
	done := make(chan struct{})
	var calls atomic.Int32
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		routeGuardDebounceLoop(ctx, events, done, 20*time.Millisecond, 0,
			func(context.Context) { calls.Add(1) })
	}()
	// Burst of 5 events, 5ms apart (< 20ms window) → one restore.
	for i := 0; i < 5; i++ {
		events <- struct{}{}
		time.Sleep(5 * time.Millisecond)
	}
	waitForCond(t, 2*time.Second, func() bool { return calls.Load() == 1 })
	// A quiet gap then a single event → a second restore.
	time.Sleep(60 * time.Millisecond)
	events <- struct{}{}
	waitForCond(t, 2*time.Second, func() bool { return calls.Load() == 2 })
	cancel()
	wg.Wait()
}

func TestRouteGuardDebounceLoopDoneAborts(t *testing.T) {
	events := make(chan struct{})
	done := make(chan struct{})
	var calls atomic.Int32
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		routeGuardDebounceLoop(context.Background(), events, done,
			time.Hour, 0, func(context.Context) { calls.Add(1) })
	}()
	events <- struct{}{}
	close(done) // pending timer must not fire
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("debounce loop did not exit on done")
	}
	time.Sleep(20 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatal("reconcile fired after done")
	}
}

// The min-interval cap: a burst inside the window must not exec
// (exec-storm guard) but is re-armed to the window's end — the
// trailing edge of a flap still lands exactly one restore.
func TestRouteGuardDebounceLoopRateLimits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan struct{}, 16)
	done := make(chan struct{})
	var calls atomic.Int32
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		routeGuardDebounceLoop(ctx, events, done, 10*time.Millisecond,
			80*time.Millisecond, func(context.Context) { calls.Add(1) })
	}()
	// First burst → immediate restore (no restore inside the window).
	events <- struct{}{}
	waitForCond(t, 2*time.Second, func() bool { return calls.Load() == 1 })

	// Second burst inside the 80ms window → suppressed, not dropped:
	// nothing fires now, one restore lands at the window's end.
	events <- struct{}{}
	time.Sleep(30 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("restore fired inside min interval: calls=%d", got)
	}
	waitForCond(t, 2*time.Second, func() bool { return calls.Load() == 2 })
	cancel()
	wg.Wait()
}

func waitForCond(t *testing.T, timeout time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within", timeout)
}

// --- restore (fixture integration) ---

// routeGuardFixture wires a node with nebula-up.sh under a HostRoot
// tempdir and an is-active=active nebula@interdc unit.
func routeGuardFixture(t *testing.T) *env {
	e := fixture(t, &watchdogconf.Config{
		NebulaNet: "interdc",
		NebulaDev: "neb1",
	})
	root := filepath.Dir(e.state)
	e.n.cfg.HostRoot = root
	// No real sysfs — the event filter arms with nebIf=0 unless the
	// test plants an ifindex file (table/pref matching always on).
	e.n.cfg.sysClassNet = t.TempDir()
	testutil.WriteFile(t, filepath.Join(root, "etc/nebula/interdc/nebula-up.sh"),
		"#!/bin/bash\nexit 0\n")
	e.sd.On("is-active nebula@interdc", "active\n")
	return e
}

func restoredCount(e *env) float64 {
	return promtest.ToFloat64(
		e.n.actions.WithLabelValues(checkRouteGuard, "restored"))
}

func execCount(e *env, sub string) int {
	n := 0
	for _, c := range e.host.Cmds() {
		if strings.Contains(strings.Join(c, " "), sub) {
			n++
		}
	}
	return n
}

func TestRouteGuardRestoreExecsScript(t *testing.T) {
	e := routeGuardFixture(t)
	e.n.restoreRouteGuard(context.Background())
	if execCount(e, "nebula-up.sh") != 1 {
		t.Fatalf("nebula-up.sh execs=%v", e.host.Cmds())
	}
	if got := restoredCount(e); got != 1 {
		t.Fatalf("restored metric=%v want 1", got)
	}
	if !strings.Contains(logLines(t, e),
		"route-guard re-ran nebula-up.sh after netlink delete") {
		t.Fatalf("missing restore log:\n%s", logLines(t, e))
	}
}

func TestRouteGuardRestoreUnitDownNoExec(t *testing.T) {
	e := routeGuardFixture(t)
	e.sd.Clear("is-active nebula@interdc") // is-active fails
	e.n.restoreRouteGuard(context.Background())
	if execCount(e, "nebula-up.sh") != 0 {
		t.Fatalf("restore ran while nebula inactive: %v", e.host.Cmds())
	}
	if got := restoredCount(e); got != 0 {
		t.Fatalf("restored=%v want 0", got)
	}
}

func TestRouteGuardRestoreMissingScriptNoOp(t *testing.T) {
	e := fixture(t, &watchdogconf.Config{NebulaNet: "interdc"})
	root := filepath.Dir(e.state)
	e.n.cfg.HostRoot = root // no nebula-up.sh under root
	e.sd.On("is-active nebula@interdc", "active\n")
	e.n.restoreRouteGuard(context.Background())
	if execCount(e, "nebula-up.sh") != 0 {
		t.Fatalf("restore ran without script: %v", e.host.Cmds())
	}
	// The script stat gates before the systemd probe — no
	// is-active call should have leaked either.
	for _, c := range e.sd.Cmds() {
		if strings.Contains(strings.Join(c, " "), "is-active") {
			t.Fatalf("is-active probed without script: %v", e.sd.Cmds())
		}
	}
}

func TestRouteGuardRestoreSigDisabled(t *testing.T) {
	e := routeGuardFixture(t)
	e.n.cfg.Watchdog.Disabled = map[string]bool{"route-guard": true}
	e.n.restoreRouteGuard(context.Background())
	if execCount(e, "nebula-up.sh") != 0 {
		t.Fatalf("restore ran despite WD_SIG_ROUTE_GUARD=off: %v", e.host.Cmds())
	}
}

func TestRouteGuardRestoreExecFailureNotCounted(t *testing.T) {
	e := routeGuardFixture(t)
	e.host.FailOn("nebula-up.sh", errCmdFail)
	e.n.restoreRouteGuard(context.Background())
	if execCount(e, "nebula-up.sh") != 1 {
		t.Fatalf("script not attempted: %v", e.host.Cmds())
	}
	if got := restoredCount(e); got != 0 {
		t.Fatalf("restored=%v want 0 on failure", got)
	}
	if got := promtest.ToFloat64(e.n.cycles.WithLabelValues(
		checkRouteGuard, "restore_error")); got != 1 {
		t.Fatalf("restore_error metric=%v want 1", got)
	}
	if !strings.Contains(logLines(t, e), "nebula-up.sh failed") {
		t.Fatalf("missing failure log:\n%s", logLines(t, e))
	}
}

// --- end-to-end: netlink event → debounced restore ---

func TestRouteGuardEventDrivesRestore(t *testing.T) {
	e := routeGuardFixture(t)
	e.n.cfg.routeDebounce = 20 * time.Millisecond
	e.n.cfg.routeMinRestore = 60 * time.Millisecond
	// Deterministic neb1 ifindex (7) — the CNI-noise deletes below
	// use foreign oif 42.
	sysdir := t.TempDir()
	testutil.WriteFile(t, filepath.Join(sysdir, "neb1", "ifindex"), "7\n")
	e.n.cfg.sysClassNet = sysdir
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fds[1]) }()
	e.n.cfg.openRouteSocket = func() (int, error) { return fds[0], nil }

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.n.routeGuard(ctx)
	}()
	// The monitor entry runs an up-front restore (bash parity).
	waitForCond(t, 2*time.Second, func() bool { return restoredCount(e) >= 1 })

	// NEW/REPLACE events are the converge's own writes — ignored.
	if _, err := unix.Write(fds[1], nlmsg(unix.RTM_NEWROUTE)); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(fds[1], nlmsg(unix.RTM_NEWRULE)); err != nil {
		t.Fatal(err)
	}
	// Deletes NOT naming the nebula state are ignored too — the
	// CNI pod-route churn the filter exists for: a main-table
	// route out a foreign oif, and a rule at a foreign pref.
	if _, err := unix.Write(fds[1], delRoute(unix.AF_INET,
		unix.RT_TABLE_MAIN, rtattrU32(unix.RTA_OIF, 42))); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(fds[1], delRule(unix.AF_INET,
		rtattrU32(unix.FRA_PRIORITY, 9000))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond) // > debounce
	if got := restoredCount(e); got != 1 {
		t.Fatalf("non-nebula events triggered restore: restored=%v", got)
	}

	// A nebula DELROUTE+DELRULE burst debounces into one more
	// restore: `default dev neb1 table 100` + the pref-1500 rule.
	if _, err := unix.Write(fds[1], delRoute(unix.AF_INET, 100,
		rtattrU32(unix.RTA_OIF, 7))); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(fds[1], delRule(unix.AF_INET,
		rtattrU32(unix.FRA_PRIORITY, 1500))); err != nil {
		t.Fatal(err)
	}
	waitForCond(t, 2*time.Second, func() bool { return restoredCount(e) >= 2 })

	// A later burst still lands — the rate cap delays, never
	// drops. The link route (main table, oif neb1) exercises the
	// RTA_OIF match.
	if _, err := unix.Write(fds[1], delRoute(unix.AF_INET,
		unix.RT_TABLE_MAIN, rtattrU32(unix.RTA_OIF, 7))); err != nil {
		t.Fatal(err)
	}
	waitForCond(t, 2*time.Second, func() bool { return restoredCount(e) >= 3 })
	cancel()
	wg.Wait()
	// After cancel, reading the fake's command log is race-free.
	if execCount(e, "nebula-up.sh") < 3 {
		t.Fatalf("netlink DEL events did not re-run the script: %v", e.host.Cmds())
	}
}

// Read error (or fd close) must unwind the monitor: the reader
// broadcasts done to BOTH the watcher and the debounce loop — a
// send-once error channel let one side consume it and stalled the
// monitor silently forever.
func TestRouteGuardReadExitsOnReadError(t *testing.T) {
	e := routeGuardFixture(t)
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		e.n.routeGuardRead(context.Background(), fds[0],
			50*time.Millisecond, time.Millisecond)
	}()
	waitForCond(t, 2*time.Second, func() bool { return restoredCount(e) >= 1 })
	_ = unix.Close(fds[1]) // peer EOF → reader exits → done broadcasts
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("monitor stalled after read error — done not broadcast")
	}
}

// Bash ran restore unconditionally at service start — a bind that
// never succeeds must still run the gated restore (rules lost while
// the guard is down), and the failure must stay observable (metric +
// repeated log).
func TestRouteGuardBindFailureStillRestores(t *testing.T) {
	e := routeGuardFixture(t)
	e.n.cfg.routeMinRestore = time.Millisecond
	e.n.cfg.openRouteSocket = func() (int, error) {
		return -1, errors.New("netlink denied")
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.n.routeGuard(ctx)
	}()
	waitForCond(t, 2*time.Second, func() bool { return restoredCount(e) >= 1 })
	waitForCond(t, 2*time.Second, func() bool {
		return promtest.ToFloat64(e.n.cycles.WithLabelValues(
			checkRouteGuard, "open_error")) >= 1
	})
	cancel()
	wg.Wait()
	if execCount(e, "nebula-up.sh") < 1 {
		t.Fatalf("bind failure skipped the gated restore: %v", e.host.Cmds())
	}
	if !strings.Contains(logLines(t, e), "netlink socket failed") {
		t.Fatalf("missing bind-failure log:\n%s", logLines(t, e))
	}
}

// The guard must stay single-flight while alive — a second guard
// would double-bind the netlink socket and double-restore — but once
// it has exited (ctx cancel, or a recovered panic) a later Run
// restart or tick re-arms it: the old sync.Once made any guard death
// permanent.
func TestRouteGuardRespawnsAfterExit(t *testing.T) {
	e := routeGuardFixture(t)
	// Cycle's checks would race the route guard on the fixture's
	// single-writer command/systemd fakes — keep them off; this test
	// only exercises the spawn.
	e.n.cfg.Watchdog.Disabled = map[string]bool{
		checkDNSFB: true, checkCoreDNS: true, checkEgress: true,
		checkNebula: true, checkF2B: true,
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fds[1]) }()
	var opens atomic.Int32
	e.n.cfg.openRouteSocket = func() (int, error) {
		opens.Add(1)
		return fds[0], nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.n.Run(ctx)
	}()
	waitForCond(t, 2*time.Second, func() bool { return opens.Load() >= 1 })

	// A concurrent spawn attempt while the guard is alive must not
	// stack a second guard.
	e.n.spawnRouteGuard(ctx)
	time.Sleep(100 * time.Millisecond)
	if got := opens.Load(); got != 1 {
		t.Fatalf("routeGuard stacked a second guard: opens=%d", got)
	}

	cancel()
	<-done
	waitForCond(t, 2*time.Second, func() bool {
		return !e.n.routeGuardRunning.Load()
	})

	// The guard exited with ctx — a restarted Run respawns it.
	// (Production waits routeGuardRespawnBackoff between spawn
	// attempts after an exit; the test clears the backoff stamp.)
	e.n.routeGuardLastExit.Store(0)
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		e.n.Run(ctx2)
	}()
	waitForCond(t, 2*time.Second, func() bool { return opens.Load() >= 2 })
	cancel2()
	<-done2
}

// A panic inside the guard is recovered (no daemon crash), logged,
// and the running flag clears so the next spawn attempt re-arms —
// subject to the respawn backoff.
func TestRouteGuardPanicRecoveredAndRearms(t *testing.T) {
	e := routeGuardFixture(t)
	var calls atomic.Int32
	e.n.cfg.openRouteSocket = func() (int, error) {
		calls.Add(1)
		panic("boom")
	}
	ctx := context.Background()
	e.n.spawnRouteGuard(ctx)
	waitForCond(t, 2*time.Second, func() bool {
		return !e.n.routeGuardRunning.Load()
	})
	if got := calls.Load(); got != 1 {
		t.Fatalf("openRouteSocket calls=%d want 1", got)
	}
	// The backoff stamp blocks an immediate respawn…
	e.n.spawnRouteGuard(ctx)
	if got := calls.Load(); got != 1 {
		t.Fatalf("respawn ignored the backoff: calls=%d", got)
	}
	// …until it elapses — then the guard re-arms (and panics again,
	// recovered again).
	e.n.routeGuardLastExit.Store(0)
	e.n.spawnRouteGuard(ctx)
	waitForCond(t, 2*time.Second, func() bool { return calls.Load() >= 2 })
	waitForCond(t, 2*time.Second, func() bool {
		return !e.n.routeGuardRunning.Load()
	})
}

func TestRouteGuardNoScriptNeverOpensSocket(t *testing.T) {
	e := fixture(t, &watchdogconf.Config{NebulaNet: "interdc"})
	root := filepath.Dir(e.state)
	e.n.cfg.HostRoot = root // no nebula-up.sh under root
	opened := atomic.Bool{}
	e.n.cfg.openRouteSocket = func() (int, error) {
		opened.Store(true)
		return -1, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.n.routeGuard(ctx)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	wg.Wait()
	if opened.Load() {
		t.Fatal("socket bound without nebula-up.sh")
	}
}

// --- shared helpers ---

// watchdogConf reads through the WatchdogSrc reloader when wired —
// off-Cycle goroutines (route guard, MTU prober) must never touch
// the Cycle-owned conf field.
func TestWatchdogConfReadsReloader(t *testing.T) {
	e := routeGuardFixture(t)
	wdSrc := watchdogconf.NewReloader(filepath.Join(t.TempDir(), "wd.conf"),
		&watchdogconf.Config{NebulaNet: "interdc", NebulaDev: "neb1"})
	e.n.cfg.Watchdog = nil // the field must NOT be consulted
	e.n.cfg.WatchdogSrc = wdSrc
	got := e.n.watchdogConf()
	if got == nil || got.NebulaNet != "interdc" || got.NebulaDev != "neb1" {
		t.Fatalf("watchdogConf through reloader = %+v", got)
	}
}

// sleepCtx sleeps the window or reports the cancel.
func TestSleepCtx(t *testing.T) {
	if !sleepCtx(context.Background(), time.Millisecond) {
		t.Fatal("sleepCtx reported cancel on a live context")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if sleepCtx(ctx, time.Hour) {
		t.Fatal("sleepCtx slept through a cancelled context")
	}
}

// trimRunErr clips captured output for the log line: hard clip at
// 200 bytes, then trailing newline/space trim.
func TestTrimRunErr(t *testing.T) {
	long := strings.Repeat("x", 250) + "\n  \n"
	got := trimRunErr(long)
	if len(got) != 200 {
		t.Fatalf("trimRunErr len=%d want 200", len(got))
	}
	if got := trimRunErr("ok\n\n \n"); got != "ok" {
		t.Fatalf("trimRunErr=%q want ok", got)
	}
	if got := trimRunErr(""); got != "" {
		t.Fatalf("trimRunErr=%q want empty", got)
	}
}

// --- spawn gating ---

// A terminal setns failure keeps the guard dead: spawnRouteGuard
// returns before the CAS, no goroutine spawns, and the MTU prober
// (which shares the spawn point) still arms.
func TestSpawnRouteGuardSetnsDeadGate(t *testing.T) {
	e := routeGuardFixture(t)
	e.n.cfg.TextfileDir = t.TempDir()
	e.n.routeGuardSetnsDead.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.n.spawnRouteGuard(ctx)
	if e.n.routeGuardRunning.Load() {
		t.Fatal("guard spawned although setns is terminally dead")
	}
	// The prober DID arm — wait for its gauge write to land, then
	// stop it so cleanup races nothing.
	waitForCond(t, 2*time.Second, func() bool {
		st := e.n.mtuState()
		st.mu.Lock()
		defer st.mu.Unlock()
		return st.cycle >= 1
	})
	cancel()
	waitForCond(t, 2*time.Second, func() bool {
		st := e.n.mtuState()
		st.mu.Lock()
		defer st.mu.Unlock()
		return !st.running
	})
}

// The setns failure is a terminal environment property: the guard
// exits with the setns_dead metric + log line, and later spawn
// attempts keep refusing instead of churning OS threads.
func TestRouteGuardSetnsDeadExits(t *testing.T) {
	e := routeGuardFixture(t)
	e.n.cfg.TextfileDir = t.TempDir()
	e.n.cfg.openRouteSocket = func() (int, error) {
		return -1, routewatch.ErrSetns
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.n.routeGuard(ctx)
	}()
	waitForCond(t, 2*time.Second, func() bool {
		return promtest.ToFloat64(e.n.cycles.WithLabelValues(
			checkRouteGuard, "setns_dead")) >= 1
	})
	waitForCond(t, 2*time.Second, func() bool {
		return !e.n.routeGuardRunning.Load()
	})
	if !strings.Contains(logLines(t, e), "setns into the host netns failed") {
		t.Fatalf("missing setns-dead log:\n%s", logLines(t, e))
	}
	// Spawning after the latch must stay a no-op for the guard (the
	// prober still arms; quiesce it before the test returns).
	e.n.spawnRouteGuard(ctx)
	if e.n.routeGuardRunning.Load() {
		t.Fatal("guard respawned after a terminal setns failure")
	}
	cancel()
	waitForCond(t, 2*time.Second, func() bool {
		st := e.n.mtuState()
		st.mu.Lock()
		defer st.mu.Unlock()
		return !st.running
	})
	wg.Wait()
}

// A bind that keeps failing loops with the retry backoff (the bash
// `sleep 2` parity): at least one full retry proves the loop
// continues instead of dying on the first error.
func TestRouteGuardBindFailureLoopRetries(t *testing.T) {
	e := routeGuardFixture(t)
	e.n.cfg.TextfileDir = t.TempDir()
	e.n.cfg.routeMinRestore = time.Hour // one gated restore is enough
	e.n.cfg.openRouteSocket = func() (int, error) {
		return -1, errors.New("netlink denied")
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.n.routeGuard(ctx)
	}()
	waitForCond(t, 6*time.Second, func() bool {
		return promtest.ToFloat64(e.n.cycles.WithLabelValues(
			checkRouteGuard, "open_error")) >= 2
	})
	cancel()
	wg.Wait()
}

// The default socket opener (openRouteSocket nil) composes
// routewatch.Bind over HostRoot — whatever the environment answers
// (direct bind, setns, or refusal), the guard must route through it
// and unwind cleanly on cancel.
func TestRouteGuardDefaultOpen(t *testing.T) {
	e := routeGuardFixture(t)
	e.n.cfg.TextfileDir = t.TempDir()
	e.n.cfg.openRouteSocket = nil // the production default
	e.n.cfg.routeDebounce = 20 * time.Millisecond
	e.n.cfg.routeMinRestore = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.n.routeGuard(ctx)
	}()
	// Any of the three environment outcomes must be observable —
	// and none may hang or crash.
	waitForCond(t, 3*time.Second, func() bool {
		return restoredCount(e) >= 1 ||
			promtest.ToFloat64(e.n.cycles.WithLabelValues(
				checkRouteGuard, "setns_dead")) >= 1 ||
			promtest.ToFloat64(e.n.cycles.WithLabelValues(
				checkRouteGuard, "open_error")) >= 1
	})
	cancel()
	wg.Wait()
}

// --- filter wiring edge cases ---

// A zero-value NetHealth has no conf at all — the filter still arms
// with the script's pub-table constant (a missing conf must not
// blind the guard to pub-table deletes).
func TestNebulaRouteFilterNilConf(t *testing.T) {
	n := &NetHealth{}
	f := n.nebulaRouteFilter()
	if !f.tables[routeGuardTablePub] || !f.tables[routeGuardTableMark] || len(f.tables) != 2 {
		t.Fatalf("tables=%v want {100,101}", f.tables)
	}
	if f.nebIf != 0 {
		t.Fatalf("nebIf=%d want 0", f.nebIf)
	}
}

// A conf whose OVERLAY_EGRESS_TABLE is unset (0 — an un-normalized
// hand-built Config) falls back to the pub constant instead of
// arming table 0.
func TestNebulaRouteFilterZeroPubTable(t *testing.T) {
	n := &NetHealth{}
	n.cfg.Watchdog = &watchdogconf.Config{NebulaDev: "neb1"}
	n.cfg.sysClassNet = t.TempDir()
	f := n.nebulaRouteFilter()
	if !f.tables[routeGuardTablePub] || f.tables[0] || len(f.tables) != 2 {
		t.Fatalf("tables=%v want {100,101} without table 0", f.tables)
	}
}

// --- restore gates ---

// No systemd client → the restore fails closed: an unanswerable
// manager must not resurrect a possibly-stopped unit.
func TestRouteGuardRestoreNilSystemd(t *testing.T) {
	e := routeGuardFixture(t)
	e.n.cfg.Systemd = nil
	e.n.restoreRouteGuard(context.Background())
	if execCount(e, "nebula-up.sh") != 0 {
		t.Fatalf("restore ran without a systemd client: %v", e.host.Cmds())
	}
}

// A deliberately stopped unit is not resurrected by its own delete
// events — is-active "inactive" skips the exec.
func TestRouteGuardRestoreInactiveUnit(t *testing.T) {
	e := routeGuardFixture(t)
	e.sd.On("is-active nebula@interdc", "inactive\n")
	e.n.restoreRouteGuard(context.Background())
	if execCount(e, "nebula-up.sh") != 0 {
		t.Fatalf("restore resurrected a stopped unit: %v", e.host.Cmds())
	}
	if got := restoredCount(e); got != 0 {
		t.Fatalf("restored=%v want 0", got)
	}
}

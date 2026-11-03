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

	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/watchdogconf"
)

// --- netlink message decoding ---

// nlmsg serializes a bare nlmsghdr of the given type — netlink is
// host byte order, binary.NativeEndian matches the decoder.
func nlmsg(typ uint16) []byte {
	b := make([]byte, unix.NLMSG_HDRLEN)
	binary.NativeEndian.PutUint32(b[0:4], uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:6], typ)
	return b
}

func TestScanDeleteEvents(t *testing.T) {
	for name, tc := range map[string]struct {
		buf  []byte
		want bool
	}{
		"delroute":   {nlmsg(unix.RTM_DELROUTE), true},
		"delrule":    {nlmsg(unix.RTM_DELRULE), true},
		"newroute":   {nlmsg(unix.RTM_NEWROUTE), false}, // converge's own adds
		"newrule":    {nlmsg(unix.RTM_NEWRULE), false},
		"newaddr":    {nlmsg(unix.RTM_NEWADDR), false},
		"newlink":    {nlmsg(unix.RTM_NEWLINK), false},
		"multi del":  {append(nlmsg(unix.RTM_NEWADDR), nlmsg(unix.RTM_DELRULE)...), true},
		"multi miss": {append(nlmsg(unix.RTM_NEWADDR), nlmsg(unix.RTM_NEWLINK)...), false},
		"empty":      {nil, false},
		"truncated":  {nlmsg(unix.RTM_DELROUTE)[:8], false},
		"bad length": {append([]byte{0xff, 0xff, 0xff, 0xff}, nlmsg(unix.RTM_DELROUTE)[4:]...), false},
		"undersize":  {[]byte{8, 0, 0, 0, 0x19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
	} {
		if got := scanDeleteEvents(tc.buf); got != tc.want {
			t.Fatalf("%s: scanDeleteEvents=%v want %v", name, got, tc.want)
		}
	}
}

// --- host-netns bind selection ---

func TestSameNetnsSelfIsSelf(t *testing.T) {
	if !sameNetns(routeSelfNetns, routeSelfNetns) {
		t.Fatal("/proc/self/ns/net does not SameFile itself")
	}
}

// hostNetwork deployment (the DaemonSet case): pod netns IS the host
// netns → direct bind, hostRoot never consulted. Skips when the test
// env runs pid 1 in a different netns (unusual containers).
func TestOpenRouteNetlinkDirectBindWhenHostNet(t *testing.T) {
	if !sameNetns(routeSelfNetns, routeInitNetns) {
		t.Skip("test env: pid 1 lives in a different netns")
	}
	// A bogus hostRoot proves the mounted-/proc path isn't touched —
	// on the DS <hostRoot>/proc doesn't exist at all.
	fd, err := openRouteNetlink(filepath.Join(t.TempDir(), "no-such-root"))
	if err != nil {
		t.Fatalf("direct bind failed: %v", err)
	}
	if fd < 0 {
		t.Fatalf("fd=%d", fd)
	}
	defer unix.Close(fd)
	sa, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatalf("Getsockname: %v", err)
	}
	if _, ok := sa.(*unix.SockaddrNetlink); !ok {
		t.Fatalf("bound fd is not netlink: %T", sa)
	}
}

// hostPID deployment without hostNetwork: setns into /proc/1/ns/net;
// a mounted host /proc under hostRoot is only the last fallback.
// A regular file stands in for the ns magic link — setns() on it
// fails deterministically (EINVAL, no privilege needed).
func TestOpenRouteNetlinkSetnsAndHostRootFallback(t *testing.T) {
	old := routeInitNetns
	defer func() { routeInitNetns = old }()
	init := filepath.Join(t.TempDir(), "net")
	writeFile(t, init, "")
	routeInitNetns = init

	// No mounted host /proc → the setns error propagates.
	if fd, err := openRouteNetlink("/"); err == nil ||
		!strings.Contains(err.Error(), "setns") {
		if fd >= 0 {
			unix.Close(fd)
		}
		t.Fatalf("want setns failure, got fd=%d err=%v", fd, err)
	}

	// Mounted host /proc under hostRoot → attempted as last resort.
	root := t.TempDir()
	fake := filepath.Join(root, "proc/1/ns/net")
	writeFile(t, fake, "")
	fd, err := openRouteNetlink(root)
	if fd >= 0 {
		unix.Close(fd)
	}
	if err == nil || !strings.Contains(err.Error(), fake) {
		t.Fatalf("host-root fallback not attempted: %v", err)
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
	writeFile(t, filepath.Join(root, "etc/nebula/interdc/nebula-up.sh"),
		"#!/bin/bash\nexit 0\n")
	e.sdReply["is-active nebula@interdc"] = "active\n"
	return e
}

func restoredCount(e *env) float64 {
	return testutil.ToFloat64(
		e.n.actions.WithLabelValues(checkRouteGuard, "restored"))
}

func execCount(e *env, sub string) int {
	n := 0
	for _, c := range e.cmds {
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
		t.Fatalf("nebula-up.sh execs=%v", e.cmds)
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
	delete(e.sdReply, "is-active nebula@interdc") // is-active fails
	e.n.restoreRouteGuard(context.Background())
	if execCount(e, "nebula-up.sh") != 0 {
		t.Fatalf("restore ran while nebula inactive: %v", e.cmds)
	}
	if got := restoredCount(e); got != 0 {
		t.Fatalf("restored=%v want 0", got)
	}
}

func TestRouteGuardRestoreMissingScriptNoOp(t *testing.T) {
	e := fixture(t, &watchdogconf.Config{NebulaNet: "interdc"})
	root := filepath.Dir(e.state)
	e.n.cfg.HostRoot = root // no nebula-up.sh under root
	e.sdReply["is-active nebula@interdc"] = "active\n"
	e.n.restoreRouteGuard(context.Background())
	if execCount(e, "nebula-up.sh") != 0 {
		t.Fatalf("restore ran without script: %v", e.cmds)
	}
	// The script stat gates before the systemd probe — no
	// is-active call should have leaked either.
	for _, c := range e.sdcmds {
		if strings.Contains(strings.Join(c, " "), "is-active") {
			t.Fatalf("is-active probed without script: %v", e.sdcmds)
		}
	}
}

func TestRouteGuardRestoreSigDisabled(t *testing.T) {
	e := routeGuardFixture(t)
	e.n.cfg.Watchdog.Disabled = map[string]bool{"route-guard": true}
	e.n.restoreRouteGuard(context.Background())
	if execCount(e, "nebula-up.sh") != 0 {
		t.Fatalf("restore ran despite WD_SIG_ROUTE_GUARD=off: %v", e.cmds)
	}
}

func TestRouteGuardRestoreExecFailureNotCounted(t *testing.T) {
	e := routeGuardFixture(t)
	e.cmdFail["nebula-up.sh"] = true
	e.n.restoreRouteGuard(context.Background())
	if execCount(e, "nebula-up.sh") != 1 {
		t.Fatalf("script not attempted: %v", e.cmds)
	}
	if got := restoredCount(e); got != 0 {
		t.Fatalf("restored=%v want 0 on failure", got)
	}
	if got := testutil.ToFloat64(e.n.cycles.WithLabelValues(
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
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
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
	time.Sleep(80 * time.Millisecond) // > debounce
	if got := restoredCount(e); got != 1 {
		t.Fatalf("NEW events triggered restore: restored=%v", got)
	}

	// A DELROUTE+DELRULE burst debounces into one more restore.
	if _, err := unix.Write(fds[1], nlmsg(unix.RTM_DELROUTE)); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(fds[1], nlmsg(unix.RTM_DELRULE)); err != nil {
		t.Fatal(err)
	}
	waitForCond(t, 2*time.Second, func() bool { return restoredCount(e) >= 2 })

	// A later burst still lands — the rate cap delays, never drops.
	if _, err := unix.Write(fds[1], nlmsg(unix.RTM_DELROUTE)); err != nil {
		t.Fatal(err)
	}
	waitForCond(t, 2*time.Second, func() bool { return restoredCount(e) >= 3 })
	cancel()
	wg.Wait()
	// After cancel, reading the fake's command log is race-free.
	if execCount(e, "nebula-up.sh") < 3 {
		t.Fatalf("netlink DEL events did not re-run the script: %v", e.cmds)
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
	unix.Close(fds[1]) // peer EOF → reader exits → done broadcasts
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
		return testutil.ToFloat64(e.n.cycles.WithLabelValues(
			checkRouteGuard, "open_error")) >= 1
	})
	cancel()
	wg.Wait()
	if execCount(e, "nebula-up.sh") < 1 {
		t.Fatalf("bind failure skipped the gated restore: %v", e.cmds)
	}
	if !strings.Contains(logLines(t, e), "netlink socket failed") {
		t.Fatalf("missing bind-failure log:\n%s", logLines(t, e))
	}
}

// Run() may be restarted by the agent after a panic — the guard is
// spawned behind sync.Once so a restart can't double-bind the socket
// or double-restore.
func TestRouteGuardSpawnedOnceAcrossRunRestarts(t *testing.T) {
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
	defer unix.Close(fds[1])
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
	cancel()
	<-done

	// A restarted Run must not respawn the guard.
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		e.n.Run(ctx2)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel2()
	<-done2
	if got := opens.Load(); got != 1 {
		t.Fatalf("routeGuard respawned on Run restart: opens=%d", got)
	}
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

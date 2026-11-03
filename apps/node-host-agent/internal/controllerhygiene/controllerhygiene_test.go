package controllerhygiene

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/etcdrescue"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/evpurge"
)

// env is the fixture: tempdir host trees + stubbed externals + a
// controllable clock. Tests are fully hermetic — "processes" are just
// files under env.proc, "systemctl" a recorded call list, "journal" a
// scripted string.
type env struct {
	h      *Hygiene
	state  string
	proc   string
	fstate string
	unit   string
	cg     string
	now    time.Time

	rv      map[string]map[bool]rvResult // endpoint -> cached -> result
	journal string
	pgOK    bool
	kills   []killRecord
	props   map[string]string // "unit:prop" -> value
	active  map[string]string // unit -> state
	alive   map[string]bool   // url -> probe result

	mu    sync.Mutex // feeder goroutine writes rst/notif asynchronously
	rst   []string
	notif []string
}

// rstN returns the restart-call count (locked — feeder runs async).
func (e *env) rstN() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.rst)
}

// rstAt returns restart-call i.
func (e *env) rstAt(i int) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rst[i]
}

// notifN returns the notify-call count (locked).
func (e *env) notifN() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.notif)
}

// notifAt returns notify-call i.
func (e *env) notifAt(i int) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.notif[i]
}

type rvResult struct {
	rv int64
	ok bool
}

type killRecord struct {
	pid int
	sig syscall.Signal
}

func fixture(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	e := &env{
		now:    time.Now(),
		rv:     map[string]map[bool]rvResult{},
		pgOK:   true,
		props:  map[string]string{},
		active: map[string]string{},
		alive:  map[string]bool{},
	}
	e.state = filepath.Join(root, "watchdog")
	e.proc = filepath.Join(root, "proc")
	e.fstate = filepath.Join(root, "feeder-state")
	e.unit = filepath.Join(root, "k0scontroller.service")
	e.cg = filepath.Join(root, "memory.events")
	for _, d := range []string{e.state, e.proc, e.fstate} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, e.unit, "[Service]\nExecStart=/usr/bin/k0s controller\n")
	// Past the 20min uptime gate by default.
	writeFile(t, filepath.Join(e.proc, "uptime"), "86400.00 12345.00\n")

	h, err := New(Config{
		Enabled:               true,
		Interval:              time.Hour,
		WatchdogStateDir:      e.state,
		WatchdogLogFile:       filepath.Join(root, "watchdog.log"),
		ProcRoot:              e.proc,
		K0sControllerUnitFile: e.unit,
		SelfEndpoint:          "127.0.0.1:6443",
		SelfAPI:               "10.0.0.1:6443",
		PeerAPI:               "10.0.0.2:6443",
		AdminKubeconfig:       filepath.Join(root, "missing-admin.conf"),
		AdminCert:             filepath.Join(root, "missing-admin.crt"),
		CGroupEventsFile:      e.cg,
		FeederStateDir:        e.fstate,
		RemediatePeerFile:     filepath.Join(root, "peer.conf"),
		Sig13Mode:             ModeEnforce,
		KineTTLMode:           ModeEnforce,
		KinePoolMode:          ModeEnforce,
		OOMLoopMode:           ModeEnforce,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &h.cfg
	cfg.nowFn = func() time.Time { return e.now }
	cfg.sleepFn = func(time.Duration) {}
	cfg.killFn = func(pid int, sig syscall.Signal) error {
		e.kills = append(e.kills, killRecord{pid, sig})
		return nil
	}
	cfg.listRVFn = func(_ context.Context, ep string, cached bool) (int64, bool) {
		r, ok := e.rv[ep][cached]
		if !ok {
			return 0, false
		}
		return r.rv, true
	}
	cfg.journalFn = func(context.Context, string, time.Time) (string, error) {
		return e.journal, nil
	}
	cfg.pgWireFn = func(context.Context, string) bool { return e.pgOK }
	cfg.restartFn = func(_ context.Context, unit string) error {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.rst = append(e.rst, unit)
		return nil
	}
	cfg.propFn = func(_ context.Context, unit, prop string) (string, error) {
		v, ok := e.props[unit+":"+prop]
		if !ok {
			return "", fmt.Errorf("no prop")
		}
		return v, nil
	}
	cfg.isActive = func(_ context.Context, unit string) (string, error) {
		return e.active[unit], nil
	}
	cfg.notifyFn = func(msg string) error {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.notif = append(e.notif, msg)
		return nil
	}
	cfg.probeFn = func(_ context.Context, url string) bool { return e.alive[url] }
	e.h = h
	return e
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// setRV scripts a LIST response for an endpoint: "self"|"peer",
// cached or consistent.
func (e *env) setRV(ep string, cached bool, rv int64, ok bool) {
	if e.rv[ep] == nil {
		e.rv[ep] = map[bool]rvResult{}
	}
	e.rv[ep][cached] = rvResult{rv: rv, ok: ok}
}

// mkProc fabricates a running process under env.proc: comm, cmdline,
// a stat with a sane starttime (age seconds ago).
func (e *env) mkProc(t *testing.T, pid int, comm string, args []string, age float64) {
	t.Helper()
	d := filepath.Join(e.proc, strconv.Itoa(pid))
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(d, "comm"), comm+"\n")
	writeFile(t, filepath.Join(d, "cmdline"), strings.Join(args, "\x00")+"\x00")
	// starttime = field 22 (index 19 after ')') in jiffies.
	start := int64((86400.0 - age) * clkTck)
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0] = "S" // state
	fields[19] = strconv.FormatInt(start, 10)
	writeFile(t, filepath.Join(d, "stat"),
		fmt.Sprintf("%d (%s) %s", pid, comm, strings.Join(fields, " ")))
}

// mkSock links one fd to a socket inode and appends a net/tcp row to
// remote port dbPort (ESTABLISHED).
func (e *env) mkSock(t *testing.T, pid int, fd int, inode string, dbPort int) {
	t.Helper()
	d := filepath.Join(e.proc, strconv.Itoa(pid), "fd")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fmt.Sprintf("socket:[%s]", inode),
		filepath.Join(d, strconv.Itoa(fd))); err != nil {
		t.Fatal(err)
	}
	tcp := filepath.Join(e.proc, strconv.Itoa(pid), "net", "tcp")
	if _, err := os.Stat(tcp); os.IsNotExist(err) {
		writeFile(t, tcp, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
	}
	f, err := os.OpenFile(tcp, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// Columns: sl local rem st tx:rx tr:tm retr uid timeout inode ...
	fmt.Fprintf(f, "   1: 0100007F:1234 0A0000FF:%04X 01 00000000:00000000 00:00000000 00000000 0 0 %s 1 0000000000000000\n",
		dbPort, inode)
}

func (e *env) stateFile(name string) string {
	return filepath.Join(e.state, "state-"+name)
}

func (e *env) hasState(name string) bool {
	_, err := os.Stat(e.stateFile(name))
	return err == nil
}

// --- ShouldRun / gate ---

func TestShouldRun(t *testing.T) {
	root := t.TempDir()
	if ShouldRun(root) {
		t.Fatal("expected false without unit file")
	}
	writeFile(t, filepath.Join(root, "etc/systemd/system/k0scontroller.service"), "[Service]\n")
	if !ShouldRun(root) {
		t.Fatal("expected true with unit file")
	}
}

func TestCycleGated(t *testing.T) {
	e := fixture(t)
	if err := os.Remove(e.unit); err != nil {
		t.Fatal(err)
	}
	e.h.Cycle(context.Background())
	// Nothing may happen without the unit file.
	if e.rstN() != 0 || len(e.kills) != 0 {
		t.Fatal("actions ran without k0scontroller unit")
	}
}

func TestUptimeGate(t *testing.T) {
	e := fixture(t)
	writeFile(t, filepath.Join(e.proc, "uptime"), "300.00 1.00\n")
	e.setRV("127.0.0.1:6443", false, 100000, true)
	e.setRV("127.0.0.1:6443", true, 1, true)
	e.h.Cycle(context.Background())
	if e.rstN() != 0 {
		t.Fatal("uptime gate did not block the wedge guard")
	}
}

// --- Guard a: wedge detection ---

func TestGapWedgePeerFreshRestarts(t *testing.T) {
	e := fixture(t)
	self := "127.0.0.1:6443"
	peer := "10.0.0.2:6443"
	// rv_now - rv_cache > 10000; peer close to head => fresh.
	e.setRV(self, false, 20000, true)
	e.setRV(self, true, 5000, true)
	e.setRV(peer, true, 19900, true)
	e.h.Cycle(context.Background()) // gn=1
	e.h.Cycle(context.Background()) // gn=2 => wedge confirmed
	if !e.hasState(stateCacheWedged) {
		t.Fatal("state-apiserver-cache-wedged missing")
	}
	if e.rstN() != 1 || e.rstAt(0) != "k0scontroller.service" {
		t.Fatalf("expected 1 restart, got %d", e.rstN())
	}
	// Rate budget spent.
	if h := e.h.readEpoch(filepath.Join(e.state, fileRateRestart)); h == 0 {
		t.Fatal("last-sig13-restart budget not spent")
	}
}

func TestGapWedgePeerStaleHeld(t *testing.T) {
	e := fixture(t)
	self := "127.0.0.1:6443"
	peer := "10.0.0.2:6443"
	e.setRV(self, false, 90000, true)
	e.setRV(self, true, 5000, true)
	e.setRV(peer, true, 4000, true) // peer cache far behind too
	for i := 0; i < 3; i++ {
		e.h.Cycle(context.Background())
	}
	if e.rstN() != 0 {
		t.Fatal("restart happened while peer stale and solo cycles short")
	}
	if !e.hasState(stateCacheWedged) {
		t.Fatal("wedge state missing")
	}
}

func TestFrozenWedgeSoloAfterCycles(t *testing.T) {
	e := fixture(t)
	self := "127.0.0.1:6443"
	e.h.cfg.PeerAPI = "" // single-hub => always first
	rvN := int64(100)
	// rv_cache frozen at 50 while rv_now grows — the first cycle
	// only seeds last-rvc, so FrozenCycles=2 trips on cycle 3.
	for i := 0; i < 3; i++ {
		e.setRV(self, true, 50, true)
		e.setRV(self, false, rvN, true)
		rvN += 10
		e.h.Cycle(context.Background())
	}
	if !e.hasState(stateCacheWedged) {
		t.Fatal("frozen wedge not detected after FrozenCycles")
	}
	// Solo path needs SoloCycles gap-counter (each wedged cycle
	// increments) — keep cycling until restart.
	for i := 0; i < 10 && e.rstN() == 0; i++ {
		e.setRV(self, false, rvN, true)
		rvN += 10
		e.h.Cycle(context.Background())
	}
	if e.rstN() != 1 {
		t.Fatalf("expected solo restart, got %d", e.rstN())
	}
}

func TestIdleClusterNoFrozen(t *testing.T) {
	e := fixture(t)
	self := "127.0.0.1:6443"
	// rv_now == rv_cache — standing still is not wedge evidence.
	for i := 0; i < 4; i++ {
		e.setRV(self, true, 70, true)
		e.setRV(self, false, 70, true)
		e.h.Cycle(context.Background())
	}
	if e.hasState(stateCacheWedged) {
		t.Fatal("idle cluster latched as wedged")
	}
	if e.rstN() != 0 {
		t.Fatal("idle cluster triggered restart")
	}
}

func TestRecoveryClearsWedge(t *testing.T) {
	e := fixture(t)
	self := "127.0.0.1:6443"
	peer := "10.0.0.2:6443"
	e.setRV(self, false, 90000, true)
	e.setRV(self, true, 1000, true)
	e.setRV(peer, true, 89900, true)
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if !e.hasState(stateCacheWedged) {
		t.Fatal("precondition: wedge not latched")
	}
	// Cache catches up.
	e.setRV(self, true, 89500, true)
	e.h.Cycle(context.Background())
	if e.hasState(stateCacheWedged) {
		t.Fatal("wedge state not cleared on recovery")
	}
}

func TestDeadFallbackKineOK(t *testing.T) {
	e := fixture(t)
	e.h.cfg.PeerAPI = "" // single hub
	e.h.cfg.KineDBProbe = "10.0.0.9:6432"
	e.journal = "x required revision has been compacted\n" // cache_errs > 0
	// Both queries dead, DB healthy → dead-fallback after SoloCycles.
	for i := 0; i < 9 && e.rstN() == 0; i++ {
		e.h.Cycle(context.Background())
	}
	if e.rstN() != 1 {
		t.Fatalf("dead-fallback restart missing: %d", e.rstN())
	}
	if e.hasState(stateKineUnreachable) {
		t.Fatal("kine-backend-unreachable latched despite healthy DB")
	}
}

func TestDeadFallbackKineDead(t *testing.T) {
	e := fixture(t)
	e.h.cfg.KineDBProbe = "10.0.0.9:6432"
	e.journal = "x required revision has been compacted\n"
	e.pgOK = false // DB broken → apiserver restart is useless
	for i := 0; i < 12; i++ {
		e.h.Cycle(context.Background())
	}
	if e.rstN() != 0 {
		t.Fatal("restart ran while DB dead")
	}
	if !e.hasState(stateKineUnreachable) {
		t.Fatal("kine-backend-unreachable missing")
	}
}

func TestSecondHubNeverSolo(t *testing.T) {
	e := fixture(t)
	// Self sorts AFTER peer → second hub.
	e.h.cfg.SelfAPI = "10.0.0.9:6443"
	e.h.cfg.PeerAPI = "10.0.0.2:6443"
	self := "127.0.0.1:6443"
	e.setRV(self, false, 90000, true)
	e.setRV(self, true, 5000, true)
	// peer unreachable → peer_note=unreachable, not fresh.
	for i := 0; i < 12; i++ {
		e.h.Cycle(context.Background())
	}
	if e.rstN() != 0 {
		t.Fatal("second hub restarted without fresh peer")
	}
}

// --- Guard b: kine pool ---

func TestKinePoolSpiral(t *testing.T) {
	e := fixture(t)
	e.mkProc(t, 1001, "kine",
		[]string{"kine", "--endpoint=postgres://10.0.0.9:6432/kine"}, 1000)
	for i := 0; i < 80; i++ {
		e.mkSock(t, 1001, 100+i, strconv.Itoa(50000+i), 6432)
	}
	for i := 0; i < 3; i++ { // KinePoolCycles=3
		e.h.Cycle(context.Background())
	}
	if !e.hasState(stateKinePoolRunaway) {
		t.Fatal("kine-pool-runaway state missing")
	}
	if len(e.kills) != 1 || e.kills[0].pid != 1001 || e.kills[0].sig != syscall.SIGTERM {
		t.Fatalf("expected SIGTERM on kine pid 1001, got %v", e.kills)
	}
	// Cooldown: still spiralling but no second kill.
	e.h.Cycle(context.Background())
	if len(e.kills) != 1 {
		t.Fatal("cooldown did not suppress the second kill")
	}
}

func TestKinePoolHealthy(t *testing.T) {
	e := fixture(t)
	e.mkProc(t, 1001, "kine",
		[]string{"kine", "--endpoint=postgres://10.0.0.9:6432/kine"}, 1000)
	for i := 0; i < 10; i++ {
		e.mkSock(t, 1001, 100+i, strconv.Itoa(60000+i), 6432)
	}
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if len(e.kills) != 0 {
		t.Fatal("healthy conn count killed kine")
	}
	if e.hasState(stateKinePoolRunaway) {
		t.Fatal("runaway latched on healthy pool")
	}
}

// --- Guard c: OOM loop ---

func writeEvents(t *testing.T, e *env, kills int) {
	t.Helper()
	writeFile(t, e.cg, fmt.Sprintf("low 0\nhigh 0\nmax 0\noom 0\noom_kill %d\noom_group_kill 0\n", kills))
}

func TestOOMLoopShield(t *testing.T) {
	e := fixture(t)
	e.mkProc(t, 2001, "kube-apiserver", []string{"kube-apiserver"}, 5000)
	e.mkProc(t, 2002, "kine", []string{"kine"}, 5000)
	// Seed baseline, then +3 kills within the window.
	writeEvents(t, e, 0)
	e.h.Cycle(context.Background())
	writeEvents(t, e, 3)
	e.h.Cycle(context.Background())
	if !e.hasState(stateControllerOOMLop) {
		t.Fatal("k0scontroller-oom-loop missing")
	}
	if v := readAdj(t, e, 2001); v != "-800" {
		t.Fatalf("apiserver adj=%s want -800", v)
	}
	if v := readAdj(t, e, 2002); v != "500" {
		t.Fatalf("kine adj=%s want 500", v)
	}
	// Loop clears → shield removed + state exits.
	e.now = e.now.Add(2 * time.Hour)
	writeEvents(t, e, 3) // no new kills; old ones pruned out
	e.h.Cycle(context.Background())
	if e.hasState(stateControllerOOMLop) {
		t.Fatal("oom-loop state not cleared")
	}
	if v := readAdj(t, e, 2001); v != "0" {
		t.Fatalf("apiserver not unshielded: %s", v)
	}
}

func TestOOMFirstRunSeedsOnly(t *testing.T) {
	e := fixture(t)
	// Pre-existing cumulative counter must NOT latch on first run.
	writeEvents(t, e, 50)
	e.h.Cycle(context.Background())
	if e.hasState(stateControllerOOMLop) {
		t.Fatal("baseline seeding latched a phantom OOM loop")
	}
}

func readAdj(t *testing.T, e *env, pid int) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.proc, strconv.Itoa(pid), "oom_score_adj"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// --- Guard a tail: kine TTL ---

func TestTTLDeadKill(t *testing.T) {
	e := fixture(t)
	e.mkProc(t, 3001, "kine", []string{"kine"}, 1000) // age > 300s
	e.journal = "E TTL initial list failed: context deadline\n"
	e.h.Cycle(context.Background())
	if !e.hasState(stateKineTTLDead) {
		t.Fatal("kine-ttl-dead missing")
	}
	if len(e.kills) != 1 || e.kills[0].pid != 3001 {
		t.Fatalf("expected kine kill, got %v", e.kills)
	}
}

func TestTTLYoungPidSpared(t *testing.T) {
	e := fixture(t)
	e.mkProc(t, 3001, "kine", []string{"kine"}, 60) // inside seed window
	e.journal = "E TTL initial list failed\n"
	e.h.Cycle(context.Background())
	if len(e.kills) != 0 {
		t.Fatal("killed a kine still in its seed window")
	}
}

func TestTTLRewedgeLoopSuppressesFastKill(t *testing.T) {
	e := fixture(t)
	e.journal = "E TTL event watch failed\n"
	e.mkProc(t, 3001, "kine", []string{"kine"}, 1000)
	e.h.Cycle(context.Background()) // pid 3001 wedged → kill (rew=1)
	if len(e.kills) != 1 {
		t.Fatal("first wedged pid not killed")
	}
	// Respawn re-wedges from boot → rew=2 >= RewedgeCycles → loop.
	// Remove the old pid dir so pgrep sees the new pid.
	if err := os.RemoveAll(filepath.Join(e.proc, "3001")); err != nil {
		t.Fatal(err)
	}
	e.mkProc(t, 3002, "kine", []string{"kine"}, 400)
	e.h.Cycle(context.Background())
	if !e.hasState(stateKineTTLLoop) {
		t.Fatal("kine-ttl-loop missing after rewedge")
	}
	// Loop path kills at CTL cadence — a second pid IS killed once
	// (the recovery probe), but the budget is spent now.
	e.h.Cycle(context.Background())
	killsAfter := len(e.kills)
	if killsAfter > 2 {
		t.Fatalf("loop path over-killed: %d", len(e.kills))
	}
	// Clean pid resets.
	e.journal = ""
	if err := os.RemoveAll(filepath.Join(e.proc, "3002")); err != nil {
		t.Fatal(err)
	}
	e.mkProc(t, 3003, "kine", []string{"kine"}, 1000)
	e.h.Cycle(context.Background())
	if e.hasState(stateKineTTLDead) || e.hasState(stateKineTTLLoop) {
		t.Fatal("clean kine did not clear TTL latches")
	}
}

// --- Guard d: feeder + remediate ---

// runFeederSteps drives the feeder for n probe iterations. The real
// loop uses time.After — tests step it through runFeederOnce-style
// control: we expose the body via a context cancelled after n feeds.
func TestFeederGraceThenFail(t *testing.T) {
	e := fixture(t)
	e.h.cfg.FeederEnabled = true
	e.h.cfg.FeedInterval = time.Millisecond
	e.props["k0scontroller.service:MainPID"] = "4242"
	e.active["k0scontroller.service"] = "active"
	// G3 passes: unit started long ago.
	e.props["k0scontroller.service:ActiveEnterTimestampMonotonic"] = "1"
	e.alive[e.h.cfg.FeedProbeURL] = false

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { e.h.runFeeder(ctx); close(done) }()
	// Grace period: probe fails but feeder keeps feeding
	// (ever_ok=0). Wait for >=1 notification then inspect.
	deadline := time.After(5 * time.Second)
	for e.notifN() == 0 {
		select {
		case <-deadline:
			t.Fatal("feeder never fed during startup grace")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if e.notifN() == 0 || e.notifAt(0) != "WATCHDOG=1" {
		t.Fatalf("unexpected notify payload: %d", e.notifN())
	}
	// Let the grace fails run out (8) → remediate triggers: probe
	// still dead → G1 fails → G2 active → G3 passes → G5 fresh
	// budget → G6 restart.
	deadline = time.After(5 * time.Second)
	for e.rstN() == 0 && !remediateLogged(e) {
		select {
		case <-deadline:
			t.Fatal("remediate never ran")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

func remediateLogged(e *env) bool {
	b, _ := os.ReadFile(filepath.Join(filepath.Dir(e.state), "watchdog.log"))
	return strings.Contains(string(b), "remediate:")
}

func TestFeederFailPathRestarts(t *testing.T) {
	e := fixture(t)
	e.h.cfg.FeederEnabled = true
	e.h.cfg.FeedInterval = time.Millisecond
	e.props["k0scontroller.service:MainPID"] = "4242"
	e.active["k0scontroller.service"] = "active"
	e.props["k0scontroller.service:ActiveEnterTimestampMonotonic"] = "1"
	e.alive[e.h.cfg.FeedProbeURL] = false

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.h.runFeeder(ctx); close(done) }()
	deadline := time.After(5 * time.Second)
	for e.rstN() == 0 {
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatal("remediate did not restart after grace fails")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
	if e.rstAt(0) != "k0scontroller.service" {
		t.Fatalf("wrong unit restarted: %v", e.rstAt(0))
	}
}

func TestFeederFeedsWhileAlive(t *testing.T) {
	e := fixture(t)
	e.h.cfg.FeederEnabled = true
	e.h.cfg.FeedInterval = time.Millisecond
	e.props["k0scontroller.service:MainPID"] = "4242"
	e.active["k0scontroller.service"] = "active"
	e.alive[e.h.cfg.FeedProbeURL] = true

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.h.runFeeder(ctx); close(done) }()
	deadline := time.After(5 * time.Second)
	for e.notifN() < 3 {
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatalf("feeder starved: %d", e.notifN())
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
	if e.rstN() != 0 {
		t.Fatal("restart triggered while apiserver alive")
	}
}

func TestRemediateG1PassNoRestart(t *testing.T) {
	e := fixture(t)
	e.active["k0scontroller.service"] = "active"
	e.alive[e.h.cfg.FeedProbeURL] = true // re-probe says alive
	e.h.runRemediate(context.Background())
	if e.rstN() != 0 {
		t.Fatal("G1 false-alarm still restarted")
	}
}

func TestRemediateG5RateLimited(t *testing.T) {
	e := fixture(t)
	e.active["k0scontroller.service"] = "active"
	e.props["k0scontroller.service:ActiveEnterTimestampMonotonic"] = "1"
	e.alive[e.h.cfg.FeedProbeURL] = false
	// Fresh budget: last restart just now.
	h := e.h
	h.writeEpochFile(filepath.Join(e.fstate, fileFeederLastRst))
	e.h.runRemediate(context.Background())
	if e.rstN() != 0 {
		t.Fatal("G5 rate-limit bypassed")
	}
}

// --- misc ---

func TestRunDisabledIdles(t *testing.T) {
	e := fixture(t)
	e.h.cfg.Enabled = false
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.h.Run(ctx); close(done) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("disabled Run did not exit on cancel")
	}
}

func TestPGWire(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback")
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("R")) // auth request = healthy
			}(c)
		}
	}()
	if !pgWireOK(context.Background(), ln.Addr().String()) {
		t.Fatal("pgWireOK rejected an R response")
	}
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback")
	}
	defer ln2.Close()
	go func() {
		for {
			c, err := ln2.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("E")) // ErrorResponse = broken
			}(c)
		}
	}()
	if pgWireOK(context.Background(), ln2.Addr().String()) {
		t.Fatal("pgWireOK accepted an E response")
	}
}

func TestRemediateMarksBudgetBeforeRestart(t *testing.T) {
	e := fixture(t)
	e.active["k0scontroller.service"] = "active"
	e.props["k0scontroller.service:ActiveEnterTimestampMonotonic"] = "1"
	e.alive[e.h.cfg.FeedProbeURL] = false
	// restartFn asserts the G5 budget file ALREADY exists when the
	// restart executes — a mid-restart kill must not leave it unspent.
	e.h.cfg.restartFn = func(_ context.Context, unit string) error {
		if _, err := os.Stat(filepath.Join(e.fstate, fileFeederLastRst)); err != nil {
			t.Errorf("G5 budget not marked before restart: %v", err)
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		e.rst = append(e.rst, unit)
		return nil
	}
	e.h.runRemediate(context.Background())
	if e.rstN() != 1 {
		t.Fatal("restart did not run")
	}
}

func TestRemediateCreatesFeederStateDir(t *testing.T) {
	e := fixture(t)
	e.active["k0scontroller.service"] = "active"
	e.props["k0scontroller.service:ActiveEnterTimestampMonotonic"] = "1"
	e.alive[e.h.cfg.FeedProbeURL] = false
	if err := os.RemoveAll(e.fstate); err != nil {
		t.Fatal(err)
	}
	e.h.runRemediate(context.Background())
	if e.rstN() != 1 {
		t.Fatal("restart blocked by absent FeederStateDir")
	}
	if _, err := os.Stat(filepath.Join(e.fstate, fileFeederLastRst)); err != nil {
		t.Fatal("budget file not written into created dir")
	}
}

func TestSelfAPIStaysEmptyWhenUnset(t *testing.T) {
	h, err := New(Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h.cfg.SelfAPI != "" {
		t.Fatalf("SelfAPI=%q want empty (no loopback default)", h.cfg.SelfAPI)
	}
}

// --- Guard e: etcdguard (embedded-etcd quota self-defence) ---

// etcdGuardFake scripts the etcdctl probe seam and records the
// evpurge/rescue remediation calls.
type etcdGuardFake struct {
	ctlCalls [][]string
	status   string // canned `endpoint status -w json`
	alarms   string // canned `alarm list`
	purges   int
	cutoffs  []time.Time
	rescues  []etcdrescue.Config
}

func (g *etcdGuardFake) ctl(_ context.Context, args ...string) ([]byte, error) {
	g.ctlCalls = append(g.ctlCalls, append([]string{}, args...))
	j := strings.Join(args, " ")
	switch {
	case strings.Contains(j, "endpoint status"):
		return []byte(g.status), nil
	case strings.Contains(j, "alarm list"):
		return []byte(g.alarms), nil
	}
	return nil, fmt.Errorf("fake: unexpected etcdctl args %q", j)
}

// mkEtcdHost fabricates <k0s>/{bin/etcdctl,pki/etcd/ca.crt} — the
// file pair the guard's presence gate keys on — and returns the
// fabricated K0sDir.
func (e *env) mkEtcdHost(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(filepath.Dir(e.state), "k0s")
	writeFile(t, filepath.Join(dir, "bin", "etcdctl"), "#!/bin/sh\n")
	writeFile(t, filepath.Join(dir, "pki", "etcd", "ca.crt"), "fake\n")
	return dir
}

// wireEtcdGuard points cfg.K0sDir at the fabricated host tree and
// installs the scripted seams.
func (e *env) wireEtcdGuard(t *testing.T, g *etcdGuardFake) {
	t.Helper()
	e.h.cfg.K0sDir = e.mkEtcdHost(t)
	e.h.cfg.etcdctlFn = g.ctl
	e.h.cfg.evpurgeRunFn = func(_ context.Context, _ evpurge.Config,
		cutoff time.Time, _ io.Writer) error {
		g.purges++
		g.cutoffs = append(g.cutoffs, cutoff)
		return nil
	}
	e.h.cfg.etcdRescueFn = func(_ context.Context,
		cfg etcdrescue.Config, _ io.Writer) error {
		g.rescues = append(g.rescues, cfg)
		return nil
	}
}

// wireEtcdSeamsOnly installs the seams WITHOUT fabricating the K0sDir
// tree — the no-op tests assert the probe is never even spawned.
func (e *env) wireEtcdSeamsOnly(g *etcdGuardFake) {
	e.h.cfg.etcdctlFn = g.ctl
	e.h.cfg.evpurgeRunFn = func(context.Context, evpurge.Config,
		time.Time, io.Writer) error {
		g.purges++
		return nil
	}
	e.h.cfg.etcdRescueFn = func(_ context.Context,
		cfg etcdrescue.Config, _ io.Writer) error {
		g.rescues = append(g.rescues, cfg)
		return nil
	}
}

func etcdStatusJSON(dbSize, inUse int64) string {
	return fmt.Sprintf(`[{"Endpoint":"https://127.0.0.1:2379",`+
		`"Status":{"header":{"revision":1},"dbSize":%d,"dbSizeInUse":%d}}]`,
		dbSize, inUse)
}

func TestEtcdGuardAbsentEtcdctlNoop(t *testing.T) {
	e := fixture(t)
	g := &etcdGuardFake{status: etcdStatusJSON(1<<30, 1<<29)}
	e.wireEtcdSeamsOnly(g)
	// Point K0sDir at an empty dir — no bin/etcdctl.
	e.h.cfg.K0sDir = filepath.Join(filepath.Dir(e.state), "absent-k0s")
	e.h.Cycle(context.Background())
	if len(g.ctlCalls) != 0 || g.purges != 0 || len(g.rescues) != 0 {
		t.Fatalf("etcdguard ran without etcdctl: calls=%v purges=%d rescues=%d",
			g.ctlCalls, g.purges, len(g.rescues))
	}
}

func TestEtcdGuardAbsentCANoop(t *testing.T) {
	e := fixture(t)
	g := &etcdGuardFake{status: etcdStatusJSON(1<<30, 1<<29)}
	e.wireEtcdSeamsOnly(g)
	// bin/etcdctl present but pki/etcd/ca.crt absent — a half-seeded
	// k0s dir must still no-op.
	dir := filepath.Join(filepath.Dir(e.state), "k0s")
	writeFile(t, filepath.Join(dir, "bin", "etcdctl"), "#!/bin/sh\n")
	e.h.cfg.K0sDir = dir
	e.h.Cycle(context.Background())
	if len(g.ctlCalls) != 0 || g.purges != 0 || len(g.rescues) != 0 {
		t.Fatalf("etcdguard ran without etcd CA: calls=%v purges=%d rescues=%d",
			g.ctlCalls, g.purges, len(g.rescues))
	}
}

func TestEtcdGuardBelowThreshold(t *testing.T) {
	e := fixture(t)
	g := &etcdGuardFake{
		status: etcdStatusJSON(100<<20, 90<<20), // ~100MiB — healthy
		alarms: "",
	}
	e.wireEtcdGuard(t, g)
	e.h.Cycle(context.Background())
	if g.purges != 0 || len(g.rescues) != 0 {
		t.Fatalf("healthy etcd triggered remediation: purges=%d rescues=%d",
			g.purges, len(g.rescues))
	}
	if got := testutil.ToFloat64(e.h.etcdDBSize); got != float64(100<<20) {
		t.Fatalf("db_size gauge=%v want %v", got, 100<<20)
	}
	if got := testutil.ToFloat64(e.h.etcdDBUse); got != float64(90<<20) {
		t.Fatalf("db_in_use gauge=%v want %v", got, 90<<20)
	}
	if got := testutil.ToFloat64(e.h.etcdNospace); got != 0 {
		t.Fatalf("nospace gauge=%v want 0", got)
	}
	// Both probes ran exactly once.
	if len(g.ctlCalls) != 2 {
		t.Fatalf("etcdctl calls=%v want status+alarm", g.ctlCalls)
	}
}

func TestEtcdGuardNospaceTriggers(t *testing.T) {
	e := fixture(t)
	g := &etcdGuardFake{
		status: etcdStatusJSON(100<<20, 90<<20), // small db
		alarms: "memberID:8845123669947417847 alarm:NOSPACE\n",
	}
	e.wireEtcdGuard(t, g)
	e.h.Cycle(context.Background())
	// The alarm alone triggers even below the size threshold.
	if g.purges != 1 || len(g.rescues) != 1 {
		t.Fatalf("nospace alarm did not trigger: purges=%d rescues=%d",
			g.purges, len(g.rescues))
	}
	if !g.rescues[0].OnlineOnly {
		t.Fatal("rescue ran without OnlineOnly — offline path allowed")
	}
	if g.rescues[0].CallTimeout != defaultEtcdGuardCallTimeout {
		t.Fatalf("rescue CallTimeout=%v want %v (the short guard cap, "+
			"not etcdrescue's 10m interactive default)",
			g.rescues[0].CallTimeout, defaultEtcdGuardCallTimeout)
	}
	if g.rescues[0].K0sDir != e.h.cfg.K0sDir {
		t.Fatalf("rescue K0sDir=%q want %q", g.rescues[0].K0sDir, e.h.cfg.K0sDir)
	}
	if got := testutil.ToFloat64(e.h.etcdNospace); got != 1 {
		t.Fatalf("nospace gauge=%v want 1", got)
	}
	// Rate budget spent.
	if h := e.h.readEpoch(filepath.Join(e.state, fileRateEtcdGuard)); h == 0 {
		t.Fatal("last-etcd-guard budget not spent")
	}
	// The purge cutoff is now - 1h (the apiserver event TTL).
	if len(g.cutoffs) != 1 ||
		g.cutoffs[0] != e.now.Add(-eventStaleAge) {
		t.Fatalf("evpurge cutoff=%v want %v", g.cutoffs,
			e.now.Add(-eventStaleAge))
	}
}

func TestEtcdGuardSizeTriggers(t *testing.T) {
	e := fixture(t)
	g := &etcdGuardFake{
		status: etcdStatusJSON(defaultEtcdDBSizeLimit, 1<<30), // at limit
		alarms: "",
	}
	e.wireEtcdGuard(t, g)
	e.h.Cycle(context.Background())
	if g.purges != 1 || len(g.rescues) != 1 {
		t.Fatalf("dbSize>=limit did not trigger: purges=%d rescues=%d",
			g.purges, len(g.rescues))
	}
	if !g.rescues[0].OnlineOnly {
		t.Fatal("rescue ran without OnlineOnly")
	}
	// dbSize already decided the trigger — the alarm-list probe is
	// skipped, so only `endpoint status` ran (hung-etcd probe
	// halving).
	if len(g.ctlCalls) != 1 ||
		!strings.Contains(strings.Join(g.ctlCalls[0], " "), "endpoint status") {
		t.Fatalf("etcdctl calls=%v want status only (alarm probe skipped)",
			g.ctlCalls)
	}
}

func TestEtcdGuardRateLimitSuppressesSecondRun(t *testing.T) {
	e := fixture(t)
	g := &etcdGuardFake{
		status: etcdStatusJSON(defaultEtcdDBSizeLimit+1, 1<<30),
		alarms: "memberID:1 alarm:NOSPACE\n",
	}
	e.wireEtcdGuard(t, g)
	e.h.Cycle(context.Background()) // run 1: spends the budget
	if g.purges != 1 || len(g.rescues) != 1 {
		t.Fatalf("first guard run missing: purges=%d rescues=%d",
			g.purges, len(g.rescues))
	}
	e.h.Cycle(context.Background()) // still tripped but in cooldown
	if g.purges != 1 || len(g.rescues) != 1 {
		t.Fatalf("cooldown did not suppress second run: purges=%d rescues=%d",
			g.purges, len(g.rescues))
	}
	// Past the 1h window the guard fires again.
	e.now = e.now.Add(2 * time.Hour)
	e.h.Cycle(context.Background())
	if g.purges != 2 || len(g.rescues) != 2 {
		t.Fatalf("post-window run missing: purges=%d rescues=%d",
			g.purges, len(g.rescues))
	}
}

func TestEtcdGuardStatusErrorNoop(t *testing.T) {
	e := fixture(t)
	g := &etcdGuardFake{status: "not json"}
	e.wireEtcdGuard(t, g)
	e.h.Cycle(context.Background())
	if g.purges != 0 || len(g.rescues) != 0 {
		t.Fatalf("unparseable status triggered remediation: purges=%d rescues=%d",
			g.purges, len(g.rescues))
	}
}

// watchdogLog returns the appended watchdog log file.
func watchdogLog(t *testing.T, e *env) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(filepath.Dir(e.state), "watchdog.log"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestEtcdGuardRunCtxBounded(t *testing.T) {
	// Both remediation steps must run under a bounded ctx — the
	// guard budget (~10m), never the process-lifetime ctx.
	e := fixture(t)
	g := &etcdGuardFake{
		status: etcdStatusJSON(defaultEtcdDBSizeLimit+1, 1<<30),
	}
	e.h.cfg.K0sDir = e.mkEtcdHost(t)
	e.h.cfg.etcdctlFn = g.ctl
	var purgeDL, rescueDL time.Time
	e.h.cfg.evpurgeRunFn = func(ctx context.Context, _ evpurge.Config,
		_ time.Time, _ io.Writer) error {
		g.purges++
		d, ok := ctx.Deadline()
		if !ok {
			t.Error("evpurge ctx carries no deadline")
			return nil
		}
		purgeDL = d
		return nil
	}
	e.h.cfg.etcdRescueFn = func(ctx context.Context,
		cfg etcdrescue.Config, _ io.Writer) error {
		g.rescues = append(g.rescues, cfg)
		d, ok := ctx.Deadline()
		if !ok {
			t.Error("rescue ctx carries no deadline")
			return nil
		}
		rescueDL = d
		return nil
	}
	e.h.Cycle(context.Background())
	for _, d := range []time.Time{purgeDL, rescueDL} {
		rem := time.Until(d)
		if rem > defaultEtcdGuardBudget || rem < defaultEtcdGuardBudget-time.Minute {
			t.Fatalf("remediation ctx deadline in %s — want ~%s out",
				rem, defaultEtcdGuardBudget)
		}
	}
}

func TestEtcdGuardBudgetExhaustedDefers(t *testing.T) {
	// evpurge stalls until its ctx dies: the 80ms parent deadline
	// stands in for the guard budget (gctx inherits the earlier of
	// the two, and its Err() is still DeadlineExceeded). The guard
	// must abort cleanly — budget stays spent, the rescue is not
	// spawned on a dead ctx, and the deferral is logged.
	e := fixture(t)
	g := &etcdGuardFake{
		status: etcdStatusJSON(defaultEtcdDBSizeLimit+1, 1<<30),
	}
	e.h.cfg.K0sDir = e.mkEtcdHost(t)
	e.h.cfg.etcdctlFn = g.ctl
	e.h.cfg.evpurgeRunFn = func(ctx context.Context, _ evpurge.Config,
		_ time.Time, _ io.Writer) error {
		g.purges++
		<-ctx.Done()
		return ctx.Err()
	}
	e.h.cfg.etcdRescueFn = func(context.Context,
		etcdrescue.Config, io.Writer) error {
		g.rescues = append(g.rescues, etcdrescue.Config{})
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	e.h.Cycle(ctx)
	if g.purges != 1 {
		t.Fatalf("evpurge runs=%d want 1", g.purges)
	}
	if len(g.rescues) != 0 {
		t.Fatal("rescue spawned on an already-dead guard ctx")
	}
	// The rate budget stays spent — a timeout defers to the next
	// window, it does not refund.
	if v := e.h.readEpoch(filepath.Join(e.state, fileRateEtcdGuard)); v == 0 {
		t.Fatal("last-etcd-guard budget not spent")
	}
	if log := watchdogLog(t, e); !strings.Contains(log, "budget") ||
		!strings.Contains(log, "deferred") {
		t.Fatalf("exhausted budget not logged clearly:\n%s", log)
	}
}

func TestRunCycleDeadlineAbortsStall(t *testing.T) {
	// A hung etcdctl blocks its seam until the cycle ctx dies —
	// the per-cycle deadline must interrupt the stall, propagate
	// into the child call, and get logged.
	e := fixture(t)
	e.h.cfg.CycleTimeout = 60 * time.Millisecond
	e.h.cfg.K0sDir = e.mkEtcdHost(t)
	var once sync.Once
	started := make(chan struct{})
	var sawErr error
	e.h.cfg.etcdctlFn = func(ctx context.Context, _ ...string) ([]byte, error) {
		once.Do(func() { close(started) })
		<-ctx.Done()
		sawErr = ctx.Err()
		return nil, ctx.Err()
	}
	e.h.cfg.evpurgeRunFn = func(context.Context, evpurge.Config,
		time.Time, io.Writer) error {
		return nil
	}
	e.h.cfg.etcdRescueFn = func(context.Context,
		etcdrescue.Config, io.Writer) error {
		return nil
	}
	start := time.Now()
	e.h.runCycle(context.Background())
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("cycle ran %s — deadline did not abort the stall", took)
	}
	<-started // runCycle returned → the seam was called and released
	if sawErr == nil {
		t.Fatal("stalled child never saw the ctx cancellation")
	}
	if log := watchdogLog(t, e); !strings.Contains(log, "cycle deadline") {
		t.Fatalf("cycle deadline not logged:\n%s", log)
	}
}

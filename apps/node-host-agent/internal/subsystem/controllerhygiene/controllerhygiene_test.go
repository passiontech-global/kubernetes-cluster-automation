package controllerhygiene

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/ops/etcdmaint"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/ops/eventpurge"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
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
	jerr    error
	jany    string
	janyErr error
	jdir    string
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
		jany:   "-- No entries --\n",
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
	e.jdir = filepath.Join(root, "journal")
	for _, d := range []string{e.state, e.proc, e.fstate, e.jdir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	testutil.WriteFile(t, e.unit, "[Service]\nExecStart=/usr/bin/k0s controller\n")
	// Past the 20min uptime gate by default.
	testutil.WriteFile(t, filepath.Join(e.proc, "uptime"), "86400.00 12345.00\n")

	h, err := New(Config{
		Interval:              time.Hour,
		WatchdogStateDir:      e.state,
		WatchdogLogFile:       filepath.Join(root, "watchdog.log"),
		ProcRoot:              e.proc,
		K0sControllerUnitFile: e.unit,
		Hub: HubConfig{
			SelfEndpoint: "127.0.0.1:6443",
			SelfAPI:      "10.0.0.1:6443",
			PeerAPI:      "10.0.0.2:6443",
		},
		AdminKubeconfig: filepath.Join(root, "missing-admin.conf"),
		AdminCert:       filepath.Join(root, "missing-admin.crt"),
		OOMLoop:         OOMLoopConfig{Mode: ModeEnforce, CGroupEventsFile: e.cg},
		Feeder: FeederConfig{
			StateDir:          e.fstate,
			RemediatePeerFile: filepath.Join(root, "peer.conf"),
		},
		Sig13:       Sig13Config{Mode: ModeEnforce},
		KineTTL:     KineTTLConfig{Mode: ModeEnforce},
		KinePool:    KinePoolConfig{Mode: ModeEnforce},
		JournalDirs: []string{e.jdir},
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
		return e.journal, e.jerr
	}
	// Unfiltered journald probe: report journald alive so scripted
	// empty unit journals classify as a quiet unit, never as
	// journald-level blindness.
	cfg.journalAnyFn = func(context.Context) (string, error) {
		return e.jany, e.janyErr
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
			return "", errors.New("no prop")
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
	testutil.WriteFile(t, filepath.Join(d, "comm"), comm+"\n")
	testutil.WriteFile(t, filepath.Join(d, "cmdline"), strings.Join(args, "\x00")+"\x00")
	// starttime = field 22 (index 19 after ')') in jiffies.
	start := int64((86400.0 - age) * clkTck)
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0] = "S" // state
	fields[19] = strconv.FormatInt(start, 10)
	testutil.WriteFile(t, filepath.Join(d, "stat"),
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
		testutil.WriteFile(t, tcp, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
	}
	f, err := os.OpenFile(tcp, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	// Columns: sl local rem st tx:rx tr:tm retr uid timeout inode ...
	_, _ = fmt.Fprintf(f, "   1: 0100007F:1234 0A0000FF:%04X 01 00000000:00000000 00:00000000 00000000 0 0 %s 1 0000000000000000\n",
		dbPort, inode)
}

// setUnitStart stamps the unit's wall-clock start time age ago —
// the remediate G3 fresh-start gate parses the unit's
// ActiveEnterTimestamp (CLOCK_REALTIME side, not the monotonic
// prop).
func (e *env) setUnitStart(unit string, age time.Duration) {
	e.props[unit+":ActiveEnterTimestamp"] =
		e.now.Add(-age).Format(systemdTimestampLayout)
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
	testutil.WriteFile(t, filepath.Join(root, "etc/systemd/system/k0scontroller.service"), "[Service]\n")
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
	testutil.WriteFile(t, filepath.Join(e.proc, "uptime"), "300.00 1.00\n")
	e.setRV("127.0.0.1:6443", false, 100000, true)
	e.setRV("127.0.0.1:6443", true, 1, true)
	e.h.Cycle(context.Background())
	if e.rstN() != 0 {
		t.Fatal("uptime gate did not block the wedge guard")
	}
}

// --- misc ---

func TestSelfAPIStaysEmptyWhenUnset(t *testing.T) {
	h, err := New(Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h.cfg.Hub.SelfAPI != "" {
		t.Fatalf("SelfAPI=%q want empty (no loopback default)", h.cfg.Hub.SelfAPI)
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
	e.h.cfg.evpurgeRunFn = func(context.Context, eventpurge.Config,
		time.Time, io.Writer) error {
		return nil
	}
	e.h.cfg.etcdRescueFn = func(context.Context,
		etcdmaint.Config, io.Writer) error {
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

// countLogLines returns the number of watchdog log lines containing
// needle.
func countLogLines(t *testing.T, e *env, needle string) int {
	t.Helper()
	n := 0
	for _, l := range strings.Split(watchdogLog(t, e), "\n") {
		if strings.Contains(l, needle) {
			n++
		}
	}
	return n
}

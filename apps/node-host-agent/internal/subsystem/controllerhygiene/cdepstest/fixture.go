// Package cdepstest holds the shared controllerhygiene test
// fixture — the tempdir host trees, stubbed externals and
// controllable clock that used to be the parent package's private
// env/fixture. It is a NON-test package on purpose: the domain
// check packages' external test files (package X_test beside the
// check) import it.
//
// It deliberately does NOT import controllerhygiene — the parent's
// own test package imports THIS package, so importing back would
// cycle. Fixture therefore builds the cdeps.Config + environment
// and Bind()s a caller-built *cdeps.Deps; each consuming test
// package wraps it with its own env{H *controllerhygiene.Hygiene}
// (one-line fixture() helper) — see controllerhygiene_test.go.
package cdepstest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/feeder"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// RVResult is one scripted LIST answer (endpoint → cached → result).
type RVResult struct {
	RV int64
	OK bool
}

// KillRecord is one stubbed signal delivery.
type KillRecord struct {
	PID int
	Sig syscall.Signal
}

// Fixture is the shared test environment: tempdir host trees +
// stubbed externals + a controllable clock. Tests are fully
// hermetic — "processes" are just files under Proc, "systemctl" a
// recorded call list, "journal" a scripted string. Cfg is a
// controllerhygiene-ready Config; the consumer builds the Hygiene
// (controllerhygiene.New(f.Cfg, reg)) and calls Bind(h.Deps) so
// every seam answers from this fixture.
type Fixture struct {
	Cfg cdeps.Config

	// Host-tree paths under the per-test tempdir.
	State  string // WatchdogStateDir — state-* latches + last-* budgets
	Proc   string // ProcRoot — fake /proc
	FState string // Feeder.StateDir
	Unit   string // K0sControllerUnitFile — the worker gate
	CG     string // OOMLoop.CGroupEventsFile
	JDir   string // JournalDirs[0]

	Now     time.Time
	RV      map[string]map[bool]RVResult // endpoint -> cached -> result
	Journal string
	JErr    error
	JAny    string
	JAnyErr error
	PgOK    bool
	Kills   []KillRecord
	Props   map[string]string // "unit:prop" -> value
	Active  map[string]string // unit -> state
	Alive   map[string]bool   // url -> probe result

	Mu    sync.Mutex // feeder goroutine writes Rst/Notif asynchronously
	Rst   []string
	Notif []string
}

// New builds the fixture environment: tempdir host trees, a
// k0scontroller unit file (the all-checks gate — tests that need
// it OFF remove Unit), a proc tree past the 20min uptime gate, and
// Cfg wired with enforce modes + the journal dir. The caller then
// builds the Hygiene and Binds it — see the package doc.
func New(t *testing.T) *Fixture {
	t.Helper()
	root := t.TempDir()
	f := &Fixture{
		Now:    time.Now(),
		RV:     map[string]map[bool]RVResult{},
		JAny:   "-- No entries --\n",
		PgOK:   true,
		Props:  map[string]string{},
		Active: map[string]string{},
		Alive:  map[string]bool{},
	}
	f.State = filepath.Join(root, "watchdog")
	f.Proc = filepath.Join(root, "proc")
	f.FState = filepath.Join(root, "feeder-state")
	f.Unit = filepath.Join(root, "k0scontroller.service")
	f.CG = filepath.Join(root, "memory.events")
	f.JDir = filepath.Join(root, "journal")
	for _, d := range []string{f.State, f.Proc, f.FState, f.JDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	testutil.WriteFile(t, f.Unit, "[Service]\nExecStart=/usr/bin/k0s controller\n")
	// Past the 20min uptime gate by default.
	testutil.WriteFile(t, filepath.Join(f.Proc, "uptime"), "86400.00 12345.00\n")
	f.Cfg = cdeps.Config{
		Interval:              time.Hour,
		WatchdogStateDir:      f.State,
		WatchdogLogFile:       filepath.Join(root, "watchdog.log"),
		ProcRoot:              f.Proc,
		K0sControllerUnitFile: f.Unit,
		Hub: cdeps.HubConfig{
			SelfEndpoint: "127.0.0.1:6443",
			SelfAPI:      "10.0.0.1:6443",
			PeerAPI:      "10.0.0.2:6443",
		},
		AdminKubeconfig: filepath.Join(root, "missing-admin.conf"),
		AdminCert:       filepath.Join(root, "missing-admin.crt"),
		OOMLoop:         cdeps.OOMLoopConfig{Mode: cdeps.ModeEnforce, CGroupEventsFile: f.CG},
		Feeder: cdeps.FeederConfig{
			StateDir:          f.FState,
			RemediatePeerFile: filepath.Join(root, "peer.conf"),
		},
		Sig13:       cdeps.Sig13Config{Mode: cdeps.ModeEnforce},
		KineTTL:     cdeps.KineTTLConfig{Mode: cdeps.ModeEnforce},
		KinePool:    cdeps.KinePoolConfig{Mode: cdeps.ModeEnforce},
		JournalDirs: []string{f.JDir},
	}
	return f
}

// Bind stubs every test seam on the caller-built Deps: signals never
// touch real processes, probes are canned, the journal snapshot is a
// scripted string. Call it after controllerhygiene.New — the seams
// live on d.Cfg, which the checks read through the same *Deps.
func (f *Fixture) Bind(d *cdeps.Deps) {
	d.Cfg.Clock.Set(func() time.Time { return f.Now })
	d.Cfg.SleepFn = func(time.Duration) {}
	d.Cfg.KillFn = func(pid int, sig syscall.Signal) error {
		f.Kills = append(f.Kills, KillRecord{pid, sig})
		return nil
	}
	d.Cfg.ListRVFn = func(_ context.Context, ep string, cached bool) (int64, bool) {
		r, ok := f.RV[ep][cached]
		if !ok {
			return 0, false
		}
		return r.RV, true
	}
	d.Cfg.JournalFn = func(context.Context, string, time.Time) (string, error) {
		return f.Journal, f.JErr
	}
	// Unfiltered journald probe: report journald alive so scripted
	// empty unit journals classify as a quiet unit, never as
	// journald-level blindness.
	d.Cfg.JournalAnyFn = func(context.Context) (string, error) {
		return f.JAny, f.JAnyErr
	}
	d.Cfg.PgWireFn = func(context.Context, string) bool { return f.PgOK }
	d.Cfg.RestartFn = func(_ context.Context, unit string) error {
		f.Mu.Lock()
		defer f.Mu.Unlock()
		f.Rst = append(f.Rst, unit)
		return nil
	}
	d.Cfg.PropFn = func(_ context.Context, unit, prop string) (string, error) {
		v, ok := f.Props[unit+":"+prop]
		if !ok {
			return "", errors.New("no prop")
		}
		return v, nil
	}
	d.Cfg.IsActiveFn = func(_ context.Context, unit string) (string, error) {
		return f.Active[unit], nil
	}
	d.Cfg.NotifyFn = func(msg string) error {
		f.Mu.Lock()
		defer f.Mu.Unlock()
		f.Notif = append(f.Notif, msg)
		return nil
	}
	d.Cfg.ProbeFn = func(_ context.Context, url string) bool { return f.Alive[url] }
}

// RstN returns the restart-call count (locked — feeder runs async).
func (f *Fixture) RstN() int {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	return len(f.Rst)
}

// RstAt returns restart-call i.
func (f *Fixture) RstAt(i int) string {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	return f.Rst[i]
}

// NotifN returns the notify-call count (locked).
func (f *Fixture) NotifN() int {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	return len(f.Notif)
}

// NotifAt returns notify-call i.
func (f *Fixture) NotifAt(i int) string {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	return f.Notif[i]
}

// SetRV scripts a LIST response for an endpoint, cached or
// consistent.
func (f *Fixture) SetRV(ep string, cached bool, rv int64, ok bool) {
	if f.RV[ep] == nil {
		f.RV[ep] = map[bool]RVResult{}
	}
	f.RV[ep][cached] = RVResult{RV: rv, OK: ok}
}

// MkProc fabricates a running process under Proc: comm, cmdline, a
// stat with a sane starttime (age seconds ago).
func (f *Fixture) MkProc(t *testing.T, pid int, comm string, args []string, age float64) {
	t.Helper()
	d := filepath.Join(f.Proc, strconv.Itoa(pid))
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(d, "comm"), comm+"\n")
	testutil.WriteFile(t, filepath.Join(d, "cmdline"), strings.Join(args, "\x00")+"\x00")
	// starttime = field 22 (index 19 after ')') in jiffies.
	start := int64((86400.0 - age) * cdeps.ClkTck)
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0] = "S" // state
	fields[19] = strconv.FormatInt(start, 10)
	testutil.WriteFile(t, filepath.Join(d, "stat"),
		fmt.Sprintf("%d (%s) %s", pid, comm, strings.Join(fields, " ")))
}

// MkSock links one fd to a socket inode and appends a net/tcp row
// to remote port dbPort (ESTABLISHED).
func (f *Fixture) MkSock(t *testing.T, pid int, fd int, inode string, dbPort int) {
	t.Helper()
	d := filepath.Join(f.Proc, strconv.Itoa(pid), "fd")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fmt.Sprintf("socket:[%s]", inode),
		filepath.Join(d, strconv.Itoa(fd))); err != nil {
		t.Fatal(err)
	}
	tcp := filepath.Join(f.Proc, strconv.Itoa(pid), "net", "tcp")
	if _, err := os.Stat(tcp); os.IsNotExist(err) {
		testutil.WriteFile(t, tcp, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
	}
	fh, err := os.OpenFile(tcp, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	// Columns: sl local rem st tx:rx tr:tm retr uid timeout inode ...
	_, _ = fmt.Fprintf(fh, "   1: 0100007F:1234 0A0000FF:%04X 01 00000000:00000000 00:00000000 00000000 0 0 %s 1 0000000000000000\n",
		dbPort, inode)
}

// SetUnitStart stamps the unit's wall-clock start time age ago —
// the remediate G3 fresh-start gate parses the unit's
// ActiveEnterTimestamp (CLOCK_REALTIME side, not the monotonic
// prop).
func (f *Fixture) SetUnitStart(unit string, age time.Duration) {
	f.Props[unit+":ActiveEnterTimestamp"] =
		f.Now.Add(-age).Format(feeder.SystemdTimestampLayout)
}

// MkEtcdHost fabricates <k0s>/{bin/etcdctl,pki/etcd/ca.crt} — the
// file pair the guard's presence gate keys on — and returns the
// fabricated K0sDir.
func (f *Fixture) MkEtcdHost(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(filepath.Dir(f.State), "k0s")
	testutil.WriteFile(t, filepath.Join(dir, "bin", "etcdctl"), "#!/bin/sh\n")
	testutil.WriteFile(t, filepath.Join(dir, "pki", "etcd", "ca.crt"), "fake\n")
	return dir
}

// StateFile returns the state-<name> latch path.
func (f *Fixture) StateFile(name string) string {
	return filepath.Join(f.State, "state-"+name)
}

// HasState reports whether the state-<name> latch exists.
func (f *Fixture) HasState(name string) bool {
	_, err := os.Stat(f.StateFile(name))
	return err == nil
}

// LogLines returns the appended watchdog log so far ("" when
// unwritten). It takes the Fixture rather than a Hygiene —
// cdepstest never imports controllerhygiene.
func (f *Fixture) LogLines() string {
	data, err := os.ReadFile(filepath.Join(filepath.Dir(f.State), "watchdog.log"))
	if err != nil {
		return ""
	}
	return string(data)
}

// CountLogLines returns the number of watchdog log lines containing
// needle.
func (f *Fixture) CountLogLines(needle string) int {
	n := 0
	for _, l := range strings.Split(f.LogLines(), "\n") {
		if strings.Contains(l, needle) {
			n++
		}
	}
	return n
}

// CheckNamer is the slice of *controllerhygiene.Hygiene the typed
// accessor needs — declared here so this package never imports
// controllerhygiene (the parent's own test package imports THIS
// one).
type CheckNamer interface {
	Check(name string) cdeps.Check
}

// Check returns the Hygiene's registered check name typed as C —
// the external domain test packages' handle on their check's
// streak/latch state. It panics on a wrong name or type — a
// fixture bug, not a test failure.
func Check[C cdeps.Check](h CheckNamer, name string) C {
	c := h.Check(name)
	if c == nil {
		panic("cdepstest.Check: no check named " + name)
	}
	typed, ok := c.(C)
	if !ok {
		var want C
		panic(fmt.Sprintf("cdepstest.Check: %s is %T, not %T", name, c, want))
	}
	return typed
}

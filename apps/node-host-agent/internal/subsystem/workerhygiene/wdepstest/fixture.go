// Package wdepstest holds the shared workerhygiene test fixture —
// the tempdir host trees, canned probe answers and controllable
// clock that used to be the parent package's private env/fixture.
// It is a NON-test package on purpose: the domain check packages'
// external test files (package X_test beside the check) import it.
//
// It deliberately does NOT import workerhygiene — the parent's own
// test package imports THIS package, so importing back would cycle.
// Fixture therefore builds the wdeps.Config + environment and
// Bind()s a caller-built *wdeps.Deps; each consuming test package
// wraps it with its own env{H *workerhygiene.Hygiene} (one-line
// fixture() helper) — see workerhygiene_test.go for the shape.
//
// The proc/task/pod builders live in builders.go; the free helpers
// in helpers.go.
package wdepstest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	nhatestutil "github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil/hostfixture"
)

// KillRecord is the shared stubbed-signal record — see
// internal/testutil/hostfixture (was the unexported killRecord in
// workerhygiene_test.go).
type KillRecord = hostfixture.KillRecord

// Fixture is the shared test environment: tempdir host trees + a
// stubbed kill function + a controllable clock. Tests run rootless —
// "live" processes are just entries in Live plus a stat file under
// ProcDir, systemd is a fake argv recorder, and HTTP/unix/journal
// probes are canned. Cfg is a workerhygiene-ready Config; the
// consumer builds the Hygiene (workerhygiene.New(f.Cfg, reg)) and
// calls Bind(h.Deps) so every seam answers from this fixture.
type Fixture struct {
	Cfg wdeps.Config
	CS  *fake.Clientset

	// Host-tree paths under the per-test tempdir.
	StateDir    string // WatchdogStateDir — state-* latches + last-* budgets
	ProcDir     string // ProcRoot — fake /proc
	CtrDir      string // CtrTaskRoot — containerd task dirs
	SbDir       string // SandboxCtlRoot
	ResolvConf  string // HostResolvConf
	UnitFile    string // K0sWorkerUnitFile — the worker gate
	KubepodsDir string // PodsDir
	IngestDir   string // Ctr.IngestDir
	SysNet      string // SysClassNet
	CiliumRt    string // Cilium.RuntimeConfig
	JDir        string // Journal.Dirs[0]

	Live   map[int]bool // pids KillFn(0) reports alive
	Kills  []KillRecord
	Now    time.Time  // Cfg.Seams.Host.Clock reads this — advance to age budgets
	SDCmds [][]string // systemd fake argv log
	// SDHook, when set, runs inside sdRun before the reply lookup —
	// tests advance the fake clock here to simulate a slow host call
	// (e.g. a D-Bus round trip taking seconds).
	SDHook  func(joined string)
	SDReply map[string]string // argv-substring → canned stdout

	// LinkDels records every interface name LinkDelFn was asked to
	// delete (the calico orphan-veth GC); LinkDelErrs injects a
	// per-name failure — nil map entry means the delete succeeds.
	LinkDels    []string
	LinkDelErrs map[string]error

	Probes   map[string]error  // url → error (nil = healthy)
	Status   map[string]int    // url → canned HTTP status for probeHTTPStatus
	Bearer   map[string]string // url → bearer token the probe carried
	SockErrs map[string]error  // unix socket path → dial error
	DiskUsed float64           // /var/lib/k0s fill ratio for statfsFn
	BodyOK   map[string]bool   // :10248 healthz body=="ok" canned answers
	UnixBody []byte
	UnixErr  error

	Journal    string // k0sworker journal snapshot body
	JournalErr error

	DNSTCP bool // cilium-lrp :53 TCP probe canned answer
	// SvcBackends is the canned cilium-lrp BPF service map —
	// "<ns>/<name>" → backend count, rendered into the /v1/service
	// wire shape by the UnixGet stub (SvcErr wins: an unreadable
	// map probe).
	SvcBackends map[string]int
	SvcErr      error
	MetricsBody string // kubelet /metrics canned body (PLEG)
	MetricsErr  error  // kubelet /metrics canned error

	mu sync.Mutex // guards SDCmds (feeder goroutine + Cycle both record)
}

// sdRun is the systemd fake: records argv, answers is-active/show for
// k0sworker (active, settled >180s), errors on anything unconfigured.
func (f *Fixture) sdRun(_ context.Context, argv []string) (string, error) {
	f.mu.Lock()
	f.SDCmds = append(f.SDCmds, argv)
	f.mu.Unlock()
	joined := strings.Join(argv, " ")
	if f.SDHook != nil {
		f.SDHook(joined)
	}
	for k, v := range f.SDReply {
		if strings.Contains(joined, k) {
			return v, nil
		}
	}
	return "", syscall.ENOENT
}

// LinkDelRan reports whether LinkDelFn was asked to delete name.
func (f *Fixture) LinkDelRan(name string) bool {
	for _, n := range f.LinkDels {
		if n == name {
			return true
		}
	}
	return false
}

// SDRan reports whether any recorded systemd argv contains sub.
func (f *Fixture) SDRan(sub string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.SDCmds {
		if strings.Contains(strings.Join(c, " "), sub) {
			return true
		}
	}
	return false
}

// New builds the fixture environment: tempdir host trees, a
// k0sworker unit with --node-ip (the worker gate plus the
// konnectivity expected IP — tests that need the gate OFF remove
// UnitFile), a fake clientset seeded with objs, and Cfg carrying the
// wired systemd fake. The caller then builds the Hygiene and Binds
// it — see the package doc.
func New(t *testing.T, objs ...runtime.Object) *Fixture {
	t.Helper()
	root := t.TempDir()
	f := &Fixture{
		Live:     map[int]bool{},
		Now:      time.Now(),
		SDReply:  map[string]string{},
		Probes:   map[string]error{},
		Status:   map[string]int{},
		Bearer:   map[string]string{},
		SockErrs: map[string]error{},
		BodyOK:   map[string]bool{},
	}
	f.StateDir = filepath.Join(root, "watchdog")
	f.ProcDir = filepath.Join(root, "proc")
	f.CtrDir = filepath.Join(root, "ctrtask")
	f.SbDir = filepath.Join(root, "sbctl")
	f.ResolvConf = filepath.Join(root, "resolv.conf")
	f.UnitFile = filepath.Join(root, "k0sworker.service")
	f.KubepodsDir = filepath.Join(root, "kubeletpods")
	f.IngestDir = filepath.Join(root, "ingest")
	f.SysNet = filepath.Join(root, "sysnet")
	f.CiliumRt = filepath.Join(root, "agent-runtime-config.json")
	f.JDir = filepath.Join(root, "journal")
	for _, d := range []string{f.StateDir, f.ProcDir, f.CtrDir, f.SbDir,
		f.KubepodsDir, f.IngestDir, f.SysNet, f.JDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	WriteFile(t, f.UnitFile, "[Service]\nExecStart=/usr/bin/k0s worker --node-ip=10.1.2.3\n")

	f.CS = nhatestutil.FakeKube(objs...)
	// Host up 2h — the uptime file feeds BOTH the Cycle G1 uptime
	// gate (procfs.UptimeSeconds) and systemd.ActiveAge's monotonic
	// compare, so one file is one host clock.
	// ActiveEnterTimestampMonotonic is µs since boot: uptimeµs - 1h →
	// a 1h-old (settled) unit.
	WriteFile(t, filepath.Join(f.ProcDir, "uptime"), "7200.5 0\n")
	// RunCmd AND RunCmdCombined share the same fake — the journald
	// probes (Journal/journalAnyFn via ExecCombined) must observe the
	// canned replies too, and a nil combined seam would exec REAL
	// journalctl on the test host.
	sd := systemd.New(systemd.Config{HostRoot: "/", RunCmd: f.sdRun,
		RunCmdCombined: f.sdRun},
		systemd.WithProcUptimeFile(filepath.Join(f.ProcDir, "uptime")))
	// k0sworker is active and settled — the restart checks need both.
	f.SDReply["systemctl is-active k0sworker.service"] = "active\n"
	f.SDReply["ActiveEnterTimestampMonotonic --value k0sworker.service"] =
		fmt.Sprintf("%d\n", 7200500000-int64(time.Hour/time.Microsecond))
	f.Cfg = wdeps.Config{
		NodeName:          "node-a",
		Interval:          time.Hour,
		WatchdogStateDir:  f.StateDir,
		WatchdogLogFile:   filepath.Join(root, "watchdog.log"),
		ProcRoot:          f.ProcDir,
		CtrTaskRoot:       f.CtrDir,
		SandboxCtlRoot:    f.SbDir,
		K0sWorkerUnitFile: f.UnitFile,
		// Promoted wiring paths get the same tempdir treatment —
		// CtrSocket/NebulaIface keep their package defaults.
		K0sDataDir:         filepath.Join(root, "k0sdata"),
		PodsDir:            f.KubepodsDir,
		SysClassNet:        f.SysNet,
		HostResolvConf:     f.ResolvConf,
		Client:             f.CS,
		Systemd:            sd,
		ConsecNeeded:       2,
		MinRestartInterval: 30 * time.Minute,
		Kubelet: wdeps.KubeletConfig{
			WatchMinAge: 15 * time.Minute,
		},
		Teardown: wdeps.TeardownConfig{
			StuckDeleteAge: 20 * time.Minute,
			StuckWedgeAge:  30 * time.Minute,
			MaxForceDelete: 5,
		},
		// Base knobs: paths under the fixture root, never the real
		// /sys or /var/lib/k0s.
		Ctr: wdeps.CtrConfig{
			IngestDir:    f.IngestDir,
			MaxTaskClean: 5,
			MaxShimKill:  10,
		},
		Cilium: wdeps.CiliumConfig{
			RuntimeConfig: f.CiliumRt,
		},
		Pressure: wdeps.PressureConfig{
			ZombieStormThreshold: 500,
		},
		// Cgroup-v2 root under the fixture — pod memory.current
		// fixtures plant here; the real /sys/fs/cgroup is never
		// touched by a unit test.
		Runtime: wdeps.RuntimeConfig{
			CgroupRoot: filepath.Join(root, "cgroup"),
		},
		Journal: wdeps.JournalConfig{
			Dirs: []string{f.JDir},
		},
	}
	return f
}

// Bind stubs every test seam on the caller-built Deps: signals never
// touch real processes, probes are canned, the journal snapshot is a
// string. Call it after workerhygiene.New — the seams live on
// d.Cfg, which the checks read through the same *Deps.
func (f *Fixture) Bind(d *wdeps.Deps) {
	d.Cfg.Seams.Host.KillFn = func(pid int, sig syscall.Signal) error {
		if sig == 0 {
			if f.Live[pid] {
				return nil
			}
			return syscall.ESRCH
		}
		f.Kills = append(f.Kills, KillRecord{PID: pid, Sig: sig})
		return nil
	}
	// The calico orphan-veth delete rides the netlink seam now —
	// record names, answer from LinkDelErrs (absent = success).
	d.Cfg.Seams.Host.LinkDelFn = func(name string) error {
		f.LinkDels = append(f.LinkDels, name)
		return f.LinkDelErrs[name]
	}
	d.Cfg.Seams.Host.Clock.Set(func() time.Time { return f.Now })
	// Zombie-peer seams: the wg dump exec is canned as an error (tests
	// stub it with synthetic dump output) and the zombie clock rides
	// the same fake time as the host clock.
	d.Cfg.Seams.Cilium.WGDump = func(_ context.Context, _ *systemd.Client) (string, error) {
		return "", errors.New("wdepstest: wg dump not stubbed")
	}
	d.Cfg.Seams.Cilium.MonotonicNow = func() time.Time { return f.Now }
	d.Cfg.ProbeGap = 0             // tests run real-time — no 2s sleep between probes
	d.Cfg.Kubelet.WdReprobeGap = 0 // same: no 3s sleep between Gate-0 re-probes
	d.Cfg.Seams.Probe.ProbeHTTP = func(_ context.Context, url string, _ time.Duration) error {
		return f.Probes[url]
	}
	// Feeder seam: BodyOK[url] answers "does :10248 return body 'ok'".
	// Unset entry → false (unhealthy) — gate tests want fails anyway.
	d.Cfg.Seams.Probe.ProbeBodyOK = func(_ context.Context, url string, _ time.Duration) bool {
		return f.BodyOK[url]
	}
	// The agent socket stub is path-aware: /v1/service is rendered
	// from SvcBackends so the cilium-lrp desync check's canned map
	// goes through the real ParseCiliumServiceBackends wire shape;
	// every other path answers the flat UnixBody/UnixErr.
	d.Cfg.Seams.Cilium.UnixGet = func(_ context.Context, _, path string) ([]byte, error) {
		if path == "/v1/service" {
			return f.serviceBody()
		}
		return f.UnixBody, f.UnixErr
	}
	d.Cfg.Seams.Host.JournalFn = func(_ context.Context) (string, error) {
		return f.Journal, f.JournalErr
	}
	// Base seams: status-code probes default 200 (healthy) unless
	// Probes[url] errors or Status[url] overrides; the unix socket
	// probe answers from SockErrs (nil = connects); statfs reports
	// f.DiskUsed of 100 blocks.
	d.Cfg.Seams.Probe.ProbeHTTPStatus = func(_ context.Context, url, bearer string, _ time.Duration) (int, error) {
		f.Bearer[url] = bearer
		if err := f.Probes[url]; err != nil {
			return 0, err
		}
		if s, ok := f.Status[url]; ok {
			return s, nil
		}
		return 200, nil
	}
	d.Cfg.Seams.Probe.ProbeUnixSock = func(_ context.Context, socket string, _ time.Duration) error {
		return f.SockErrs[socket]
	}
	// Newer probe seams — canned defaults keep tests hermetic (the
	// production defaults would dial/exec on the test host).
	d.Cfg.Seams.Probe.DNSProbeTCP = func(context.Context, string, string, time.Duration) bool {
		return f.DNSTCP
	}
	d.Cfg.Seams.Probe.KubeletMetricsFn = func(_ context.Context, _, _ string, _ time.Duration) (string, error) {
		return f.MetricsBody, f.MetricsErr
	}
	d.Cfg.Seams.Host.StatfsFn = func(_ string, st *unix.Statfs_t) error {
		st.Blocks = 100
		st.Bavail = uint64(100 - int(f.DiskUsed*100))
		return nil
	}
	// The single Ctr exec seam — record the argv like the systemd
	// fake does (SDRan substring assertions keep working on the
	// joined command line) and succeed quietly, the same default
	// the old CtrRmIngest stub carried. Tests needing exec
	// failures or argv inspection re-stub Seams.Ctr.Exec.
	d.Cfg.Seams.Ctr.Exec = func(_ context.Context, argv ...string) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.SDCmds = append(f.SDCmds, append([]string(nil), argv...))
		return nil
	}
}

// serviceBody renders f.SvcBackends ("<ns>/<name>" → backend count)
// in the GET /v1/service wire shape ParseCiliumServiceBackends
// consumes — the canned body the UnixGet stub serves for that one
// path. f.SvcErr wins when set: an unreadable-map probe.
func (f *Fixture) serviceBody() ([]byte, error) {
	if f.SvcErr != nil {
		return nil, f.SvcErr
	}
	type svcEntry struct {
		Spec struct {
			Name             string `json:"name"`
			Namespace        string `json:"namespace"`
			BackendAddresses []int  `json:"backend-addresses"`
		} `json:"spec"`
	}
	list := []svcEntry{}
	for key, n := range f.SvcBackends {
		ns, name, _ := strings.Cut(key, "/")
		var e svcEntry
		e.Spec.Name, e.Spec.Namespace = name, ns
		e.Spec.BackendAddresses = make([]int, n)
		list = append(list, e)
	}
	return json.Marshal(list)
}

// LogLines returns the watchdog log so far (empty when unwritten).
// It takes the Config rather than a Hygiene — wdepstest never
// imports workerhygiene.
func (f *Fixture) LogLines(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(f.Cfg.WatchdogLogFile)
	if err != nil {
		return ""
	}
	return string(data)
}

// controllerhygiene_test.go — the orchestration suite that stays
// at the parent package: the unit-file/uptime gates, ShouldRun,
// the runCycle deadline and the SelfAPI default. The fixture is the
// shared cdepstest.Fixture — domain check tests live beside their
// checks in the per-domain packages' external test files.
package controllerhygiene

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/etcdmaint"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/eventpurge"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// env pairs the shared cdepstest fixture with a real *Hygiene —
// cdepstest can't build the Hygiene itself (importing back would
// cycle). Every consuming test package declares this same thin
// wrapper.
type env struct {
	*cdepstest.Fixture
	H *Hygiene
}

// fixture builds the shared test environment — the same builder the
// domain packages' fixture wrappers use, plus New + Bind here.
func fixture(t *testing.T) *env {
	t.Helper()
	f := cdepstest.New(t)
	h, err := New(f.Cfg, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	f.Bind(h.Deps)
	return &env{Fixture: f, H: h}
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
	if err := os.Remove(e.Unit); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	// Nothing may happen without the unit file.
	if e.RstN() != 0 || len(e.Kills) != 0 {
		t.Fatal("actions ran without k0scontroller unit")
	}
}

func TestUptimeGate(t *testing.T) {
	e := fixture(t)
	testutil.WriteFile(t, filepath.Join(e.Proc, "uptime"), "300.00 1.00\n")
	e.SetRV("127.0.0.1:6443", false, 100000, true)
	e.SetRV("127.0.0.1:6443", true, 1, true)
	e.H.Cycle(context.Background())
	if e.RstN() != 0 {
		t.Fatal("uptime gate did not block the wedge guard")
	}
}

// --- misc ---

func TestSelfAPIStaysEmptyWhenUnset(t *testing.T) {
	h, err := New(Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h.Cfg.Hub.SelfAPI != "" {
		t.Fatalf("SelfAPI=%q want empty (no loopback default)", h.Cfg.Hub.SelfAPI)
	}
}

// watchdogLog returns the appended watchdog log file.
func watchdogLog(t *testing.T, e *env) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(filepath.Dir(e.State), "watchdog.log"))
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
	e.H.Cfg.CycleTimeout = 60 * time.Millisecond
	e.H.Cfg.K0sDir = e.MkEtcdHost(t)
	var once sync.Once
	started := make(chan struct{})
	var sawErr error
	e.H.Cfg.EtcdctlFn = func(ctx context.Context, _ ...string) ([]byte, error) {
		once.Do(func() { close(started) })
		<-ctx.Done()
		sawErr = ctx.Err()
		return nil, ctx.Err()
	}
	e.H.Cfg.EvpurgeRunFn = func(context.Context, eventpurge.Config,
		time.Time, io.Writer) error {
		return nil
	}
	e.H.Cfg.EtcdRescueFn = func(context.Context,
		etcdmaint.Config, io.Writer) error {
		return nil
	}
	start := time.Now()
	e.H.runCycle(context.Background())
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("cycle ran %s — deadline did not abort the stall", took)
	}
	<-started // runCycle returned → the seam was called and released
	if sawErr == nil {
		t.Fatal("stalled child never saw the ctx cancellation")
	}
	if log := e.LogLines(); !strings.Contains(log, "cycle deadline") {
		t.Fatalf("cycle deadline not logged:\n%s", log)
	}
}

// countLogLines returns the number of watchdog log lines containing
// needle.
func countLogLines(t *testing.T, e *env, needle string) int {
	t.Helper()
	n := 0
	for _, l := range strings.Split(e.LogLines(), "\n") {
		if strings.Contains(l, needle) {
			n++
		}
	}
	return n
}

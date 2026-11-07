// fixture_test.go — the engine's test fixture: a temp host tree +
// Store + clock cell, every exec/device seam pre-stubbed so a
// Refresh() can never touch the real host. This is the parent's
// fixture()/fixtureSeams stance rebuilt against Deps — the stubs
// now land as Deps fields instead of package-var reassignments.
package kernelfail

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// fixture is the engine wired over a temp host tree — no real
// /proc, /dev/kmsg, chronyc, dmesg or sysctl writes reach the
// host.
type fixture struct {
	r    *Runner
	deps Deps // the construction-time copy; r.deps is the live one
	log  string
}

// kfixture lays out the state/proc/host roots under t.TempDir() and
// returns the engine over them. The seams are stubbed to
// "disabled"/fixture paths — tests that exercise kmsg, dmesg or
// chronyc re-point r.deps.<seam> themselves.
func kfixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{
		"node-watchdog", "proc", "hostroot",
	} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	clock := timex.NewCell(nil)
	stateDir := filepath.Join(root, "node-watchdog")
	log := filepath.Join(root, "node-watchdog.log")
	deps := Deps{
		StateDir:         stateDir,
		ProcRoot:         filepath.Join(root, "proc"),
		HostRoot:         filepath.Join(root, "hostroot"),
		ConntrackMaxFile: filepath.Join(root, "nf_conntrack_max"),
		FileNRFile:       filepath.Join(root, "file-nr"),
		OpenEBSLocalDir:  "/var/openebs/local",
		Store:            hoststate.New(stateDir, log, clock.Now, logger),
		Clock:            clock,
		// Hermetic defaults — the real adjtimex/chronyc/dmesg
		// would feed live host data into assertions; the kmsg
		// candidates point at a (missing) fixture device so the
		// drain falls back to the stubbed dmesg path.
		Adjtimex: func(*unix.Timex) (int, error) { return 0, unix.ENOSYS },
		RunHostCmd: func(context.Context, ...string) (string, error) {
			return "", errors.New("exec disabled in tests")
		},
		KmsgDevicePaths: func(string) []string {
			return []string{filepath.Join(root, "dev", "kmsg")}
		},
	}
	return &fixture{r: New(deps), deps: deps, log: log}
}

// kmsgFixture seeds a resumable kmsg session: boot_id under ProcRoot,
// a kmsg cursor at seq 0, and records in the fixture device file.
func kmsgFixture(t *testing.T, deps Deps, records ...string) {
	t.Helper()
	bootDir := filepath.Join(deps.ProcRoot, "sys", "kernel", "random")
	if err := os.MkdirAll(bootDir, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(bootDir, "boot_id"), "testboot\n")
	testutil.WriteFile(t, filepath.Join(deps.StateDir, kmsgCursorFile),
		"kmsg testboot 0 0\n")
	var b strings.Builder
	for i, m := range records {
		fmt.Fprintf(&b, "6,%d,%d,0;%s\n", i+1, (i+1)*1000, m)
	}
	devDir := filepath.Dir(deps.KmsgDevicePaths(deps.HostRoot)[0])
	if err := os.MkdirAll(devDir, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, deps.KmsgDevicePaths(deps.HostRoot)[0], b.String())
}

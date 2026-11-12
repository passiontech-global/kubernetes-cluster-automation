// Package kdepstest holds the shared kinedb test fixture — the
// tempdir layout, fake exec runner and frozen clock that used to be
// the flat package's private fixture(). It is a NON-test package on
// purpose: the domain packages' internal test files (package
// probe|compact|maint beside the loop) import it, as does the root
// package's own suite.
//
// It deliberately does NOT import kinedb — the parent's own test
// package imports THIS package, so importing back would cycle.
// Config builds a kinedb-ready kdeps.Config (the same fields the
// old fixture injected); Deps wraps it into a *kdeps.Deps the
// domain workers construct directly (probe.New(d) etc.); the root
// suite instead passes the Config to kinedb.New.
package kdepstest

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// TestNow is the frozen-clock instant the fixture binds — the
// epoch the pre-split tests asserted last-run/last-compact
// timestamps against.
const TestNow = 1700000000

// Config builds a kinedb-ready kdeps.Config over a fresh tempdir:
// a stack .env with postgres/secret creds, per-dir textfile/guard
// paths, podman runtime, the frozen clock and the fake-exec +
// wire-ok seams. rules answer commands in order (testutil.ExecRule
// substring matching). Returns the config, the FakeExec (for
// On/FailOn/Joined assertions) and the tempdir root.
func Config(t *testing.T, rules []testutil.ExecRule) (kdeps.Config, *testutil.FakeExec, string) {
	t.Helper()
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile,
		[]byte("POSTGRES_USER=postgres\nPOSTGRES_PASSWORD=secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fr := testutil.NewFakeExec(rules...)
	return kdeps.Config{
		EnvFile:       envFile,
		TextfileDir:   filepath.Join(dir, "textfile"),
		GuardStateDir: filepath.Join(dir, "guard"),
		Runtime:       "podman",
		Clock:         timex.NewCell(func() time.Time { return time.Unix(TestNow, 0) }),
		Run:           fr.RunStdin,
		WireFn:        func(context.Context, string) bool { return true },
	}, fr, dir
}

// Deps wraps Config + kdeps.NewDeps — the *kdeps.Deps a domain
// worker's New consumes (metrics unregistered, the bare-construction
// contract).
func Deps(t *testing.T, cfg kdeps.Config) *kdeps.Deps {
	t.Helper()
	d, err := kdeps.NewDeps(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// ReadText reads <dir>/textfile/<name> — the textfile emission
// every domain test asserts against.
func ReadText(t *testing.T, dir, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "textfile", name))
	if err != nil {
		t.Fatalf("read textfile %s: %v", name, err)
	}
	return string(data)
}

// ShowPoolsOut is the full-success SHOW POOLS reply shared by the
// probe-OK rule set.
const ShowPoolsOut = `database|user|cl_active|cl_waiting|sv_active|sv_idle|sv_used|sv_tested|sv_login|maxwait|maxwait_us|pool_mode
postgres|postgres|4|0|3|7|0|0|0|0|0|transaction
pgbouncer|pgbouncer|1|0|0|0|0|0|0|0|0|transaction
`

// ProbeOKRules is the full-success command set. The revision query
// answers head|compact_rev|live_tup — no COUNT(*) (the row count is
// the guard's job; a per-2min seq-scan bloats what it measures).
var ProbeOKRules = []testutil.ExecRule{
	{Substr: "inspect", Out: "true"},
	{Substr: "SHOW POOLS", Out: ShowPoolsOut},
	{Substr: "logs --since", Out: "all quiet"},
	{Substr: "MAX(id)", Out: "1000|200|290|1\n"},
	{Substr: "select 1", Out: "1\n"},
}

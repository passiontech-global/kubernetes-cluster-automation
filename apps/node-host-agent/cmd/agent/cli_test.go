// cli_test.go — subcommand dispatch, arg parsing, and the usage table.

package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/ops/evpurge"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/ops/hostconverge"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/hostconfig"
)

// --- subcommand dispatch (arg-parse level) ---

func TestDispatchDaemonArgs(t *testing.T) {
	for _, argv := range [][]string{
		{"node-host-agent"},
		{"node-host-agent", "-version"},
		{"node-host-agent", "--standalone", "--node-name=x"},
	} {
		if code, handled := dispatch(argv); handled {
			t.Fatalf("dispatch(%v)=(%d,true) want (0,false)", argv, code)
		}
	}
}

func TestDispatchUnknownSubcommand(t *testing.T) {
	code, handled := dispatch([]string{"node-host-agent", "bogus"})
	if !handled || code != 2 {
		t.Fatalf("dispatch(bogus)=(%d,%v) want (2,true)", code, handled)
	}
}

// TestSubcommandUsageText pins the generated usage block to the
// pre-table text — the table IS the dispatch contract, and the
// rendered help must not drift from what operators documented.
func TestSubcommandUsageText(t *testing.T) {
	want := `usage:
  node-host-agent [daemon flags]            run the agent daemon
  node-host-agent version                   print version and exit
  node-host-agent concourse-worker-init [--work-dir=DIR] [--runc-dir=DIR] [--runc-source=PATH] [--wrapper-source=PATH]
                                            concourse worker init-rm (init container)
  node-host-agent concourse-runc-wrapper    runc shim (argv[0] "runc" works too)
  node-host-agent converge-once --vars-dir=DIR [--node-name=N] [--nebula-certs-dir=DIR]
                                            one hostconfig converge on the host, then exit
  node-host-agent nebula-sign --vars-dir=DIR --ca-dir=DIR [--node=N] [--duration=8760h] [--ssh-key=PATH]
                                            sign interdc nebula host certs with the local CA
  node-host-agent purge-events [--api=URL] [--ca=FILE] [--cert=FILE] [--key=FILE] [--workers=N] [--before=TS | RFC3339]
                                            delete apiserver events older than the cutoff (etcd backlog GC)
  node-host-agent check-kine-db [--env-file=FILE] [--wire-addr=HOST:PORT] [--runtime=podman|docker]
                                            verify the kine postgres+pgbouncer stack (exit 1 on any FAIL)
  node-host-agent check-k0s-drift [--config=FILE] [--expected-keys=a,b] [--removed-flags=x,y] [--unit-file=FILE]
                                            report k0s.yaml extraArgs drift (removed-flag/extra-key/missing-key)
  node-host-agent rescue-etcd [--k0s-dir=DIR] [--endpoint=URL] [--force-offline]
                                            rescue a k0s etcd at backend quota
                                            (compact -> online defrag -> offline defrag -> alarm disarm -> canary)
`
	if got := subcommandUsageText(); got != want {
		t.Fatalf("usage text drifted:\n--- got ---\n%s\n--- want ---\n%s",
			got, want)
	}
	// Every table entry must be dispatchable — a name typo in the
	// table would silently drop a subcommand.
	seen := map[string]bool{}
	for _, sc := range subcommands {
		seen[sc.name] = true
	}
	for _, name := range []string{
		"version", "concourse-worker-init", "concourse-runc-wrapper",
		"converge-once", "nebula-sign", "purge-events", "check-kine-db",
		"check-k0s-drift", "rescue-etcd",
	} {
		if !seen[name] {
			t.Fatalf("subcommand %q missing from dispatch table", name)
		}
	}
}

func TestDispatchRuncArgv0(t *testing.T) {
	// argv[0] "runc" selects the wrapper; runc.real does not exist in
	// the test env so exec fails → non-zero, but dispatch handled it.
	code, handled := dispatch([]string{"/concourse-runc/runc", "state"})
	if !handled {
		t.Fatal("argv0 runc was not handled")
	}
	if code == 0 {
		t.Fatal("runc wrapper returned 0 without runc.real — unexpected")
	}
}

func TestDispatchConvergeOnceArgParsing(t *testing.T) {
	// Bad flag → exit 2; -h/--help → exit 0 (flag.ErrHelp is not an
	// error — a user asking for usage must not fail CI/wrappers).
	if code, handled := dispatch([]string{"nha", "converge-once", "--bogus"}); !handled || code != 2 {
		t.Fatalf("converge-once --bogus=(%d,%v) want (2,true)", code, handled)
	}
	for _, h := range []string{"-h", "--help"} {
		if code, handled := dispatch([]string{"nha", "converge-once", h}); !handled || code != 0 {
			t.Fatalf("converge-once %s=(%d,%v) want (0,true)", h, code, handled)
		}
	}
	// A vars dir without the topology files → the cycle counts the
	// load error and the command exits 1 (converge-once reports
	// errs > 0 — same contract as nebula-sign on missing vars).
	dir := t.TempDir()
	code, handled := dispatch([]string{"nha", "converge-once",
		"--vars-dir=" + dir, "--node-name=testnode"})
	if !handled || code != 1 {
		t.Fatalf("converge-once=(%d,%v) want (1,true)", code, handled)
	}
}

// quietRunner answers every host command with empty output + nil
// error — the scriptedRunner equivalent for the converge-once clean
// path (a node absent from the registry self-gates every group).
type quietRunner struct{}

func (quietRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	return "", nil
}

func TestDispatchConvergeOnceCleanExit0(t *testing.T) {
	// Stub the host seams: a tempdir host root + a runner that never
	// fails, so a fully self-gating converge reports errs==0 and the
	// command exits 0 (the timer/CI "converged" contract).
	oldRoot, oldRunner := hostconverge.HostRoot, hostconverge.RunnerFactory
	defer func() {
		hostconverge.HostRoot, hostconverge.RunnerFactory = oldRoot, oldRunner
	}()
	hostconverge.HostRoot = t.TempDir()
	hostconverge.RunnerFactory = func() hostconfig.Runner { return quietRunner{} }

	dir := t.TempDir()
	for name, content := range map[string]string{
		"interdc_nodes.yaml": "{}\n",
		"cluster.yaml":       "{}\n",
		"defaults.yaml":      "interdc_nebula_enabled: false\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	code, handled := dispatch([]string{"nha", "converge-once",
		"--vars-dir=" + dir, "--node-name=testnode"})
	if !handled || code != 0 {
		t.Fatalf("converge-once clean=(%d,%v) want (0,true)", code, handled)
	}
}

func TestDispatchNebulaSignArgParsing(t *testing.T) {
	// --ca-dir is required.
	if code, handled := dispatch([]string{"nha", "nebula-sign"}); !handled || code != 2 {
		t.Fatalf("nebula-sign (no ca-dir)=(%d,%v) want (2,true)", code, handled)
	}
	// -h exits 0 — help is a clean exit, not a usage error.
	if code, handled := dispatch([]string{"nha", "nebula-sign", "-h"}); !handled || code != 0 {
		t.Fatalf("nebula-sign -h=(%d,%v) want (0,true)", code, handled)
	}
	// Missing vars files → error exit 1 (topology.Load fails before
	// any signing).
	dir := t.TempDir()
	code, handled := dispatch([]string{"nha", "nebula-sign",
		"--vars-dir=" + dir, "--ca-dir=" + dir})
	if !handled || code != 1 {
		t.Fatalf("nebula-sign missing vars=(%d,%v) want (1,true)", code, handled)
	}
}

func TestDispatchConcourseWorkerInitArgParsing(t *testing.T) {
	if code, handled := dispatch([]string{"nha", "concourse-worker-init", "--bogus"}); !handled || code != 2 {
		t.Fatalf("concourse-worker-init --bogus=(%d,%v) want (2,true)", code, handled)
	}
	if code, handled := dispatch([]string{"nha", "concourse-worker-init", "-h"}); !handled || code != 0 {
		t.Fatalf("concourse-worker-init -h=(%d,%v) want (0,true)", code, handled)
	}
	// --wrapper-source pointing at a missing binary fails the
	// install (copyFileAtomic errors) → exit 1, proving the flag
	// reached cfg.WrapperSource. The other flags get temp dirs and a
	// temp runc source so everything before the wrapper copy works.
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	runcDir := filepath.Join(dir, "runc")
	runcSrc := filepath.Join(dir, "runc-real")
	for _, d := range []string{work, runcDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(runcSrc, []byte("fake-runc"), 0o755); err != nil {
		t.Fatal(err)
	}
	code, handled := dispatch([]string{"nha", "concourse-worker-init",
		"--work-dir=" + work, "--runc-dir=" + runcDir,
		"--runc-source=" + runcSrc,
		"--wrapper-source=" + filepath.Join(dir, "no-such-binary")})
	if !handled || code != 1 {
		t.Fatalf("concourse-worker-init bad wrapper-source=(%d,%v) want (1,true)",
			code, handled)
	}
}

func TestDispatchPurgeEventsArgParsing(t *testing.T) {
	if code, handled := dispatch([]string{"nha", "purge-events", "--bogus"}); !handled || code != 2 {
		t.Fatalf("purge-events --bogus=(%d,%v) want (2,true)", code, handled)
	}
	if code, handled := dispatch([]string{"nha", "purge-events", "-h"}); !handled || code != 0 {
		t.Fatalf("purge-events -h=(%d,%v) want (0,true)", code, handled)
	}
	// A malformed cutoff is a usage error before any TLS/dial work.
	for _, argv := range [][]string{
		{"nha", "purge-events", "not-a-timestamp"},
		{"nha", "purge-events", "--before=not-a-timestamp"},
	} {
		if code, handled := dispatch(argv); !handled || code != 2 {
			t.Fatalf("purge-events %v=(%d,%v) want (2,true)", argv[2:], code, handled)
		}
	}
	// Missing PKI files → Run fails building the client → exit 1.
	code, handled := dispatch([]string{"nha", "purge-events",
		"--ca=/nonexistent/ca.crt", "2026-08-23T04:27:00Z"})
	if !handled || code != 1 {
		t.Fatalf("purge-events missing CA=(%d,%v) want (1,true)", code, handled)
	}
}

// The positional-cutoff scan works on a clone — the compacting
// appends must not corrupt the caller's slice (which aliases the
// os.Args backing array in production).
func TestPurgeEventsDoesNotMutateArgs(t *testing.T) {
	for _, args := range [][]string{
		// Positional first: without the clone the compaction shifts
		// the flag left over it inside the shared backing array.
		{"2026-08-23T04:27:00Z", "--ca=/nonexistent/ca.crt"},
		// The `--` branch drops the element after it in place.
		{"--", "not-a-timestamp", "--ca=/nonexistent/ca.crt"},
	} {
		want := slices.Clone(args)
		if code := evpurge.Cmd(context.Background(), args); code != 1 && code != 2 {
			t.Fatalf("purge-events %v=%d want 1 or 2", args, code)
		}
		if !slices.Equal(args, want) {
			t.Fatalf("args mutated in place: got %v want %v", args, want)
		}
	}
}

func TestDispatchCheckKineDBArgParsing(t *testing.T) {
	if code, handled := dispatch([]string{"nha", "check-kine-db", "--bogus"}); !handled || code != 2 {
		t.Fatalf("check-kine-db --bogus=(%d,%v) want (2,true)", code, handled)
	}
	if code, handled := dispatch([]string{"nha", "check-kine-db", "-h"}); !handled || code != 0 {
		t.Fatalf("check-kine-db -h=(%d,%v) want (0,true)", code, handled)
	}
}

func TestDispatchCheckK0sDriftArgParsing(t *testing.T) {
	if code, handled := dispatch([]string{"nha", "check-k0s-drift", "--bogus"}); !handled || code != 2 {
		t.Fatalf("check-k0s-drift --bogus=(%d,%v) want (2,true)", code, handled)
	}
	if code, handled := dispatch([]string{"nha", "check-k0s-drift", "-h"}); !handled || code != 0 {
		t.Fatalf("check-k0s-drift -h=(%d,%v) want (0,true)", code, handled)
	}
	// A nonexistent unit file gates the check off → clean exit 0 on
	// any host (the "not a k0s controller" skip).
	code, handled := dispatch([]string{"nha", "check-k0s-drift",
		"--unit-file=" + filepath.Join(t.TempDir(), "no-such.service")})
	if !handled || code != 0 {
		t.Fatalf("check-k0s-drift no unit=(%d,%v) want (0,true)", code, handled)
	}
	// Missing config + present unit → unreadable drift → exit 1.
	dir := t.TempDir()
	unit := filepath.Join(dir, "k0scontroller.service")
	if err := os.WriteFile(unit, []byte("[Unit]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, handled = dispatch([]string{"nha", "check-k0s-drift",
		"--unit-file=" + unit,
		"--config=" + filepath.Join(dir, "no-such.yaml")})
	if !handled || code != 1 {
		t.Fatalf("check-k0s-drift missing config=(%d,%v) want (1,true)", code, handled)
	}
}

func TestDispatchRescueEtcdArgParsing(t *testing.T) {
	if code, handled := dispatch([]string{"nha", "rescue-etcd", "--bogus"}); !handled || code != 2 {
		t.Fatalf("rescue-etcd --bogus=(%d,%v) want (2,true)", code, handled)
	}
	if code, handled := dispatch([]string{"nha", "rescue-etcd", "-h"}); !handled || code != 0 {
		t.Fatalf("rescue-etcd -h=(%d,%v) want (0,true)", code, handled)
	}
	// A missing k0s dir → the etcdctl exec fails on the very first
	// endpoint status → exit 1.
	code, handled := dispatch([]string{"nha", "rescue-etcd",
		"--k0s-dir=" + filepath.Join(t.TempDir(), "no-such")})
	if !handled || code != 1 {
		t.Fatalf("rescue-etcd missing k0s-dir=(%d,%v) want (1,true)", code, handled)
	}
}

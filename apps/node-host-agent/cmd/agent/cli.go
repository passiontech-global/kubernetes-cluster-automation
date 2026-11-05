// cli.go — multi-call subcommand dispatch. The binary is also copied
// to /concourse-runc/runc by the concourse worker init, so argv[0]
// selects the runc wrapper directly; everything else is argv[1].
// Dispatch runs BEFORE flag.Parse so daemon flags stay untouched.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/ops/concourseinit"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/ops/etcdrescue"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/ops/evpurge"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/ops/neblasign"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/subsystem/hostconfig"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/subsystem/hostmetrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/subsystem/kinedb"
)

// dispatch runs a subcommand selected by argv[0]/argv[1] and returns
// (exitCode, true) when one handled the invocation; (0, false) means
// "not a subcommand — run the daemon" (argv[1] absent or a flag).
func dispatch(argv []string) (int, bool) {
	if len(argv) == 0 {
		return 0, false
	}
	// /concourse-runc/runc is a copy of this binary exec'd by
	// containerd-shim — argv[0] selects the wrapper.
	if filepath.Base(argv[0]) == "runc" {
		return concourseinit.RuncWrapper(), true
	}
	if len(argv) < 2 || strings.HasPrefix(argv[1], "-") {
		return 0, false
	}
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	switch argv[1] {
	case "concourse-worker-init":
		return concourseWorkerInit(ctx, argv[2:]), true
	case "concourse-runc-wrapper":
		// The subcommand word is not part of the runc argv — the
		// wrapper forwards argv[1:] to runc.real.
		runcArgv := append([]string{argv[0]}, argv[2:]...)
		return concourseinit.RunRuncWrapper(runcArgv, os.Environ()), true
	case "converge-once":
		return convergeOnce(ctx, argv[2:]), true
	case "nebula-sign":
		return nebulasign.Cmd(ctx, argv[2:]), true
	case "purge-events":
		return purgeEventsCmd(ctx, argv[2:]), true
	case "check-kine-db":
		return checkKineDBCmd(ctx, argv[2:]), true
	case "check-k0s-drift":
		return checkK0sDriftCmd(ctx, argv[2:]), true
	case "rescue-etcd":
		return rescueEtcdCmd(ctx, argv[2:]), true
	case "version":
		// Positional twin of --version — a bare `version` word
		// should not fall through to "unknown subcommand".
		fmt.Println(version)
		return 0, true
	default:
		subcommandUsage(argv[1])
		return 2, true
	}
}

// subcommandUsage prints the dispatch table for an unknown word.
func subcommandUsage(word string) {
	fmt.Fprintf(os.Stderr, `unknown subcommand %q

usage:
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
`, word)
}

// concourseWorkerInit is the init-rm subcommand: the flags map onto
// concourseinit.Config's path knobs so the container invocation can
// point at its mounts (`--wrapper-source=/usr/local/bin/node-host-agent`
// self-installs the agent as the runc wrapper even when argv[0]
// resolves elsewhere).
func concourseWorkerInit(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("concourse-worker-init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workDir := fs.String("work-dir", "",
		"concourse work dir to soft-reset (default "+concourseinit.DefaultWorkDir+")")
	runcDir := fs.String("runc-dir", "",
		"emptyDir shared with the worker holding runc + runc.real (default "+
			concourseinit.DefaultRuncDir+")")
	runcSource := fs.String("runc-source", "",
		"the image's real runc, copied to <runc-dir>/runc.real (default "+
			concourseinit.DefaultRuncSource+")")
	wrapperSource := fs.String("wrapper-source", "",
		"binary installed as <runc-dir>/runc — the multi-call agent "+
			"(default: os.Executable)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0 // -h/--help is a clean exit, not a usage error
		}
		return 2
	}
	if err := concourseinit.WorkerInit(ctx, concourseinit.Config{
		WorkDir:       *workDir,
		RuncDir:       *runcDir,
		RuncSource:    *runcSource,
		WrapperSource: *wrapperSource,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "concourse-worker-init:", err)
		return 1
	}
	return 0
}

// convergeHostRoot/convergeRunner wire the production standalone
// contract ("/" + DirectRunner) — tests stub both to run a scripted
// converge against a tempdir host root instead of exec'ing real
// host commands.
var (
	convergeHostRoot = "/"
	convergeRunner   = func() hostconfig.Runner { return hostconfig.DirectRunner{} }
)

// convergeOnce runs exactly one hostconfig cycle on the host — the
// systemd timer / manual "converge now" entrypoint for standalone
// targets (DirectRunner: already inside the host namespaces).
func convergeOnce(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("converge-once", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	varsDir := fs.String("vars-dir",
		getenv("NODE_HOST_AGENT_HOSTCONFIG_VARS_DIR", "/etc/node-host-agent/vars"),
		"vars dir holding defaults.yaml/cluster.yaml/interdc_nodes.yaml")
	nodeName := fs.String("node-name",
		getenv("NODE_HOST_AGENT_NODE_NAME", getenv("NODE_NAME", "")),
		"registry node name (default: OS hostname)")
	certsDir := fs.String("nebula-certs-dir",
		getenv("NODE_HOST_AGENT_NEBULA_CERTS_DIR", "/etc/node-host-agent/nebula-certs"),
		"nebula cert dir (hubsync pushes to /etc/node-host-agent/nebula-certs)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0 // -h/--help is a clean exit, not a usage error
		}
		return 2
	}

	hostname, _ := os.Hostname()
	nn := *nodeName
	if nn == "" {
		nn = hostname
	}
	hc, err := hostconfig.New(hostconfig.Config{
		Enabled:        true,
		NodeName:       nn,
		Hostname:       hostname,
		HostRoot:       convergeHostRoot,
		VarsDir:        *varsDir,
		NebulaCertsDir: *certsDir,
		Runner:         convergeRunner(),
	}, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "converge-once:", err)
		return 1
	}
	logger().Info("converge-once starting",
		"node", nn, "varsDir", *varsDir, "certsDir", *certsDir)
	// CycleWithErrors counts topology/vars failures, group
	// write/command errors and panics — a non-zero count means the
	// converge did not fully apply, so the timer/CI caller gets a
	// non-zero exit (ansible failed_when parity).
	if errs := hc.CycleWithErrors(ctx); errs > 0 {
		logger().Error("converge-once finished with errors",
			"node", nn, "errors", errs)
		return 1
	}
	return 0
}

// --- purge-events: port of scripts/purge-events.py ---
//
// Bulk-deletes apiserver Events older than a cutoff through the
// k0s admin client certs — run as root ON a controller node. The
// cutoff is a flag (--before) or a bare positional RFC3339 arg, like
// the script's sys.argv[1]; the empty default is the script's
// "1970-01-01T00:00:00Z" (delete everything).
func purgeEventsCmd(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("purge-events", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	api := fs.String("api", "https://127.0.0.1:6443", "apiserver base URL")
	ca := fs.String("ca", "",
		"CA bundle (default /var/lib/k0s/pki/ca.crt, fallback /var/lib/k0s/pki/etcd/ca.crt)")
	cert := fs.String("cert", "/var/lib/k0s/pki/admin.crt", "client certificate")
	key := fs.String("key", "/var/lib/k0s/pki/admin.key", "client key")
	workers := fs.Int("workers", 8,
		"parallel DELETE workers (drop to 2 on a weak cluster)")
	before := fs.String("before", "",
		"delete events created before this RFC3339 timestamp "+
			"(positional arg also accepted; default deletes everything)")
	// flag stops parsing at the first positional, so
	// `purge-events <ts> --workers=2` would silently drop --workers —
	// pull the positional cutoff out first, then parse what remains.
	// Value-taking flags in `--flag value` form skip their value so
	// it is not mistaken for the cutoff.
	valueFlags := map[string]bool{
		"api": true, "ca": true, "cert": true,
		"key": true, "workers": true, "before": true,
	}
	// Work on a clone: args aliases the os.Args backing array and the
	// in-place compaction below (`append(args[:i], args[i+1:]...)`)
	// would corrupt argv for anything that reads it afterwards.
	args = slices.Clone(args)
	var positional string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			if i+1 < len(args) {
				positional = args[i+1]
				args = append(args[:i+1], args[i+2:]...)
			}
			break
		}
		if !strings.HasPrefix(a, "-") {
			positional = a
			args = append(args[:i], args[i+1:]...)
			break
		}
		if name := strings.TrimLeft(a, "-"); !strings.Contains(name, "=") &&
			valueFlags[name] {
			i++
		}
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0 // -h/--help is a clean exit, not a usage error
		}
		return 2
	}
	cutStr := *before
	if cutStr == "" && positional != "" {
		cutStr = positional
	}
	if cutStr == "" && fs.NArg() > 0 {
		cutStr = fs.Arg(0)
	}
	if cutStr == "" {
		cutStr = "1970-01-01T00:00:00Z"
	}
	cutoff, err := time.Parse(time.RFC3339, cutStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "purge-events: bad cutoff %q: %v\n", cutStr, err)
		return 2
	}
	if err := evpurge.Run(ctx, evpurge.Config{
		API:      *api,
		CAFile:   *ca,
		CertFile: *cert,
		KeyFile:  *key,
		Workers:  *workers,
	}, cutoff, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "purge-events:", err)
		return 1
	}
	return 0
}

// --- check-kine-db: port of scripts/check-kine-db.sh ---
//
// The operator-side verify after a postgres+pgbouncer stack update
// on the kine DB VM. Prints the script's OK/FAIL check lines and
// exits 1 on any failure.
func checkKineDBCmd(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("check-kine-db", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	envFile := fs.String("env-file", "/opt/apps/postgres/.env",
		"postgres stack .env (POSTGRES_USER/POSTGRES_PASSWORD)")
	wireAddr := fs.String("wire-addr", "127.0.0.1:6432",
		"pgbouncer host:port for the wire probe")
	runtime := fs.String("runtime", "",
		"container runtime podman|docker (default: auto-detect)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0 // -h/--help is a clean exit, not a usage error
		}
		return 2
	}
	return kinedb.RunCheckCLI(ctx, kinedb.Config{
		EnvFile:  *envFile,
		WireAddr: *wireAddr,
		Runtime:  *runtime,
	}, os.Stdout)
}

// --- check-k0s-drift: on-node half of scripts/check-node-config-drift.sh ---
//
// Reports removed-flag / extra-key / missing-key drift between the
// node's /etc/k0s/k0s.yaml controllerManager.extraArgs and the
// expected set. Exit 0 clean (or not a k0s controller), 1 on drift.
func checkK0sDriftCmd(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("check-k0s-drift", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	config := fs.String("config", "/etc/k0s/k0s.yaml", "k0s config to scan")
	expected := fs.String("expected-keys", "",
		"comma-separated expected controllerManager.extraArgs keys "+
			"(default: the repo-pinned set)")
	removed := fs.String("removed-flags", "",
		"comma-separated config keys removed upstream "+
			"(default: concurrent-service-syncs)")
	unit := fs.String("unit-file", "/etc/systemd/system/k0scontroller.service",
		"k0s controller gate — the check only runs when this unit file "+
			"exists (point at /dev/null to force on a non-controller)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0 // -h/--help is a clean exit, not a usage error
		}
		return 2
	}
	// Provided-vs-absent matters: --expected-keys= (explicit empty)
	// means "no expected keys" while a missing flag means "use the
	// repo-pinned default" — see K0sDriftConfig.
	provided := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { provided[f.Name] = true })
	var exp, rem []string
	if provided["expected-keys"] {
		exp = splitCSV(*expected)
	}
	if provided["removed-flags"] {
		rem = splitCSV(*removed)
	}
	// The scan itself is a fast file read — honoring the signal ctx
	// is an upfront cancellation gate.
	if err := ctx.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "check-k0s-drift:", err)
		return 1
	}
	return hostmetrics.RunK0sDriftCLI(hostmetrics.K0sDriftConfig{
		ConfigFile:   *config,
		UnitFile:     *unit,
		ExpectedKeys: exp,
		RemovedFlags: rem,
	}, os.Stdout)
}

// --- rescue-etcd: port of scripts/rescue-etcd.sh ---
//
// Rescues a k0s controller etcd that hit the backend quota — run as
// root ON the controller. Compact -> online defrag -> offline defrag
// when the online pass reclaims nothing (or --force-offline) ->
// alarm disarm -> write canary.
func rescueEtcdCmd(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("rescue-etcd", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	k0sDir := fs.String("k0s-dir", "/var/lib/k0s",
		"k0s data dir (derives bin/etcd*, pki/ cert paths)")
	endpoint := fs.String("endpoint", "https://127.0.0.1:2379",
		"etcd client endpoint")
	forceOffline := fs.Bool("force-offline", false,
		"skip the online defrag attempt, go straight to offline defrag")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0 // -h/--help is a clean exit, not a usage error
		}
		return 2
	}
	if err := etcdrescue.Run(ctx, etcdrescue.Config{
		K0sDir:       *k0sDir,
		Endpoint:     *endpoint,
		ForceOffline: *forceOffline,
	}, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "rescue-etcd:", err)
		return 1
	}
	return 0
}

// splitCSV splits a comma-separated flag value, trimming spaces and
// dropping empty elements. Empty input yields an empty NON-nil
// slice — callers distinguish "flag absent" (nil -> defaults) from
// "flag provided empty" (empty set honored).
func splitCSV(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

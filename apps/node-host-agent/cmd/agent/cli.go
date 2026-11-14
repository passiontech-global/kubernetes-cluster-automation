// cli.go — multi-call subcommand dispatch. The binary is also copied
// to /concourse-runc/runc by the concourse worker init, so argv[0]
// selects the runc wrapper directly; everything else is argv[1].
// Dispatch runs BEFORE flag.Parse so daemon flags stay untouched.
//
// The subcommands table IS the usage text — subcommandUsage renders
// it, so the help can never drift from what dispatch accepts. Every
// subcommand's flag parsing and run logic lives in its owning
// internal/ops package (nebulasign.Cmd is the precedent —
// Cmd(ctx, args) int).
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/ops/concourseinit"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/ops/etcdrescue"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/ops/evpurge"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/ops/hostconverge"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/ops/k0sdrift"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/ops/kinecheckdb"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/ops/nebulasign"
)

// usageDescCol is the column descriptions start at in the usage
// text — long flag lists wrap onto the next line at this indent.
const usageDescCol = 44

var usageIndent = strings.Repeat(" ", usageDescCol)

// subcommand is one row of the dispatch table: the argv[1] word, the
// usage text (flags + description column), and the runner. run gets
// the signal context and the invocation argv MINUS the subcommand
// word — argv[0] is kept because concourse-runc-wrapper forwards the
// rebuilt argv to runc.real.
type subcommand struct {
	name  string
	flags string // what follows the name in usage ("" = none)
	desc  string // description column ("\n" continues on the next line)
	run   func(ctx context.Context, argv []string) int
}

var subcommands = []subcommand{
	{
		name: "version",
		desc: "print version and exit",
		// Positional twin of --version — a bare `version` word
		// should not fall through to "unknown subcommand".
		run: func(context.Context, []string) int {
			fmt.Println(version)
			return 0
		},
	},
	{
		name:  "concourse-worker-init",
		flags: "[--work-dir=DIR] [--runc-dir=DIR] [--runc-source=PATH] [--wrapper-source=PATH]",
		desc:  "concourse worker init-rm (init container)",
		run: func(ctx context.Context, argv []string) int {
			return concourseinit.Cmd(ctx, argv[1:])
		},
	},
	{
		name: "concourse-runc-wrapper",
		desc: `runc shim (argv[0] "runc" works too)`,
		// The subcommand word is already stripped from argv — the
		// wrapper forwards it to runc.real.
		run: func(_ context.Context, argv []string) int {
			return concourseinit.RunRuncWrapper(argv, os.Environ())
		},
	},
	{
		name:  "converge-once",
		flags: "--vars-dir=DIR [--node-name=N] [--nebula-certs-dir=DIR]",
		desc:  "one hostconfig converge on the host, then exit",
		run: func(ctx context.Context, argv []string) int {
			return hostconverge.Cmd(ctx, argv[1:])
		},
	},
	{
		name:  "nebula-sign",
		flags: "--vars-dir=DIR --ca-dir=DIR [--node=N] [--duration=8760h] [--ssh-key=PATH]",
		desc:  "sign interdc nebula host certs with the local CA",
		run: func(ctx context.Context, argv []string) int {
			return nebulasign.Cmd(ctx, argv[1:])
		},
	},
	{
		name:  "purge-events",
		flags: "[--api=URL] [--ca=FILE] [--cert=FILE] [--key=FILE] [--workers=N] [--before=TS | RFC3339]",
		desc:  "delete apiserver events older than the cutoff (etcd backlog GC)",
		run: func(ctx context.Context, argv []string) int {
			return evpurge.Cmd(ctx, argv[1:])
		},
	},
	{
		name:  "check-kine-db",
		flags: "[--env-file=FILE] [--wire-addr=HOST:PORT] [--runtime=podman|docker]",
		desc:  "verify the kine postgres+pgbouncer stack (exit 1 on any FAIL)",
		run: func(ctx context.Context, argv []string) int {
			return kinecheckdb.Cmd(ctx, argv[1:])
		},
	},
	{
		name:  "check-k0s-drift",
		flags: "[--config=FILE] [--expected-keys=a,b] [--removed-flags=x,y] [--unit-file=FILE]",
		desc:  "report k0s.yaml extraArgs drift (removed-flag/extra-key/missing-key)",
		run: func(ctx context.Context, argv []string) int {
			return k0sdrift.Cmd(ctx, argv[1:])
		},
	},
	{
		name:  "rescue-etcd",
		flags: "[--k0s-dir=DIR] [--endpoint=URL] [--force-offline]",
		desc: "rescue a k0s etcd at backend quota\n" + usageIndent +
			"(compact -> online defrag -> offline defrag -> alarm disarm -> canary)",
		run: func(ctx context.Context, argv []string) int {
			return etcdrescue.Cmd(ctx, argv[1:])
		},
	},
}

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
		return concourseinit.RunRuncWrapper(argv, os.Environ()), true
	}
	if len(argv) < 2 || strings.HasPrefix(argv[1], "-") {
		return 0, false
	}
	for _, sc := range subcommands {
		if sc.name != argv[1] {
			continue
		}
		ctx, stop := signalContext()
		defer stop()
		// The subcommand word is not part of the runner's argv —
		// rebuild argv without it so argv[0] still leads.
		return sc.run(ctx, append([]string{argv[0]}, argv[2:]...)), true
	}
	subcommandUsage(argv[1])
	return 2, true
}

// subcommandUsage prints the dispatch table for an unknown word.
func subcommandUsage(word string) {
	fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n%s",
		word, subcommandUsageText())
}

// subcommandUsageText renders the usage block from the dispatch
// table itself — the help can never drift from what dispatch
// accepts.
func subcommandUsageText() string {
	var b strings.Builder
	b.WriteString("usage:\n")
	// The daemon itself is not a subcommand, but the usage block
	// leads with it.
	b.WriteString(usageLine("[daemon flags]", "", "run the agent daemon"))
	for _, sc := range subcommands {
		b.WriteString(usageLine(sc.name, sc.flags, sc.desc))
	}
	return b.String()
}

// usageLine renders one "  node-host-agent <name> <flags>" row: the
// description joins the same line when it fits before usageDescCol,
// otherwise it wraps to the next line at that indent.
func usageLine(name, flags, desc string) string {
	line := "  node-host-agent " + name
	if flags != "" {
		line += " " + flags
	}
	if len(line) >= usageDescCol {
		return line + "\n" + usageIndent + desc + "\n"
	}
	return line + strings.Repeat(" ", usageDescCol-len(line)) + desc + "\n"
}

// cli.go — multi-call subcommand dispatch. The binary is also copied
// to /concourse-runc/runc by the concourse worker init, so argv[0]
// selects the runc wrapper directly; everything else is argv[1].
// Dispatch runs BEFORE flag.Parse so daemon flags stay untouched.
//
// This file is a pure dispatch table: every subcommand's flag
// parsing and run logic lives in its owning internal/ops package
// (neblasign.Cmd is the precedent — Cmd(ctx, args) int).
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/ops/concourseinit"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/ops/etcdrescue"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/ops/evpurge"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/ops/hostconverge"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/ops/k0sdrift"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/ops/kinecheckdb"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/ops/neblasign"
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
		return concourseinit.Cmd(ctx, argv[2:]), true
	case "concourse-runc-wrapper":
		// The subcommand word is not part of the runc argv — the
		// wrapper forwards argv[1:] to runc.real.
		runcArgv := append([]string{argv[0]}, argv[2:]...)
		return concourseinit.RunRuncWrapper(runcArgv, os.Environ()), true
	case "converge-once":
		return hostconverge.Cmd(ctx, argv[2:]), true
	case "nebula-sign":
		return nebulasign.Cmd(ctx, argv[2:]), true
	case "purge-events":
		return evpurge.Cmd(ctx, argv[2:]), true
	case "check-kine-db":
		return kinecheckdb.Cmd(ctx, argv[2:]), true
	case "check-k0s-drift":
		return k0sdrift.Cmd(ctx, argv[2:]), true
	case "rescue-etcd":
		return etcdrescue.Cmd(ctx, argv[2:]), true
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

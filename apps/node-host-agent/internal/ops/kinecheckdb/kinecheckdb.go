// Package kinecheckdb owns the `check-kine-db` subcommand's flag
// layer — the operator-side post-update verify after a
// postgres+pgbouncer stack update on the kine DB VM (port of
// scripts/check-kine-db.sh).
//
// The check itself lives in internal/subsystem/kinedb
// (RunCheckCLI): it runs the seven probe checks and prints the
// script's OK/FAIL lines, exiting 1 on any failure. It exists to
// catch the 2026-09-25 failure mode: POSTGRES_* credentials rotated
// in .env but the old volume skips initdb → backend role keeps the
// old password → pgbouncer auth fails → kine dies while TCP :6432
// still accepts connections.
//
// cmd/agent wires this as the `check-kine-db` subcommand via Cmd.
package kinecheckdb

import (
	"context"
	"errors"
	"flag"
	"os"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/subsystem/kinedb"
)

// Cmd is the `check-kine-db` subcommand entrypoint: flag parsing +
// dispatch, returning the process exit code (0 clean, 1 check
// failure, 2 usage error — same contract as the other ops
// subcommands).
func Cmd(ctx context.Context, args []string) int {
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

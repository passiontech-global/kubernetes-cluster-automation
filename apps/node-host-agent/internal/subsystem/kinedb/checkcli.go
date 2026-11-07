// checkcli.go — `node-host-agent check-kine-db`: the operator-side
// post-update verify, port of scripts/check-kine-db.sh. The bash ran
// over SSH right after `docker compose up -d` on the DB VM; the Go
// port runs the same seven probe checks (the periodic kine-db-probe
// already owns them) and prints the script's OK/FAIL lines verbatim.
//
// It exists to catch the 2026-09-25 failure mode: POSTGRES_*
// credentials rotated in .env but the old volume skips initdb →
// backend role keeps the old password → pgbouncer auth fails → kine
// dies while TCP :6432 still accepts connections.
package kinedb

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/probe"
)

// RunCheckCLI runs the seven probe checks once — containers, wire,
// e2e_auth, backend_env, log_errors, pools, revision_horizon — and
// prints one "  OK   <name>" / "  FAIL <name>" line per check in the
// bash script's format, then the ALL OK / CO CHECK FAIL verdict.
// Returns the process exit code: 0 when every check succeeded, else 1.
// The CLI is strictly read-only: Config.ReadOnly is forced so it
// prints diagnostics without touching the daemon's state files, the
// kine-db-xact.prom textfile, sessions, DDL, or containers (the
// pre-fix CLI ran the live remediation path — it could zero the
// xact textfile, consume the last-seq-tup-read delta, terminate
// sessions, VACUUM, roll back prepared xacts and restart pgbouncer).
func RunCheckCLI(ctx context.Context, cfg Config, out io.Writer) int {
	cfg.ReadOnly = true
	k, err := New(cfg, nil)
	if err != nil {
		_, _ = fmt.Fprintln(out, "check-kine-db: init:", err)
		return 1
	}
	host, _ := os.Hostname()
	_, _ = fmt.Fprintf(out, "== kine DB probe on %s (runtime=%s) ==\n",
		host, k.Cfg.Runtime)

	res := k.probe.RunChecks(ctx)

	fail := 0
	check := func(name string, ok bool) {
		if ok {
			_, _ = fmt.Fprintf(out, "  OK   %s\n", name)
			return
		}
		_, _ = fmt.Fprintf(out, "  FAIL %s\n", name)
		fail++
	}
	check(fmt.Sprintf("containers %s + %s running",
		res.PGName, res.PGBName), res.Checks[probe.CheckContainers] == 1)
	check(fmt.Sprintf("pgbouncer %s wire probe (startup -> auth request)",
		k.Cfg.WireAddr), res.Checks[probe.CheckWire] == 1)
	check("e2e auth via pooler (kine path: client->pooler->backend)",
		res.Checks[probe.CheckE2EAuth] == 1)
	check(fmt.Sprintf("backend auth: POSTGRES_USER=%s postgres login works",
		res.EnvUser), res.Checks[probe.CheckBackendEnv] == 1)
	check(fmt.Sprintf("pgbouncer log clean (server_login_retry/auth fail = %d)",
		res.LogErrs), res.Checks[probe.CheckLogErrors] == 1)
	check(fmt.Sprintf("SHOW POOLS: db postgres has server conn (sv_*>0) and cl_waiting<=%d",
		k.Cfg.WaitMax), res.Checks[probe.CheckPools] == 1)
	check(fmt.Sprintf("revision horizon (head=%s compact_rev=%s live_tup=%s)",
		kdeps.IntOrNA(res.RevSeen, res.Head),
		kdeps.IntOrNA(res.RevSeen, res.Compact),
		kdeps.IntOrNA(res.RevSeen, res.LiveTup)),
		res.Checks[probe.CheckRevision] == 1)

	_, _ = fmt.Fprintln(out)
	if fail == 0 {
		_, _ = fmt.Fprintln(out,
			"ALL OK — update is safe. Still verify the api: kubectl get nodes")
		return 0
	}
	_, _ = fmt.Fprintln(out, "CHECKS FAILED — do NOT treat the update as done.")
	_, _ = fmt.Fprintln(out,
		"If backend_auth fails: .env rotated but old DB roles remain -> fix:")
	_, _ = fmt.Fprintf(out,
		"  %s exec %s psql -U postgres -d postgres \\\n"+
			"    -c \"ALTER ROLE <user> WITH PASSWORD '<NEW_POSTGRES_PASSWORD>'\"\n",
		k.Cfg.Runtime, res.PGName)
	return 1
}

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
)

// RunCheckCLI runs the seven probe checks once — containers, wire,
// e2e_auth, backend_env, log_errors, pools, revision_horizon — and
// prints one "  OK   <name>" / "  FAIL <name>" line per check in the
// bash script's format, then the ALL OK / CO CHECK FAIL verdict.
// Returns the process exit code: 0 when every check succeeded, else 1.
// Note: pgHygiene writes the kine-db-xact.prom textfile on every run
// (shared with the periodic path — no separate CLI-only emit path).
func RunCheckCLI(ctx context.Context, cfg Config, out io.Writer) int {
	k, err := New(cfg, nil)
	if err != nil {
		_, _ = fmt.Fprintln(out, "check-kine-db: init:", err)
		return 1
	}
	host, _ := os.Hostname()
	_, _ = fmt.Fprintf(out, "== kine DB probe on %s (runtime=%s) ==\n",
		host, k.cfg.Runtime)

	res := k.runProbeChecks(ctx)

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
		res.pgName, res.pgbName), res.checks[checkContainers] == 1)
	check(fmt.Sprintf("pgbouncer %s wire probe (startup -> auth request)",
		k.cfg.WireAddr), res.checks[checkWire] == 1)
	check("e2e auth via pooler (kine path: client->pooler->backend)",
		res.checks[checkE2EAuth] == 1)
	check(fmt.Sprintf("backend auth: POSTGRES_USER=%s postgres login works",
		res.envUser), res.checks[checkBackendEnv] == 1)
	check(fmt.Sprintf("pgbouncer log clean (server_login_retry/auth fail = %d)",
		res.logErrs), res.checks[checkLogErrors] == 1)
	check(fmt.Sprintf("SHOW POOLS: db postgres has server conn (sv_*>0) and cl_waiting<=%d",
		k.cfg.WaitMax), res.checks[checkPools] == 1)
	check(fmt.Sprintf("revision horizon (head=%s compact_rev=%s live_tup=%s)",
		intOrNA(res.revSeen, res.head),
		intOrNA(res.revSeen, res.compact),
		intOrNA(res.revSeen, res.liveTup)),
		res.checks[checkRevision] == 1)

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
		k.cfg.Runtime, res.pgName)
	return 1
}

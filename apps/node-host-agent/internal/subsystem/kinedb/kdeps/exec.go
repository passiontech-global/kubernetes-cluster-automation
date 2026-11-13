// exec.go — the runtime plumbing every domain loop shares: exec
// budgets, container discovery, the stack-.env credential read, the
// psql-in-container helpers and the textfile emitter. Was run.go's
// shared-helper half; the methods hang off *Deps so probe, compact
// and maint all reach them without importing each other.
package kdeps

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
)

// Exec runs argv under the short command budget.
func (d *Deps) Exec(ctx context.Context, argv []string, stdin string) (string, error) {
	return d.ExecEnv(ctx, nil, argv, stdin)
}

// ExecLong runs argv under the long maintenance budget — compact
// sessions, VACUUM/REINDEX, pg_repack, the container→host cp of a
// fresh backup dump.
func (d *Deps) ExecLong(ctx context.Context, argv []string, stdin string) (string, error) {
	return d.ExecLongEnv(ctx, nil, argv, stdin)
}

// ExecEnv is Exec with extra child environment — the only channel a
// secret may take: it rides the child's env, never argv.
func (d *Deps) ExecEnv(ctx context.Context, env, argv []string, stdin string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, d.Cfg.CmdTimeout)
	defer cancel()
	return d.Cfg.Run(cctx, env, argv, stdin)
}

// ExecCombined runs argv under the short command budget with the
// child's stderr folded into the returned output — the `2>&1` the
// pgbouncer `logs` scan needs (its log lines stream on stderr,
// which Exec deliberately excludes). argv reaches the child
// verbatim: no sh -c, so no quoting layer can mangle a configured
// runtime/container name.
func (d *Deps) ExecCombined(ctx context.Context, argv []string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, d.Cfg.CmdTimeout)
	defer cancel()
	return d.Cfg.RunCombined(cctx, nil, argv, "")
}

// ExecLongEnv runs argv under the maintenance budget with extra
// child environment (see ExecEnv — the only channel a secret may
// take).
func (d *Deps) ExecLongEnv(ctx context.Context, env, argv []string, stdin string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, d.Cfg.LongCmdTimeout)
	defer cancel()
	return d.Cfg.Run(cctx, env, argv, stdin)
}

// DiscoverContainer returns preferred when it exists, else the first
// running container matching match (and not exclude) — the bash
// rename-resilience for stack redeploys.
func (d *Deps) DiscoverContainer(ctx context.Context, preferred string, match, exclude *regexp.Regexp) string {
	if _, err := d.Exec(ctx, []string{d.Cfg.Runtime, "inspect", preferred}, ""); err == nil {
		return preferred
	}
	out, err := d.Exec(ctx, []string{d.Cfg.Runtime, "ps", "--format", "{{.Names}}"}, "")
	if err != nil {
		return preferred
	}
	for n := range strings.SplitSeq(out, "\n") {
		n = strings.TrimSpace(n)
		if n == "" || !match.MatchString(n) {
			continue
		}
		if exclude != nil && exclude.MatchString(n) {
			continue
		}
		return n
	}
	return preferred
}

// PGContainerName resolves the postgres container — configured name
// first, then the percona|postgres auto-discovery.
func (d *Deps) PGContainerName(ctx context.Context) string {
	return d.DiscoverContainer(ctx, d.Cfg.PGContainer, rePGName, rePGExclude)
}

// PGBContainerName resolves the pgbouncer container — configured
// name first, then the pgbouncer|pgb auto-discovery.
func (d *Deps) PGBContainerName(ctx context.Context) string {
	return d.DiscoverContainer(ctx, d.Cfg.PGBouncerContainer, rePGBName, nil)
}

// ContainerRunning reports whether `Runtime inspect -f
// {{.State.Running}}` answers true for name.
func (d *Deps) ContainerRunning(ctx context.Context, name string) bool {
	out, err := d.Exec(ctx, []string{d.Cfg.Runtime, "inspect", "-f", "{{.State.Running}}", name}, "")
	return err == nil && strings.Contains(out, "true")
}

// ContainersRunning is ContainerRunning's batched sibling — ONE
// `Runtime inspect -f {{.State.Running}}` exec answers every name
// (docker/podman apply the template per object, one result per
// line, in argv order). The probe cycle asks about pg AND pgb
// every round; two inspect forks became one buffered pass. A
// failed exec — including one bad name failing the whole inspect,
// exactly like the per-name calls' AND verdict — answers false
// for every slot; a short line count falses only the missing tail.
func (d *Deps) ContainersRunning(ctx context.Context, names ...string) []bool {
	out := make([]bool, len(names))
	if len(names) == 0 {
		return out
	}
	argv := append([]string{d.Cfg.Runtime, "inspect", "-f", "{{.State.Running}}"}, names...)
	s, err := d.Exec(ctx, argv, "")
	if err != nil {
		return out
	}
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := range out {
		if i < len(lines) && strings.Contains(lines[i], "true") {
			out[i] = true
		}
	}
	return out
}

// Creds re-reads the stack .env every cycle — the backend_env check
// exists to catch credential drift, so caching would hide it.
func (d *Deps) Creds() (user, pass string, ok bool) {
	data, err := os.ReadFile(d.Cfg.EnvFile)
	if err != nil {
		return "", "", false
	}
	user = EnvValue(string(data), "POSTGRES_USER")
	pass = EnvValue(string(data), "POSTGRES_PASSWORD")
	return user, pass, user != "" && pass != ""
}

// PsqlArgs builds `RT exec [-i] -e PGPASSWORD <pg> psql -h 127.0.0.1
// -U <user> -d postgres <extra...>` — every backend query goes through
// the container like the bash originals. The password is NOT on argv:
// `-e PGPASSWORD` forwards the var from the docker/podman client's
// own environment (PsqlPassEnv on the child), keeping it off
// /proc/<pid>/cmdline where any host process could read it.
func (d *Deps) PsqlArgs(pg, user string, interactive bool, extra ...string) []string {
	return d.psqlExecArgs(pg, user, interactive,
		[]string{"PGPASSWORD", "PGAPPNAME"}, extra...)
}

// PsqlMaintArgs is PsqlArgs plus the `-e PGOPTIONS` forward —
// REQUIRED pairing with PsqlMaintEnv: `docker exec -e VAR` (no
// value) injects VAR from the docker client's own environment into
// the container, but ONLY for names listed on argv. PGOPTIONS set
// in PsqlMaintEnv reaches the docker exec process yet would never
// reach psql/libpq inside the container without this flag — the
// server-side statement/lock timeouts would silently never apply.
func (d *Deps) PsqlMaintArgs(pg, user string, interactive bool, extra ...string) []string {
	return d.psqlExecArgs(pg, user, interactive,
		[]string{"PGPASSWORD", "PGAPPNAME", "PGOPTIONS"}, extra...)
}

func (d *Deps) psqlExecArgs(pg, user string, interactive bool,
	envForward []string, extra ...string) []string {
	argv := []string{d.Cfg.Runtime, "exec"}
	if interactive {
		argv = append(argv, "-i")
	}
	for _, v := range envForward {
		argv = append(argv, "-e", v)
	}
	argv = append(argv, pg,
		"psql", "-h", "127.0.0.1", "-U", user, "-d", "postgres")
	return append(argv, extra...)
}

// PGAPPNAME is the application_name every maint/compact-side psql
// session presents in pg_stat_activity — the marker the probe's
// stuck-session reaper exempts (stuckSessionPredicate's
// application_name NOT IN ('pg_repack', 'pg_dump',
// 'node_host_agent_maint')). Without it our own psql children show
// up as application_name='psql' and the reaper would terminate the
// very maintenance/remediation sessions it shares the DB with.
const PGAPPNAME = "node_host_agent_maint"

// PsqlPassEnv is the env half of the password hand-off — paired with
// the bare `-e PGPASSWORD` in PsqlArgs/the exec call sites. It also
// pins PGAPPNAME (see PGAPPNAME): the env is the only channel a
// dynamic value may take, and the application_name marker must ride
// every session built from this helper.
func PsqlPassEnv(pass string) []string {
	return []string{"PGPASSWORD=" + pass, "PGAPPNAME=" + PGAPPNAME}
}

const (
	// maintStmtTimeoutMargin keeps the server-side statement bound
	// just under the client kill so postgres aborts a wedged
	// statement with a clean error (and releases its locks) BEFORE
	// ExecLongEnv's context deadline SIGKILLs the docker exec and
	// orphans the backend.
	maintStmtTimeoutMargin = time.Minute
	// maintLockTimeout bounds any single lock wait inside a
	// maintenance session — a wedged lock must fail fast and retry
	// next cycle, not burn the whole long budget.
	maintLockTimeout = 2 * time.Minute
	// maintMinStatementTimeout floors the derived statement bound so
	// a tiny configured LongCmdTimeout cannot produce a nonsense
	// (or negative) PGOPTIONS value.
	maintMinStatementTimeout = 30 * time.Second
)

// maintPGOptions renders the PGOPTIONS value every long-budget
// maintenance psql session carries. Derived from LongCmdTimeout so
// the server bound always lands inside the client budget.
func (d *Deps) maintPGOptions() string {
	stmt := d.Cfg.LongCmdTimeout - maintStmtTimeoutMargin
	if stmt < maintMinStatementTimeout {
		stmt = maintMinStatementTimeout
	}
	lock := maintLockTimeout
	if lock > stmt {
		lock = stmt
	}
	return fmt.Sprintf("-c statement_timeout=%d -c lock_timeout=%d",
		stmt.Milliseconds(), lock.Milliseconds())
}

// PsqlMaintEnv is PsqlPassEnv plus the PGOPTIONS maintenance psql
// sessions carry (statement/lock timeouts — the kinedb statement-
// timeout hardening). Restricted to psql: pg_dump is also a libpq
// client but its per-table COPY streams must not inherit a
// statement cap, so backup.go keeps PsqlPassEnv.
func (d *Deps) PsqlMaintEnv(pass string) []string {
	return append(PsqlPassEnv(pass), "PGOPTIONS="+d.maintPGOptions())
}

// PsqlQuery runs one statement with -tAc (unaligned, tuples only).
func (d *Deps) PsqlQuery(ctx context.Context, pg, user, pass, sql string) (string, error) {
	return d.ExecEnv(ctx, PsqlPassEnv(pass), d.PsqlArgs(pg, user, false, "-tAc", sql), "")
}

// PsqlScript runs a multi-statement script in ONE psql session via
// stdin — required for the session-scoped advisory lock to cover the
// chunk loop + vacuum. Every caller is maintenance-class work
// (compact guard, heavy reindex/freeze, lock probes, dead-tuple
// vacuum), so the session carries the PGOPTIONS timeouts.
func (d *Deps) PsqlScript(ctx context.Context, pg, user, pass, script string) (string, error) {
	return d.ExecLongEnv(ctx, d.PsqlMaintEnv(pass), d.PsqlMaintArgs(pg, user, true,
		"-v", "ON_ERROR_STOP=1", "-f", "-"), script)
}

// LongBudgetExceeded reports whether a failed long-budget exec
// consumed (essentially) the whole LongCmdTimeout — i.e. the client
// was killed by its own deadline rather than failing fast, which is
// the case where the server-side session can outlive the exec.
// The fake clock never advances inside one call, so tests see false.
func (d *Deps) LongBudgetExceeded(start time.Time, err error) bool {
	if err == nil || d.Cfg.LongCmdTimeout < 2*time.Second {
		return false
	}
	return d.Cfg.Clock.Now().Sub(start)+time.Second >= d.Cfg.LongCmdTimeout
}

// ReapOrphanedMaintSessions terminates maintenance backends carrying
// our own application_names that are at least a minute old — the
// exec-timeout backstop: when `runtime exec` is killed client-side
// the server-side psql/pg_repack session can survive it (the runtime
// does not always propagate the kill), still holding the advisory
// lock or a pg_repack shadow table. The age guard spares a session
// that started after the timeout — a concurrent compact's own psql
// carries the same app_name — and pid<>pg_backend_pid() spares the
// reaper query itself. Best-effort: callers note the error.
func (d *Deps) ReapOrphanedMaintSessions(ctx context.Context, pg, user, pass string) (int, error) {
	out, err := d.PsqlQuery(ctx, pg, user, pass,
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "+
			"WHERE datname IN ('postgres', 'kine') "+
			"AND application_name IN ('pg_repack', 'pg_dump', '"+PGAPPNAME+"') "+
			"AND backend_start < now() - interval '1 minute' "+
			"AND pid <> pg_backend_pid()")
	if err != nil {
		return 0, err
	}
	n := 0
	for l := range strings.SplitSeq(out, "\n") {
		if strings.TrimSpace(l) == "t" {
			n++
		}
	}
	return n, nil
}

// EmitTextfile installs the rendered builder as
// <TextfileDir>/<name> — promfile.Write stages + renames so the
// textfile collector never sees a partial file.
func (d *Deps) EmitTextfile(name string, p *promfile.Builder) {
	_ = promfile.WriteLogged(d.Cfg.TextfileDir, name, []byte(p.String()),
		func(_, name string, err error) {
			logger().Warn("kinedb textfile write failed", "file", name, "error", err)
		})
}

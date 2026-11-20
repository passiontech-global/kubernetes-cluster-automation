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
	"sync/atomic"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
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
// take). Every long-budget exec is a legitimately long-running
// child (compact session, REINDEX/FREEZE script, pg_repack,
// pg_dump, backup cp) whose runtime can outlive the loop's own
// liveness budget — RunWithHeartbeat keeps stamping the ctx's
// beat every minute so /healthz never mistakes a healthy 20-minute
// pg_repack for a wedge.
func (d *Deps) ExecLongEnv(ctx context.Context, env, argv []string, stdin string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, d.Cfg.LongCmdTimeout)
	defer cancel()
	var out string
	var err error
	cycle.RunWithHeartbeat(cctx, time.Minute, func(hctx context.Context) {
		out, err = d.Cfg.Run(hctx, env, argv, stdin)
	})
	return out, err
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
// first, then the percona|postgres auto-discovery. The result rides
// the Deps name memo (nameMemoTTL) so coincident probe/compact/maint
// cycles share one inspect+ps resolution instead of each paying it.
func (d *Deps) PGContainerName(ctx context.Context) string {
	return d.memoizedContainerName(ctx, "pg",
		func(ctx context.Context) string {
			return d.DiscoverContainer(ctx, d.Cfg.PGContainer, rePGName, rePGExclude)
		})
}

// PGBContainerName resolves the pgbouncer container — configured
// name first, then the pgbouncer|pgb auto-discovery (same memo).
func (d *Deps) PGBContainerName(ctx context.Context) string {
	return d.memoizedContainerName(ctx, "pgb",
		func(ctx context.Context) string {
			return d.DiscoverContainer(ctx, d.Cfg.PGBouncerContainer, rePGBName, nil)
		})
}

// memoizedContainerName serves key's resolved name from the Deps
// memo while it is younger than nameMemoTTL, resolving through fn
// otherwise. The memo keys on the ROLE ("pg"/"pgb"), not the
// configured name — a cfg re-point mid-process still resolves
// through fn's fresh DiscoverContainer call on expiry, and the
// memo entry simply carries whichever name that returned.
func (d *Deps) memoizedContainerName(ctx context.Context, key string,
	fn func(context.Context) string) string {
	d.nameMu.Lock()
	defer d.nameMu.Unlock()
	if d.nameCache != nil {
		if m, ok := d.nameCache[key]; ok {
			age := d.Cfg.Clock.Now().Sub(m.at)
			if age >= 0 && age < nameMemoTTL {
				return m.name
			}
		}
	}
	name := fn(ctx)
	if name == "" {
		return name // a failed discovery must not pin for the TTL
	}
	if d.nameCache == nil {
		d.nameCache = map[string]nameMemo{}
	}
	d.nameCache[key] = nameMemo{name: name, at: d.Cfg.Clock.Now()}
	return name
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

// Per-loop application_name markers every psql session presents in
// pg_stat_activity. One name per loop (probe/compact/maint) so the
// orphan-session reaper kills only ITS OWN loop's timed-out
// backends — a shared name let the compact guard terminate a
// healthy maint pg_repack (and vice versa). The probe's
// stuck-session reaper exempts all three (stuckSessionPredicate's
// application_name NOT IN list); without them our own psql children
// show up as application_name='psql' and the reaper would terminate
// the very maintenance/remediation sessions it shares the DB with.
const (
	AppNameProbe   = "nha_probe"
	AppNameCompact = "nha_compact"
	AppNameMaint   = "nha_maint"
)

// PsqlPassEnv is the env half of the password hand-off — paired with
// the bare `-e PGPASSWORD` in PsqlArgs/the exec call sites. It also
// pins PGAPPNAME (see the AppName* consts): the env is the only
// channel a dynamic value may take, and the application_name marker
// must ride every session built from this helper.
func PsqlPassEnv(pass, appName string) []string {
	return []string{"PGPASSWORD=" + pass, "PGAPPNAME=" + appName}
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
	queryStmtTimeoutMargin   = 15 * time.Second
	queryMinStmtTimeout      = 10 * time.Second
)

func (d *Deps) queryPGOptions() string {
	stmt := d.Cfg.CmdTimeout
	if stmt > queryMinStmtTimeout {
		stmt -= queryStmtTimeoutMargin
		if stmt < queryMinStmtTimeout {
			stmt = queryMinStmtTimeout
		}
	}
	if stmt <= 0 {
		stmt = queryMinStmtTimeout
	}
	return fmt.Sprintf("-c statement_timeout=%d", stmt.Milliseconds())
}

// PsqlQueryEnv is PsqlPassEnv plus the query PGOPTIONS statement_timeout
// bound derived from CmdTimeout.
func (d *Deps) PsqlQueryEnv(pass, appName string) []string {
	return append(PsqlPassEnv(pass, appName), "PGOPTIONS="+d.queryPGOptions())
}

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
func (d *Deps) PsqlMaintEnv(pass, appName string) []string {
	return append(PsqlPassEnv(pass, appName), "PGOPTIONS="+d.maintPGOptions())
}

// PsqlQuery runs one statement with -tAc (unaligned, tuples only) and
// forwards PGOPTIONS statement_timeout so a timed-out exec does not
// leave an unbounded backend query running server-side.
func (d *Deps) PsqlQuery(ctx context.Context, pg, user, pass, appName, sql string) (string, error) {
	return d.ExecEnv(ctx, d.PsqlQueryEnv(pass, appName), d.PsqlMaintArgs(pg, user, false, "-tAc", sql), "")
}

// PsqlScript runs a multi-statement script in ONE psql session via
// stdin — required for the session-scoped advisory lock to cover the
// chunk loop + vacuum. Every caller is maintenance-class work
// (compact guard, heavy reindex/freeze, lock probes, dead-tuple
// vacuum), so the session carries the PGOPTIONS timeouts.
func (d *Deps) PsqlScript(ctx context.Context, pg, user, pass, appName, script string) (string, error) {
	return d.ExecLongEnv(ctx, d.PsqlMaintEnv(pass, appName), d.PsqlMaintArgs(pg, user, true,
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
// the CALLING loop's own application_names that are at least a
// minute old — the exec-timeout backstop: when `runtime exec` is
// killed client-side the server-side psql/pg_repack session can
// survive it (the runtime does not always propagate the kill),
// still holding the advisory lock or a pg_repack shadow table.
// apps scopes the kill to the caller's loop: the maint loop passes
// its own name plus the child binaries it spawns (pg_repack,
// pg_dump), the compact loop passes its own — a shared name let one
// loop's timeout reap a sibling's healthy session. The age guard
// spares a session that started after the timeout, and
// pid<>pg_backend_pid() spares the reaper query itself.
// Best-effort: callers note the error.
func (d *Deps) ReapOrphanedMaintSessions(ctx context.Context, pg, user, pass string, apps ...string) (int, error) {
	if len(apps) == 0 {
		return 0, nil
	}
	quoted := make([]string, len(apps))
	for i, a := range apps {
		quoted[i] = "'" + strings.ReplaceAll(a, "'", "''") + "'"
	}
	out, err := d.PsqlQuery(ctx, pg, user, pass, AppNameMaint,
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "+
			"WHERE datname IN ('postgres', 'kine') "+
			"AND application_name IN ("+strings.Join(quoted, ", ")+") "+
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

// holdStmtTimeoutMargin keeps the hold session's server-side
// statement bound ABOVE LongCmdTimeout: the session's pg_sleep is
// a single 86400s statement that must outlive the caller's whole
// work window (pg_repack runs up to LongCmdTimeout) — the
// maintenance margin (LongCmdTimeout-1m) would abort the sleep
// BEFORE the work budget ends and drop the advisory lock while
// pg_repack is still running.
const holdStmtTimeoutMargin = 5 * time.Minute

// holdNonce disambiguates concurrent HoldAdvisoryLock sessions —
// each hold presents application_name "<app>-hold-<pid>-<n>" so the
// confirmation poll and release()'s pg_terminate_backend hit OUR
// backend exactly, never a sibling loop's session.
var holdNonce atomic.Uint64

// holdPGOptions is maintPGOptions with statement_timeout lifted
// past LongCmdTimeout (see holdStmtTimeoutMargin).
func (d *Deps) holdPGOptions() string {
	stmt := d.Cfg.LongCmdTimeout + holdStmtTimeoutMargin
	return fmt.Sprintf("-c statement_timeout=%d -c lock_timeout=%d",
		stmt.Milliseconds(), maintLockTimeout.Milliseconds())
}

// HoldAdvisoryLock takes the shared maintenance advisory lock
// (Cfg.AdvisoryLockID, 20260921) on a DEDICATED psql session and
// returns a release func — for work that cannot carry the lock
// inside its own session script (pg_repack/pg_dump are separate
// binaries, not psql statements). The hold session runs
// `pg_try_advisory_lock` + `pg_sleep(86400)` under a nonce
// application_name: try_lock never creates a granted=false
// pg_locks row (unlike the blocking pg_advisory_lock, whose
// pending row previously read as "held" to the poll and let a
// second maint run pg_repack ON TOP of the compact guard), and a
// busy lock exits the session immediately instead of queueing
// server-side. Acquisition is confirmed by polling pg_locks for
// OUR backend's GRANTED row (classid=0/objsubid=1 pin the
// single-bigint lock form) before returning held=true — callers
// must skip, not queue. The poll is bounded by holdTimeout;
// release() terminates the hold backend by application_name so
// the lock drops NOW rather than whenever the orphaned psql's
// pg_sleep statement_timeout would fire.
func (d *Deps) HoldAdvisoryLock(ctx context.Context, pg, user, pass,
	appName string, holdTimeout time.Duration) (release func(), held bool, err error) {
	return d.holdAdvisoryLock(ctx, pg, user, pass, appName, holdTimeout, nil)
}

func (d *Deps) holdAdvisoryLock(ctx context.Context, pg, user, pass,
	appName string, holdTimeout time.Duration,
	beforePoll func(done <-chan struct{})) (release func(), held bool, err error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}

	holdApp := fmt.Sprintf("%s-hold-%d-%d", appName, os.Getpid(),
		holdNonce.Add(1))
	script := fmt.Sprintf(
		"SELECT CASE WHEN pg_try_advisory_lock(%d) THEN 'on' ELSE 'off' END AS hold_got\n"+
			"\\gset\n\\if :hold_got\n"+
			"SELECT pg_sleep(86400);\n"+
			"\\else\n\\echo 'advisory-lock-busy'\n\\endif\n",
		d.Cfg.AdvisoryLockID)

	var holdOut string
	var holdErr error
	holdCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		// The hold must outlive the caller's whole work window —
		// ExecLongEnv's fixed LongCmdTimeout budget would expire
		// FIRST (the hold starts before the work it guards) and
		// drop the lock early, so the session gets its own
		// LongCmdTimeout+margin ctx with the same heartbeat
		// liveness stamp.
		cctx, ccancel := context.WithTimeout(holdCtx,
			d.Cfg.LongCmdTimeout+holdStmtTimeoutMargin)
		defer ccancel()
		cycle.RunWithHeartbeat(cctx, time.Minute, func(hctx context.Context) {
			holdOut, holdErr = d.Cfg.Run(hctx,
				append(PsqlPassEnv(pass, holdApp),
					"PGOPTIONS="+d.holdPGOptions()),
				d.PsqlMaintArgs(pg, user, true, "-f", "-"), script)
		})
	}()

	// terminateHold terminates our server-side hold backend by its
	// unique application_name under a non-canceled bounded ctx so an
	// expired or canceled caller ctx never leaves pg_sleep(86400)
	// holding the advisory lock on the server.
	terminateHold := func() {
		tctx, tcancel := context.WithTimeout(context.WithoutCancel(ctx), d.Cfg.CmdTimeout)
		defer tcancel()
		_, _ = d.PsqlQuery(tctx, pg, user, pass,
			AppNameMaint, fmt.Sprintf(
				"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "+
					"WHERE application_name = '%s' AND pid <> pg_backend_pid()",
				strings.ReplaceAll(holdApp, "'", "''")))
	}

	releaseFn := func() {
		// Terminate OUR hold backend BEFORE cancelling the exec —
		// cancel alone kills only the host-side docker/podman
		// exec; the server-side psql would keep sleeping until its
		// statement_timeout and squat on the advisory lock the
		// whole time, blocking compact and emergency VACUUM.
		terminateHold()
		cancel()
		<-done
	}

	abortHold := func() {
		cancel()
		<-done
		terminateHold()
	}

	// lockHeld reports whether OUR nonce-named backend holds the
	// GRANTED advisory lock — pg_locks splits bigint AdvisoryLockID
	// into unsigned 32-bit classid (upper) and objid (lower) with
	// objsubid=1; granted excludes waiters.
	lockKey := uint64(d.Cfg.AdvisoryLockID)
	classID := uint32(lockKey >> 32)
	objID := uint32(lockKey)
	lockHeld := func() bool {
		out, qerr := d.PsqlQuery(ctx, pg, user, pass, AppNameMaint, fmt.Sprintf(
			"SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a "+
				"ON l.pid = a.pid WHERE l.locktype = 'advisory' "+
				"AND l.classid = %d AND l.objid = %d AND l.objsubid = 1 "+
				"AND l.granted AND a.application_name = '%s'",
			classID, objID, strings.ReplaceAll(holdApp, "'", "''")))
		if qerr != nil {
			return false
		}
		n := strings.TrimSpace(FirstLine(out))
		return n != "" && n != "0"
	}

	// onDone must only be called after <-done has fired so reading
	// holdOut/holdErr is race-free.
	onDone := func() (func(), bool, error) {
		if err := ctx.Err(); err != nil {
			cancel()
			<-done
			if holdErr != nil || !strings.Contains(holdOut, "advisory-lock-busy") {
				terminateHold()
			}
			return nil, false, err
		}
		heldNow := lockHeld()
		if err := ctx.Err(); err != nil {
			cancel()
			<-done
			if heldNow || holdErr != nil || !strings.Contains(holdOut, "advisory-lock-busy") {
				terminateHold()
			}
			return nil, false, err
		}
		if heldNow {
			return releaseFn, true, nil
		}
		cancel()
		<-done
		if holdErr == nil && strings.Contains(holdOut, "advisory-lock-busy") {
			return nil, false, nil
		}
		terminateHold()
		if holdErr != nil {
			return nil, false, holdErr
		}
		return nil, false, nil
	}

	if beforePoll != nil {
		beforePoll(done)
	}

	// The bound is an ITERATION count, not the injected clock: the
	// poll sleeps are real time and a frozen test clock must not
	// turn the wait into an infinite loop.
	polls := int(holdTimeout / (500 * time.Millisecond))
	if polls < 1 {
		polls = 1
	}
	for i := 0; i < polls; i++ {
		// A dead hold session can never hold the lock — check the
		// lock row once more (a just-released row can linger a
		// poll) then bail instead of sleeping out the budget.
		select {
		case <-done:
			return onDone()
		default:
		}
		if err := ctx.Err(); err != nil {
			abortHold()
			return nil, false, err
		}
		heldNow := lockHeld()
		if err := ctx.Err(); err != nil {
			abortHold()
			return nil, false, err
		}
		if heldNow {
			return releaseFn, true, nil
		}
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			abortHold()
			return nil, false, ctx.Err()
		case <-done:
			timer.Stop()
			return onDone()
		case <-timer.C:
		}
	}
	select {
	case <-done:
		return onDone()
	default:
	}
	abortHold()
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	return nil, false, nil
}

// exec.go — the runtime plumbing every domain loop shares: exec
// budgets, container discovery, the stack-.env credential read, the
// psql-in-container helpers and the textfile emitter. Was run.go's
// shared-helper half; the methods hang off *Deps so probe, compact
// and maint all reach them without importing each other.
package kdeps

import (
	"context"
	"os"
	"regexp"
	"strings"
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

// PGDataDF runs `df -B1 --output=<col>` inside the postgres container against
// Cfg.PGDataDir (or DefaultPGDataDir). When Cfg.PGDataDir is unset and the
// default path fails (e.g. Percona/Bitnami PGDATA=/data/db), it probes
// `printenv PGDATA` inside the container and retries once.
func (d *Deps) PGDataDF(ctx context.Context, pg, outputCol string) (string, error) {
	dataDir := d.Cfg.PGDataDir
	if dataDir == "" {
		dataDir = DefaultPGDataDir
	}
	df, err := d.Exec(ctx, []string{d.Cfg.Runtime, "exec", pg,
		"df", "-B1", "--output=" + outputCol, dataDir}, "")
	if err == nil || d.Cfg.PGDataDir != "" {
		return df, err
	}
	pgdata, perr := d.Exec(ctx, []string{d.Cfg.Runtime, "exec", pg,
		"printenv", "PGDATA"}, "")
	pgdata = strings.TrimSpace(pgdata)
	if perr != nil || pgdata == "" || pgdata == dataDir {
		return df, err
	}
	return d.Exec(ctx, []string{d.Cfg.Runtime, "exec", pg,
		"df", "-B1", "--output=" + outputCol, pgdata}, "")
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
	now := d.Cfg.Clock.Now()
	d.nameMu.Lock()
	if d.nameCache != nil {
		if m, ok := d.nameCache[key]; ok {
			age := now.Sub(m.at)
			if age >= 0 && age < nameMemoTTL {
				d.nameMu.Unlock()
				return m.name
			}
		}
	}
	d.nameMu.Unlock()

	name := fn(ctx)
	if name == "" || ctx.Err() != nil {
		return name // a failed or cancelled discovery must not pin for the TTL
	}

	storeNow := d.Cfg.Clock.Now()
	d.nameMu.Lock()
	if d.nameCache == nil {
		d.nameCache = map[string]nameMemo{}
	}
	if m, ok := d.nameCache[key]; ok {
		age := storeNow.Sub(m.at)
		if age >= 0 && age < nameMemoTTL {
			cached := m.name
			d.nameMu.Unlock()
			return cached
		}
	}
	d.nameCache[key] = nameMemo{name: name, at: storeNow}
	d.nameMu.Unlock()
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

// EmitTextfile installs the rendered builder as
// <TextfileDir>/<name> — promfile.Write stages + renames so the
// textfile collector never sees a partial file.
func (d *Deps) EmitTextfile(name string, p *promfile.Builder) {
	_ = promfile.WriteLogged(d.Cfg.TextfileDir, name, []byte(p.String()),
		func(_, name string, err error) {
			logger().Warn("kinedb textfile write failed", "file", name, "error", err)
		})
}

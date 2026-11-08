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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
)

// Exec runs argv under the short command budget.
func (d *Deps) Exec(ctx context.Context, argv []string, stdin string) (string, error) {
	return d.ExecEnv(ctx, nil, argv, stdin)
}

// ExecEnv is Exec with extra child environment — the only channel a
// secret may take: it rides the child's env, never argv.
func (d *Deps) ExecEnv(ctx context.Context, env, argv []string, stdin string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, d.Cfg.CmdTimeout)
	defer cancel()
	return d.Cfg.Run(cctx, env, argv, stdin)
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
	for _, n := range strings.Split(out, "\n") {
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
	argv := []string{d.Cfg.Runtime, "exec"}
	if interactive {
		argv = append(argv, "-i")
	}
	argv = append(argv, "-e", "PGPASSWORD", pg,
		"psql", "-h", "127.0.0.1", "-U", user, "-d", "postgres")
	return append(argv, extra...)
}

// PsqlPassEnv is the env half of the password hand-off — paired with
// the bare `-e PGPASSWORD` in PsqlArgs/the exec call sites.
func PsqlPassEnv(pass string) []string {
	return []string{"PGPASSWORD=" + pass}
}

// PsqlQuery runs one statement with -tAc (unaligned, tuples only).
func (d *Deps) PsqlQuery(ctx context.Context, pg, user, pass, sql string) (string, error) {
	return d.ExecEnv(ctx, PsqlPassEnv(pass), d.PsqlArgs(pg, user, false, "-tAc", sql), "")
}

// PsqlScript runs a multi-statement script in ONE psql session via
// stdin — required for the session-scoped advisory lock to cover the
// chunk loop + vacuum.
func (d *Deps) PsqlScript(ctx context.Context, pg, user, pass, script string) (string, error) {
	return d.ExecLongEnv(ctx, PsqlPassEnv(pass), d.PsqlArgs(pg, user, true,
		"-v", "ON_ERROR_STOP=1", "-f", "-"), script)
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

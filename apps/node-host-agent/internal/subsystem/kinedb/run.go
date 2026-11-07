// run.go — the loop lifecycle (Run drives probe/compact-guard/maint
// through cycle.RunAll) plus the runtime helpers every cycle body
// shares: exec budgets, container discovery, psql plumbing, textfile
// emission and the small parse/state-file utilities.
package kinedb

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
)

// Run starts the three loops (probe, compact guard, maintenance) and
// blocks until ctx is cancelled.
func (k *KineDB) Run(ctx context.Context) {
	// countPanic is the metric half of the old safeCycle — the
	// recover half moved into cycle.EverySafe, so a panicking round
	// counts cycles{loop,"panic"} and skips to the next interval
	// instead of unwinding the loop's goroutine.
	countPanic := func(loop string, _ any) {
		k.m.cycles.WithLabelValues(loop, "panic").Inc()
	}
	cycle.RunAll(ctx,
		cycle.EverySafe("probe", k.cfg.ProbeInterval,
			func(ctx context.Context) { k.probeCycle(ctx) }, countPanic),
		cycle.EverySafe("compact-guard", k.cfg.GuardInterval,
			func(ctx context.Context) { k.guardCycle(ctx) }, countPanic),
		cycle.EverySafe("maint", k.cfg.MaintInterval,
			func(ctx context.Context) { k.maintCycle(ctx) }, countPanic),
	)
}

// --- command + container helpers ---

// exec runs argv under the short command budget.
func (k *KineDB) exec(ctx context.Context, argv []string, stdin string) (string, error) {
	return k.execEnv(ctx, nil, argv, stdin)
}

// execEnv is exec with extra child environment — the only channel a
// secret may take: it rides the child's env, never argv.
func (k *KineDB) execEnv(ctx context.Context, env, argv []string, stdin string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, k.cfg.CmdTimeout)
	defer cancel()
	return k.cfg.run(cctx, env, argv, stdin)
}

// execLongEnv runs argv under the maintenance budget with extra
// child environment (see execEnv — the only channel a secret may
// take).
func (k *KineDB) execLongEnv(ctx context.Context, env, argv []string, stdin string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, k.cfg.LongCmdTimeout)
	defer cancel()
	return k.cfg.run(cctx, env, argv, stdin)
}

// discoverContainer returns preferred when it exists, else the first
// running container matching match (and not exclude) — the bash
// rename-resilience for stack redeploys.
func (k *KineDB) discoverContainer(ctx context.Context, preferred string, match, exclude *regexp.Regexp) string {
	if _, err := k.exec(ctx, []string{k.cfg.Runtime, "inspect", preferred}, ""); err == nil {
		return preferred
	}
	out, err := k.exec(ctx, []string{k.cfg.Runtime, "ps", "--format", "{{.Names}}"}, "")
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

func (k *KineDB) pgContainerName(ctx context.Context) string {
	return k.discoverContainer(ctx, k.cfg.PGContainer, rePGName, rePGExclude)
}

func (k *KineDB) pgbContainerName(ctx context.Context) string {
	return k.discoverContainer(ctx, k.cfg.PGBouncerContainer, rePGBName, nil)
}

func (k *KineDB) containerRunning(ctx context.Context, name string) bool {
	out, err := k.exec(ctx, []string{k.cfg.Runtime, "inspect", "-f", "{{.State.Running}}", name}, "")
	return err == nil && strings.Contains(out, "true")
}

// creds re-reads the stack .env every cycle — the backend_env check
// exists to catch credential drift, so caching would hide it.
func (k *KineDB) creds() (user, pass string, ok bool) {
	data, err := os.ReadFile(k.cfg.EnvFile)
	if err != nil {
		return "", "", false
	}
	user = envValue(string(data), "POSTGRES_USER")
	pass = envValue(string(data), "POSTGRES_PASSWORD")
	return user, pass, user != "" && pass != ""
}

// shq single-quotes a shell word — the one place a configured name
// reaches a `sh -c` STRING (probeLogScan's runtime+container) must
// not let a stray space or metachar split or glob the command.
func shq(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// envValue extracts KEY=value from .env content the way dotenv does:
// an optional `export ` prefix, a value that may be wrapped in one
// quote pair (only the wrapping pair is stripped — inner quotes,
// spaces and '#' stay literal), and a trailing ` # comment` on bare
// values. The bash `tr -d "\"' "` deleted every quote and space
// INSIDE the value too, silently corrupting credentials that
// legitimately contain them.
func envValue(data, key string) string {
	prefix := key + "="
	for _, l := range strings.Split(data, "\n") {
		l = strings.TrimSpace(l)
		l = strings.TrimPrefix(l, "export ")
		if !strings.HasPrefix(l, prefix) {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(l, prefix))
		if v == "" {
			return ""
		}
		if v[0] == '"' || v[0] == '\'' {
			// Quoted value: content runs to the matching closer;
			// anything after it (a trailing comment) is dropped.
			if end := strings.LastIndexByte(v[1:], v[0]); end >= 0 {
				return v[1 : 1+end]
			}
			// Unmatched opener: the bash `tr -d "\"' "` stripped
			// the leading quote too — drop it for parity rather
			// than smuggling it into the credential.
			return v[1:]
		}
		// Bare value: ` #` opens a comment.
		if i := strings.Index(v, " #"); i >= 0 {
			v = v[:i]
		}
		return strings.TrimSpace(v)
	}
	return ""
}

// psqlArgs builds `RT exec [-i] -e PGPASSWORD <pg> psql -h 127.0.0.1
// -U <user> -d postgres <extra...>` — every backend query goes through
// the container like the bash originals. The password is NOT on argv:
// `-e PGPASSWORD` forwards the var from the docker/podman client's
// own environment (psqlPassEnv on the child), keeping it off
// /proc/<pid>/cmdline where any host process could read it.
func (k *KineDB) psqlArgs(pg, user string, interactive bool, extra ...string) []string {
	argv := []string{k.cfg.Runtime, "exec"}
	if interactive {
		argv = append(argv, "-i")
	}
	argv = append(argv, "-e", "PGPASSWORD", pg,
		"psql", "-h", "127.0.0.1", "-U", user, "-d", "postgres")
	return append(argv, extra...)
}

// psqlPassEnv is the env half of the password hand-off — paired with
// the bare `-e PGPASSWORD` in psqlArgs/the exec call sites.
func psqlPassEnv(pass string) []string {
	return []string{"PGPASSWORD=" + pass}
}

// psqlQuery runs one statement with -tAc (unaligned, tuples only).
func (k *KineDB) psqlQuery(ctx context.Context, pg, user, pass, sql string) (string, error) {
	return k.execEnv(ctx, psqlPassEnv(pass), k.psqlArgs(pg, user, false, "-tAc", sql), "")
}

// psqlScript runs a multi-statement script in ONE psql session via
// stdin — required for the session-scoped advisory lock to cover the
// chunk loop + vacuum.
func (k *KineDB) psqlScript(ctx context.Context, pg, user, pass, script string) (string, error) {
	return k.execLongEnv(ctx, psqlPassEnv(pass), k.psqlArgs(pg, user, true,
		"-v", "ON_ERROR_STOP=1", "-f", "-"), script)
}

// --- textfile helpers ---

// emitTextfile installs the rendered builder as
// <TextfileDir>/<name> — promfile.Write stages + renames so the
// textfile collector never sees a partial file.
func (k *KineDB) emitTextfile(name string, p *promfile.Builder) {
	if err := promfile.Write(k.cfg.TextfileDir, name, []byte(p.String())); err != nil {
		logger().Warn("kinedb textfile write failed", "file", name, "error", err)
	}
}

// --- small parsing helpers ---

func firstLine(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) != "" {
			return strings.TrimSpace(l)
		}
	}
	return ""
}

// parsePair parses a `a|b` psql -tA row into two int64s.
func parsePair(out string) (a, b int64, err error) {
	f := strings.Split(firstLine(out), "|")
	if len(f) < 2 {
		return 0, 0, fmt.Errorf("expected 2 fields, got %q", firstLine(out))
	}
	if a, err = strconv.ParseInt(strings.TrimSpace(f[0]), 10, 64); err != nil {
		return 0, 0, err
	}
	if b, err = strconv.ParseInt(strings.TrimSpace(f[1]), 10, 64); err != nil {
		return 0, 0, err
	}
	return a, b, nil
}

// parseTriple parses a `a|b|c` psql -tA row into three int64s.
func parseTriple(out string) (a, b, c int64, err error) {
	f := strings.Split(firstLine(out), "|")
	if len(f) < 3 {
		return 0, 0, 0, fmt.Errorf("expected 3 fields, got %q", firstLine(out))
	}
	if a, err = strconv.ParseInt(strings.TrimSpace(f[0]), 10, 64); err != nil {
		return 0, 0, 0, err
	}
	if b, err = strconv.ParseInt(strings.TrimSpace(f[1]), 10, 64); err != nil {
		return 0, 0, 0, err
	}
	if c, err = strconv.ParseInt(strings.TrimSpace(f[2]), 10, 64); err != nil {
		return 0, 0, 0, err
	}
	return a, b, c, nil
}

// parseQuad parses a `a|b|c|d` psql -tA row into four int64s.
func parseQuad(out string) (a, b, c, d int64, err error) {
	f := strings.Split(firstLine(out), "|")
	if len(f) < 4 {
		return 0, 0, 0, 0, fmt.Errorf("expected 4 fields, got %q", firstLine(out))
	}
	vals := []*int64{&a, &b, &c, &d}
	for i := range vals {
		if *vals[i], err = strconv.ParseInt(strings.TrimSpace(f[i]), 10, 64); err != nil {
			return 0, 0, 0, 0, err
		}
	}
	return a, b, c, d, nil
}

func readIntFile(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
}

func writeIntFile(path string, v int64) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		logger().Warn("kinedb state file write failed", "file", path, "error", err)
		return
	}
	// hostutil's random-suffix tmp + fsync + rename — probe and
	// guard loops can reach the same file from different goroutines,
	// so a fixed .tmp-<name> staging path could clobber mid-write.
	if err := hostutil.WriteFileAtomicBytes(path,
		[]byte(strconv.FormatInt(v, 10)+"\n")); err != nil {
		logger().Warn("kinedb state file write failed", "file", path, "error", err)
	}
}

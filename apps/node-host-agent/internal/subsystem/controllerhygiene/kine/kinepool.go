package kine

// kinepool.go — port of scripts/k0s-kine-pool-probe.sh (60s timer):
// the kine -> datastore connection-spiral backstop.
//
// Incident 2026-10-01: kine defaults to
// --datastore-max-open-connections=0 (UNLIMITED) so a slow Postgres
// behind PgBouncer made every slow query open ANOTHER client
// connection instead of queueing in the Go pool — 312 conns on one
// controller into an ~40-80 slot pool → cl_waiting>300 → "Slow SQL"
// → apiserver handler timeouts → controller restart cascade. The
// k0sctl.yaml cap is the real fix; this probe is the backstop for an
// unapplied/broken cap: kine's own TCP connections to the DB port
// exceeding KinePoolMaxConns for KinePoolCycles consecutive cycles →
// SIGTERM the kine pid (the k0s supervisor respawns it with a clean
// pool, draining all conns queued at pgbouncer).
//
// No peer fence: the signal is per-node. Rate-limit: one kill per
// KinePoolMinRestart (1200s) via last-kinepool-kill.
//
// Port detail: `ss -Htnp "dport = :$db_port" | grep -c "pid=$kpid,"`
// is realised by intersecting the socket inodes of
// /proc/<kine-pid>/fd with the remote-port column of
// /proc/<kine-pid>/net/tcp(6) — the identical socket set, no ss
// dependency. DB port is parsed from kine's --endpoint argv with the
// same 6432 fallback.

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

var (
	// endpointPortRe is the --endpoint=postgres://...:PORT/db match on
	// the kine cmdline (the sed 's/^--endpoint=.*:\([0-9][0-9]*\)\/[^/]*$/\1/p'
	// of k0s-kine-pool-probe.sh, applied per argv entry).
	endpointPortRe = regexp.MustCompile(`^--endpoint=.*:([0-9]+)/[^/]*$`)
	// sockInodeRe matches socket:[<inode>] fd symlink targets.
	sockInodeRe = regexp.MustCompile(`^socket:\[([0-9]+)\]$`)
)

// tcpStateListen is the st column of /proc/net/tcp(6) rows in LISTEN.
const tcpStateListen = "0A"

// PoolCheck is the kine->DB connection-spiral backstop as a
// Check — it keeps no in-memory state: the spiral streak lives in
// consecutive-kine-pool (the cross-process shell contract).
type PoolCheck struct {
	d *cdeps.Deps
}

// Name returns the check label / log context.
func (c *PoolCheck) Name() string { return cdeps.CheckKinePool }

// Run executes one pool-guard cycle.
func (c *PoolCheck) Run(_ context.Context) {
	kpid := c.d.Proc.FindByComm("kine")
	if kpid == 0 {
		// No kine process: etcd controller or k0s not initialised —
		// the probe is a silent no-op (the shell exited the same way).
		c.d.Cycles.WithLabelValues(cdeps.CheckKinePool, "no_kine").Inc()
		return
	}
	dbPort := c.kineDBPort(kpid)
	conns := c.kineDBConns(kpid, dbPort)
	c.d.KineConns.Set(float64(conns))

	if conns <= c.d.Cfg.KinePool.MaxConns {
		c.d.State.ResetCounter(cdeps.FileCtrPool)
		c.d.StateExit(cdeps.StateKinePoolRunaway)
		c.d.Cycles.WithLabelValues(cdeps.CheckKinePool, "ok").Inc()
		return
	}

	n := c.d.State.Incr(cdeps.FileCtrPool)
	if n < c.d.Cfg.KinePool.Cycles {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: kine conns-to-db=%d > %d — pool spiral? (check %d/%d)",
			conns, c.d.Cfg.KinePool.MaxConns, n, c.d.Cfg.KinePool.Cycles))
		c.d.Cycles.WithLabelValues(cdeps.CheckKinePool, "ok").Inc()
		return
	}

	// --- spiral confirmed ---
	c.d.State.Enter(cdeps.StateKinePoolRunaway, fmt.Sprintf(
		"conns=%d>%d x%d pid=%d", conns, c.d.Cfg.KinePool.MaxConns, n, kpid))

	if !c.d.State.RateOK(cdeps.FileRatePoolKill, c.d.Cfg.KinePool.MinRestart) {
		c.d.State.SuspectLog(cdeps.StateKinePoolRunaway, fmt.Sprintf(
			"kine-pool-runaway conns=%d (%dx) but in kill cooldown (<%dm), skip",
			conns, n, int(c.d.Cfg.KinePool.MinRestart.Minutes())),
			c.d.Cfg.SuspectLogCadence)
		c.d.Cycles.WithLabelValues(cdeps.CheckKinePool, "ok").Inc()
		return
	}

	switch c.d.Cfg.KinePool.Mode {
	case cdeps.ModeEnforce:
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: kill kine pid=%d — conns-to-db=%d > %d x%d (k0s supervisor respawns with a clean pool)",
			kpid, conns, c.d.Cfg.KinePool.MaxConns, n))
		c.d.State.RateSpend(cdeps.FileRatePoolKill)
		c.d.State.ResetCounter(cdeps.FileCtrPool)
		if err := c.d.Cfg.KillFn(kpid, syscall.SIGTERM); err != nil {
			c.d.State.AppendLogWarn(fmt.Sprintf(
				"suspect: kill kine pid=%d failed: %v", kpid, err))
		}
		c.d.Actions.WithLabelValues(cdeps.CheckKinePool, "kill_kine").Inc()
	case cdeps.ModeDryRun:
		c.d.State.AppendLog(fmt.Sprintf(
			"DRY-RUN: would kill kine pid=%d — conns-to-db=%d > %d x%d",
			kpid, conns, c.d.Cfg.KinePool.MaxConns, n))
		c.d.Actions.WithLabelValues(cdeps.CheckKinePool, "dryrun_kill").Inc()
	}
	c.d.Cycles.WithLabelValues(cdeps.CheckKinePool, "ok").Inc()
}

// kineDBPort parses the datastore port out of kine's --endpoint argv:
// `--endpoint=postgres://...:PORT/db`. Fallback 6432 when absent —
// the same default the probe's shell header documents.
func (c *PoolCheck) kineDBPort(kpid int) int {
	for _, arg := range c.d.Proc.Cmdline(kpid) {
		if m := endpointPortRe.FindStringSubmatch(arg); m != nil {
			if p, err := strconv.Atoi(m[1]); err == nil {
				return p
			}
		}
	}
	return c.d.Cfg.KinePool.DBPortFallback
}

// kineDBConns counts pid's TCP sockets whose remote port is dbPort —
// the `ss -Htnp dport = :PORT | grep pid=` set: the pid's own socket
// inodes (from /proc/<pid>/fd) intersected with the non-LISTEN rows
// of its /proc/net/tcp(+tcp6) view.
func (c *PoolCheck) kineDBConns(pid, dbPort int) int {
	inodes := c.socketInodes(pid)
	if len(inodes) == 0 {
		return 0
	}
	n := 0
	for _, f := range []string{"net/tcp", "net/tcp6"} {
		data, err := os.ReadFile(c.d.Proc.File(pid, f))
		if err != nil {
			continue
		}
		n += countConnsToPort(string(data), dbPort, inodes)
	}
	return n
}

// socketInodes returns the socket inode set of a process — the fd
// symlinks of the form socket:[<inode>].
func (c *PoolCheck) socketInodes(pid int) map[string]bool {
	entries, err := os.ReadDir(c.d.Proc.File(pid, "fd"))
	if err != nil {
		return nil
	}
	set := make(map[string]bool, len(entries))
	for _, e := range entries {
		link, err := os.Readlink(c.d.Proc.File(pid, "fd", e.Name()))
		if err != nil {
			continue
		}
		if m := sockInodeRe.FindStringSubmatch(link); m != nil {
			set[m[1]] = true
		}
	}
	return set
}

// countConnsToPort parses a /proc/net/tcp(6) table and counts rows
// whose remote port is dbPort, that are not LISTEN and whose inode
// belongs to the watched process.
//
// Table columns (0-indexed after the header row — tx_queue:rx_queue
// and tr:tm->when are each ONE colon-joined field):
//
//	sl local rem st tx:rx tr:tm retrnsmt uid timeout inode ...
//	0  1     2   3  4     5     6        7   8       9
func countConnsToPort(table string, dbPort int, inodes map[string]bool) int {
	n := 0
	header := true
	for rest := table; rest != ""; {
		line, after, _ := strings.Cut(rest, "\n")
		rest = after
		if header {
			header = false
			continue // header row
		}
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		if f[3] == tcpStateListen {
			continue
		}
		// rem_address is hex "0100007F:1538".
		rem := f[2]
		j := strings.LastIndexByte(rem, ':')
		if j < 0 {
			continue
		}
		port, err := strconv.ParseUint(rem[j+1:], 16, 16)
		if err != nil || int(port) != dbPort {
			continue
		}
		if inodes[f[9]] {
			n++
		}
	}
	return n
}

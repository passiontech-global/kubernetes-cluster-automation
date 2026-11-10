package storelocal

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
	"bufio"
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

// W20-CP2 stuck-connection states on the same st column:
// FIN_WAIT2 (05) — we closed, the peer never ACKed our FIN;
// CLOSE_WAIT (08) — the peer closed, the local app never did.
// Either held open against the DB port is an orphaned connection
// the pool count alone cannot distinguish from a live one.
const (
	tcpStateFinWait2  = "05"
	tcpStateCloseWait = "08"
	// kineRetransmitStuck is the retrnsmt column floor that reads
	// as "retransmitting abnormally" — occasional loss retries sit
	// at 1-2; a socket past 3 has stopped making progress.
	kineRetransmitStuck = 3
)

// PoolCheck is the kine->DB connection-spiral backstop as a
// Check — it keeps no in-memory state: the spiral streak lives in
// consecutive-kine-pool (the cross-process shell contract).
type PoolCheck struct {
	d *cdeps.Deps
}

// Name returns the check label / log context.
func (c *PoolCheck) Name() string { return cdeps.CheckKinePool }

// Run executes one pool-guard cycle. ctx is honored at the two
// points where aborting is cheap and safe: between the kine
// discovery scan and the fd/net-table scan, and before the kill —
// a SIGTERM delivered on a cancelled context races the supervisor's
// own shutdown stop.
func (c *PoolCheck) Run(ctx context.Context) {
	kpid := c.d.Proc.FindByComm("kine")
	if kpid == 0 {
		// No kine process: etcd controller or k0s not initialised —
		// the probe is a silent no-op (the shell exited the same way).
		c.d.Cycles.WithLabelValues(cdeps.CheckKinePool, "no_kine").Inc()
		return
	}
	// Shutdown between the discovery scan and the fd/net-table scan:
	// an aborted cycle must not publish half-read gauges.
	if err := ctx.Err(); err != nil {
		c.d.Cycles.WithLabelValues(cdeps.CheckKinePool, "aborted").Inc()
		return
	}
	dbPort := c.kineDBPort(kpid)
	// W20-CP2 — one inode∩port scan yields BOTH the conn count and
	// the stuck subset: CLOSE_WAIT/FIN_WAIT2 rows are connections the
	// peer already closed that kine never reaped, and a climbing
	// retrnsmt counter is a socket retransmitting into a dead
	// PgBouncer/Postgres. The count alone cannot see them — surface
	// the stuck set on its own gauge + suspect line as early warning
	// before the orphans starve the pool. (Scanning /proc twice per
	// cycle for the two numbers would double the fd/net-table read
	// for zero extra signal.)
	conns, stuck := c.kineDBConnStats(kpid, dbPort)
	c.d.KineConns.Set(float64(conns))
	c.d.KineStuckConns.Set(float64(stuck))
	if stuck > 0 {
		c.d.State.SuspectLog(cdeps.StateKinePoolRunaway, fmt.Sprintf(
			"suspect: kine db conns stuck — %d socket(s) CLOSE_WAIT/FIN_WAIT2 or retransmitting (kine->pgbouncer/postgres orphaned-conn signature)",
			stuck), c.d.Cfg.SuspectLogCadence)
	}

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

	// The kill gate: cancellation is checked AFTER the evidence is
	// persisted (the latch + spiral counter files survive the abort
	// and re-arm the next cycle) but BEFORE any budget spend or
	// signal — an aborted cycle must not spend the kill budget on a
	// SIGTERM it never delivers.
	if err := ctx.Err(); err != nil {
		c.d.Cycles.WithLabelValues(cdeps.CheckKinePool, "aborted").Inc()
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

// kineDBConnStats counts pid's TCP sockets whose remote port is
// dbPort AND how many of those are stuck — the `ss -Htnp dport =
// :PORT | grep pid=` set intersected with the W20-CP2 orphan
// signature, from ONE pass over the pid's socket inodes (fd links)
// and its /proc/net/tcp(+tcp6) view. stuck is always a subset of
// conns: every stuck row is a non-LISTEN conn to dbPort.
func (c *PoolCheck) kineDBConnStats(pid, dbPort int) (conns, stuck int) {
	inodes := c.socketInodes(pid)
	if len(inodes) == 0 {
		return 0, 0
	}
	for _, f := range []string{"net/tcp", "net/tcp6"} {
		fp, err := os.Open(c.d.Proc.File(pid, f))
		if err != nil {
			continue
		}
		// Stream line-by-line — os.ReadFile + string() would pull the
		// WHOLE host TCP table (kine shares the host netns; 15-25 MiB
		// on busy nodes) into heap twice, every 60s cycle.
		sc := bufio.NewScanner(fp)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		header := true
		for sc.Scan() {
			if header {
				header = false
				continue // header row
			}
			isConn, isStuck := classifyConnLine(sc.Text(), dbPort, inodes)
			if isConn {
				conns++
			}
			if isStuck {
				stuck++
			}
		}
		_ = fp.Close()
	}
	return conns, stuck
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

// classifyConnLine classifies one /proc/net/tcp(6) data row:
// isConn when its remote port is dbPort, it is not LISTEN and its
// inode belongs to the watched process (the `ss dport` set);
// isStuck when that conn additionally shows the W20-CP2 orphan
// signature — FIN_WAIT2/CLOSE_WAIT state or a retrnsmt counter
// past the stuck floor. stuck ⊆ conn by construction.
//
// Table columns (0-indexed; tx_queue:rx_queue and tr:tm->when are
// each ONE colon-joined field):
//
//	sl local rem st tx:rx tr:tm retrnsmt uid timeout inode ...
//	0  1     2   3  4     5     6        7   8       9
func classifyConnLine(line string, dbPort int,
	inodes map[string]bool) (isConn, isStuck bool) {

	f := strings.Fields(line)
	if len(f) < 10 {
		return false, false
	}
	if f[3] == tcpStateListen {
		return false, false
	}
	port, ok := tcpRemotePort(f)
	if !ok || port != dbPort || !inodes[f[9]] {
		return false, false
	}
	if f[3] == tcpStateFinWait2 || f[3] == tcpStateCloseWait {
		return true, true
	}
	// retrnsmt is %08X — HEX, not decimal (tcp_ipv4.c seq_printf).
	// Atoi would fail on "0000000A" (10 retries) and misread
	// "00000010" as ten instead of sixteen.
	retr, err := strconv.ParseUint(f[6], 16, 32)
	return true, err == nil && retr > kineRetransmitStuck
}

// tcpRemotePort parses the remote port out of a /proc/net/tcp(6)
// row's fields — rem_address is hex "0100007F:1538".
func tcpRemotePort(f []string) (int, bool) {
	rem := f[2]
	j := strings.LastIndexByte(rem, ':')
	if j < 0 {
		return 0, false
	}
	port, err := strconv.ParseUint(rem[j+1:], 16, 16)
	if err != nil {
		return 0, false
	}
	return int(port), true
}

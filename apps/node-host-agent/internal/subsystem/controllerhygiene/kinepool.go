package controllerhygiene

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
	"strconv"
	"strings"
	"syscall"
)

// checkKinePool runs one pool-guard cycle.
func (h *Hygiene) checkKinePool(_ context.Context) {
	kpid := h.findProcByComm("kine")
	if kpid == 0 {
		// No kine process: etcd controller or k0s not initialised —
		// the probe is a silent no-op (the shell exited the same way).
		h.cycles.WithLabelValues(checkKinePool, "no_kine").Inc()
		return
	}
	dbPort := h.kineDBPort(kpid)
	conns := h.kineDBConns(kpid, dbPort)
	h.kineConns.Set(float64(conns))

	if conns <= h.cfg.KinePoolMaxConns {
		h.state.ResetCounter(fileCtrPool)
		h.stateExit(stateKinePoolRunaway)
		h.cycles.WithLabelValues(checkKinePool, "ok").Inc()
		return
	}

	n := h.state.Incr(fileCtrPool)
	if n < h.cfg.KinePoolCycles {
		h.state.AppendLog(fmt.Sprintf(
			"suspect: kine conns-to-db=%d > %d — pool spiral? (check %d/%d)",
			conns, h.cfg.KinePoolMaxConns, n, h.cfg.KinePoolCycles))
		h.cycles.WithLabelValues(checkKinePool, "ok").Inc()
		return
	}

	// --- spiral confirmed ---
	h.state.Enter(stateKinePoolRunaway, fmt.Sprintf(
		"conns=%d>%d x%d pid=%d", conns, h.cfg.KinePoolMaxConns, n, kpid))

	if !h.state.RateOK(fileRatePoolKill, h.cfg.KinePoolMinRestart) {
		h.state.SuspectLog(stateKinePoolRunaway, fmt.Sprintf(
			"kine-pool-runaway conns=%d (%dx) but in kill cooldown (<%dm), skip",
			conns, n, int(h.cfg.KinePoolMinRestart.Minutes())),
			h.cfg.SuspectLogCadence)
		h.cycles.WithLabelValues(checkKinePool, "ok").Inc()
		return
	}

	switch h.cfg.KinePoolMode {
	case ModeEnforce:
		h.state.AppendLog(fmt.Sprintf(
			"ACTION: kill kine pid=%d — conns-to-db=%d > %d x%d (k0s supervisor respawns with a clean pool)",
			kpid, conns, h.cfg.KinePoolMaxConns, n))
		h.state.RateSpend(fileRatePoolKill)
		h.state.ResetCounter(fileCtrPool)
		if err := h.cfg.killFn(kpid, syscall.SIGTERM); err != nil {
			h.state.AppendLogWarn(fmt.Sprintf(
				"suspect: kill kine pid=%d failed: %v", kpid, err))
		}
		h.actions.WithLabelValues(checkKinePool, "kill_kine").Inc()
	case ModeDryRun:
		h.state.AppendLog(fmt.Sprintf(
			"DRY-RUN: would kill kine pid=%d — conns-to-db=%d > %d x%d",
			kpid, conns, h.cfg.KinePoolMaxConns, n))
		h.actions.WithLabelValues(checkKinePool, "dryrun_kill").Inc()
	}
	h.cycles.WithLabelValues(checkKinePool, "ok").Inc()
}

// kineDBPort parses the datastore port out of kine's --endpoint argv:
// `--endpoint=postgres://...:PORT/db`. Fallback 6432 when absent —
// the same default the probe's shell header documents.
func (h *Hygiene) kineDBPort(kpid int) int {
	for _, arg := range h.procCmdline(kpid) {
		if m := endpointPortRe.FindStringSubmatch(arg); m != nil {
			if p, err := strconv.Atoi(m[1]); err == nil {
				return p
			}
		}
	}
	return h.cfg.KineDBPortFallback
}

// kineDBConns counts pid's TCP sockets whose remote port is dbPort —
// the `ss -Htnp dport = :PORT | grep pid=` set: the pid's own socket
// inodes (from /proc/<pid>/fd) intersected with the non-LISTEN rows
// of its /proc/net/tcp(+tcp6) view.
func (h *Hygiene) kineDBConns(pid, dbPort int) int {
	inodes := h.socketInodes(pid)
	if len(inodes) == 0 {
		return 0
	}
	n := 0
	for _, f := range []string{"net/tcp", "net/tcp6"} {
		data, err := os.ReadFile(h.procFile(pid, f))
		if err != nil {
			continue
		}
		n += countConnsToPort(string(data), dbPort, inodes)
	}
	return n
}

// socketInodes returns the socket inode set of a process — the fd
// symlinks of the form socket:[<inode>].
func (h *Hygiene) socketInodes(pid int) map[string]bool {
	entries, err := os.ReadDir(h.procFile(pid, "fd"))
	if err != nil {
		return nil
	}
	set := make(map[string]bool, len(entries))
	for _, e := range entries {
		link, err := os.Readlink(h.procFile(pid, "fd", e.Name()))
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

// ctr_meta.go — the meta-db-corruption containerd meta.db corruption guard
// (split out of the old deep_failure_checks.go): journal-signature
// probe plus the reparented-orphan-shim evidence channel. Shares the
// shim-scope helpers in ctr_tasks.go.
package ctr

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// ctrMetaOrphanMinAge is the "dead for >15m" evidence bar for KR3
// orphan shims — a shim whose init died seconds ago is a normal
// teardown in flight, not corruption.
const ctrMetaOrphanMinAge = 15 * time.Minute

// ctrMetaJournalWindow is the KR3 journal lookback — corruption
// signatures only need the recent window; a stale hit from days ago
// must not latch. Only the hand-built-env fork fallback still uses
// it (the live probe rides the cycle-shared 10m snapshot).
const ctrMetaJournalWindow = "3 minutes ago"

// ctrMetaProbeTimeout is the containerd socket dial budget — the
// kubelet A4 hang probe's unixSockProbeTimeout parity (5s): a
// wedged listener stops accepting and the dial deadline is the
// verdict.
const ctrMetaProbeTimeout = 5 * time.Second

// ctrNonNegatedPrefix matches a line start, delimiter, positive count,
// or non-negation word immediately before "invalid" / "corrupt",
// rejecting zero counts ("0", "00") and negations ("no", "not").
const ctrNonNegatedPrefix = `(?:^|\n|[:(\[/]\s*` +
	`|(?:^|[\s:(\[/])(?:` +
	`[1-9][0-9]*` +
	`|[A-MO-Za-mo-z_][A-Za-z0-9_.-]*` +
	`|[nN][A-NP-Za-np-z0-9_.-][A-Za-z0-9_.-]*` +
	`|[nN][oO][A-SU-Za-su-z0-9_.-][A-Za-z0-9_.-]*` +
	`|[nN][oO][tT][A-Za-z0-9_.-]+` +
	`)\s+)`

// ctrMetaCorruptRe is the KR3 journal signature set — bbolt/meta.db
// corruption phrases containerd logs when its bolt store won't open.
var ctrMetaCorruptRe = regexp.MustCompile(
	`failed to loadmeta` +
		`|invalid freelist page` +
		`|meta\.db: Somethings wrong` +
		`|(?:bbolt|meta\.db)(?:\s+|[^\n]*)(?:panic|out of bounds|already freed|Somethings wrong|checksum (?:(?:verify|verification) )?(?:mismatch|error|invalid|fail))` +
		`|(?:bbolt|meta\.db)(?:\s+|[^\n]*` + ctrNonNegatedPrefix + `)(?:(?:invalid|bad|corrupt)[^\n]*checksum|invalid (?:freelist|page|crc|bucket|node|tx|meta|db|database|magic|header))` +
		`|(?:bbolt|meta\.db)(?:\s+|[^\n]*` + ctrNonNegatedPrefix + `)corrupt` +
		`|(?:panic|` + ctrNonNegatedPrefix + `invalid (?:freelist|page|crc|checksum|bucket|node|tx|meta|db|database|magic|header))[^\n]*(?:bbolt|meta\.db)` +
		`|` + ctrNonNegatedPrefix + `corrupt[^\n]*(?:bbolt|meta\.db)`)

// CtrMetaCheck is the meta-db-corruption containerd meta.db corruption
// guard as a Check; it owns the evidence streak
// (ex-Hygiene.ctrMetaFails). Two evidence channels, either
// sufficient for state-containerd-corrupt (KubeletRuntimeStall
// altStateKey — a corrupt store survives k0sworker restarts, so the
// NHC→SNR path needs the latch, not just a restart):
//
//   - the cycle-shared k0sworker journal snapshot (e.JournalOnce)
//     matching the bbolt/meta.db corruption signatures, and
//   - containerd-shim-runc-v2 processes reparented to PID 1 whose
//     k8s.io task dir still exists but whose init has been dead
//     >15m — the shape containerd leaves when it loses track of a
//     task (its bookkeeping DB is the usual suspect).
//
// ConsecNeeded consecutive evidence cycles latch; a clean cycle
// clears. An unreadable journal is inconclusive for that half —
// the shim half still evaluates.
type CtrMetaCheck struct {
	d     *wdeps.Deps
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *CtrMetaCheck) Name() string { return wdeps.CheckCtrMeta }

// Run executes one containerd-meta round.
func (c *CtrMetaCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckCtrMeta) {
		return
	}
	evidence := ""
	// The journal probe rides the CYCLE-SHARED k0sworker snapshot
	// (e.JournalOnce — built at most once per cycle, and only when a
	// consumer actually pulls it) instead of forking its own
	// `journalctl -u k0sworker -u containerd --since "3 minutes ago"`
	// every cycle: the bbolt/meta.db corruption signatures come out
	// of k0sworker's own journal when k0s supervises containerd, and
	// the shared 10-minute window still only covers the recent
	// past. MetaJournalFn overrides for tests; the old two-unit fork
	// stays the last fallback for hand-built envs with no snapshot.
	journalFn := c.d.Cfg.Ctr.MetaJournalFn
	if journalFn == nil {
		if e != nil && e.JournalOnce != nil {
			journalFn = func(context.Context) (string, error) {
				out := e.JournalOnce()
				if e.JournalOK != nil && !e.JournalOK() {
					return "", errors.New("k0sworker journal snapshot failed")
				}
				return out, nil
			}
		} else if c.d.Cfg.Systemd != nil {
			journalFn = func(ctx context.Context) (string, error) {
				return c.d.Cfg.Systemd.ExecCombined(ctx, "journalctl",
					"-u", "k0sworker.service", "-u", "containerd.service",
					"--since", ctrMetaJournalWindow, "--no-pager")
			}
		}
	}
	journalOK := true
	if journalFn != nil {
		out, err := journalFn(ctx)
		if err != nil {
			journalOK = false
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: containerd-meta journal probe failed: %v — journal half inconclusive",
				err))
		} else if m := ctrMetaCorruptRe.FindString(out); m != "" {
			evidence = "journal: " + m
		}
	}
	pids, pidsOK := c.d.CyclePIDs(e)
	shimInconclusive := false
	if pidsOK {
		var orphans int
		orphans, shimInconclusive = countMetaOrphanShims(c.d, e, pids)
		if orphans > 0 {
			if evidence != "" {
				evidence += "; "
			}
			evidence += fmt.Sprintf("%d orphan shim(s) ppid=1", orphans)
		}
	}
	c.measureMetaDBSize(ctx)
	if evidence != "" {
		if !c.d.StreakPending(&c.fails,
			fmt.Sprintf("suspect: containerd meta.db corruption evidence (%s)", evidence)) {
			c.d.State.Enter(latchdefs.LatchContainerdCorrupt, evidence)
		}
		c.d.CycleResult(wdeps.CheckCtrMeta, "ok")
		return
	}
	if !pidsOK {
		c.d.CycleResult(wdeps.CheckCtrMeta, "inconclusive")
		return
	}
	if !journalOK || shimInconclusive {
		c.d.CycleResult(wdeps.CheckCtrMeta, "abort")
		return
	}
	c.fails = 0
	c.d.State.Exit(latchdefs.LatchContainerdCorrupt, nil)
	c.d.CycleResult(wdeps.CheckCtrMeta, "ok")
}

// ctrMetaDBRel is meta.db's path under K0sDataDir — the bbolt store
// every containerd metadata op serializes through.
const ctrMetaDBRel = "containerd/io.containerd.metadata.v1.bolt/meta.db"

// measureMetaDBSize stats the bbolt store and publishes its size on
// node_agent_ctr_metadb_bytes (containerd-meta-guard), then times the
// lightest reachability probe containerd serves — a connect+close on
// the daemon's grpc unix socket (d.Cfg.CtrSocket, the same path the
// kubelet A4 hang probe dials) — onto
// node_agent_ctr_meta_probe_latency_seconds (selfheal-alert-coverage).
// A containerd that stops accepting — wedged accept loop, restart
// mid-flight, a meta.db so broken the daemon never came up — stops
// answering here first. A missing file or a failed probe leaves the
// last value — never a fake 0.
func (c *CtrMetaCheck) measureMetaDBSize(ctx context.Context) {
	fi, err := os.Stat(filepath.Join(
		c.d.Cfg.K0sDataDir, ctrMetaDBRel))
	if err == nil {
		c.d.CtrMetaDBBytes = fi.Size()
	}
	c.measureMetaProbeLatency(ctx)
}

// measureMetaProbeLatency times one connect+close round-trip on the
// containerd grpc socket through the shared ProbeUnixSock seam. The
// probe touches only the socket's accept queue — no ctr fork, no
// RPC — so its wall time tracks daemon liveness/accept latency. A
// nil seam or dial error leaves the previous reading in place.
func (c *CtrMetaCheck) measureMetaProbeLatency(ctx context.Context) {
	if c.d.Cfg.Seams.Probe.ProbeUnixSock == nil {
		return
	}
	start := c.d.Cfg.Seams.Host.Clock.Now()
	if err := c.d.Cfg.Seams.Probe.ProbeUnixSock(ctx,
		c.d.Cfg.CtrSocket, ctrMetaProbeTimeout); err != nil {
		return
	}
	c.d.CtrMetaProbeLatencySec =
		c.d.Cfg.Seams.Host.Clock.Now().Sub(start).Seconds()
}

// countMetaOrphanShims counts containerd-shim-runc-v2 processes that
// look like meta.db-loss orphans: in-scope for THIS containerd
// (ctrShimScope — never a foreign daemon's shim), reparented to PID
// 1 (containerd forgot them), older than ctrMetaOrphanMinAge, and
// whose k8s.io task dir still exists with a dead/missing init —
// wdeps.CheckCtrTasks owns the missing-dir orphan case and live-init dirs
// are normal tasks, so both are excluded here.
func countMetaOrphanShims(d *wdeps.Deps, e *wdeps.CycleEnv, pids []int) (int, bool) {
	n := 0
	inconclusive := false
	for _, pid := range pids {
		// Same comm pre-filter as the ctr-tasks shim scan — a
		// non-shim comm cannot produce the argv match below.
		comm, known := procCommKnown(e, d, pid)
		if known && !strings.HasPrefix(comm, "containerd-shim") {
			continue
		}
		state, ppid, ok := d.ProcStatStatePPID(pid)
		if !ok {
			if procFileReadNonENOENT(d.Proc.File(pid, "stat")) {
				inconclusive = true
			}
			continue
		}
		if ppid != 1 {
			continue
		}
		if state == "X" || state == "x" {
			continue
		}
		var ns, sid string
		var inScope bool
		if state == "D" || state == "Z" {
			// D/Z-state cmdline is mm-backed and would hang on mmap_lock;
			// inspect fd readlinks instead.
			var dzInc bool
			ns, sid, inScope, dzInc = dzShimScopeChecked(d, pid)
			if dzInc {
				inconclusive = true
				continue
			}
		} else {
			argv := d.Proc.Cmdline(pid)
			if len(argv) == 0 {
				if curState, _, sok := d.ProcStatStatePPID(pid); sok {
					if curState == "D" || curState == "Z" {
						var dzInc bool
						ns, sid, inScope, dzInc = dzShimScopeChecked(d, pid)
						if dzInc {
							inconclusive = true
							continue
						}
					} else if curState == "X" || curState == "x" {
						continue
					} else if procFileReadNonENOENT(d.Proc.File(pid, "cmdline")) {
						inconclusive = true
						continue
					}
				} else if procFileReadNonENOENT(d.Proc.File(pid, "stat")) ||
					procFileReadNonENOENT(d.Proc.File(pid, "cmdline")) {
					inconclusive = true
					continue
				}
				if !inScope {
					continue
				}
			} else {
				if !strings.Contains(strings.Join(argv, " "), "containerd-shim-runc-v2") {
					continue
				}
				ns, sid, inScope = ctrShimScope(d, argv)
			}
		}
		if !inScope || ns != "k8s.io" || sid == "" {
			continue
		}
		if d.ProcAge(pid) < ctrMetaOrphanMinAge {
			continue
		}
		dir := shimTaskDir(d, ns, sid)
		fi, err := os.Stat(dir)
		if err != nil {
			if !os.IsNotExist(err) {
				inconclusive = true
			}
			continue // dir gone → wdeps.CheckCtrTasks' orphan-shim path
		}
		if !fi.IsDir() {
			continue
		}
		if d.Cfg.Seams.Host.Clock.Now().Sub(fi.ModTime()) < ctrMetaOrphanMinAge {
			continue
		}
		live, inc := ctrTaskInitStatus(d, dir)
		if inc {
			inconclusive = true
			continue
		}
		if live {
			continue
		}
		n++
	}
	return n, inconclusive
}

// ctrTaskInitLive reports whether the task dir's init.pid names a
// live process — the same liveness rule wdeps.CheckCtrTasks applies.
func ctrTaskInitLive(d *wdeps.Deps, dir string) bool {
	live, _ := ctrTaskInitStatus(d, dir)
	return live
}

// ctrTaskInitStatus distinguishes missing/dead init.pid from non-ENOENT
// read errors (e.g. EACCES/EISDIR) so CtrMetaCheck never treats an
// unreadable init.pid on a healthy container as an orphan shim.
func ctrTaskInitStatus(d *wdeps.Deps, dir string) (live, inconclusive bool) {
	data, err := os.ReadFile(filepath.Join(dir, "init.pid"))
	if err != nil {
		if !os.IsNotExist(err) {
			return false, true
		}
		return false, false
	}
	ipid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || ipid <= 0 {
		return false, false
	}
	return d.PidLive(ipid), false
}

// --- kernel-dmesg consumer: host-level OOM → event + metric ---

// lastHostOOMEventFile dedups SystemOOMVictim events — the marker
// files are cumulative, so "already emitted" is a count/epoch pair.

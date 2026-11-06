// ctr_meta.go — the W10-KR3 containerd meta.db corruption guard
// (split out of the old deep_failure_checks.go): journal-signature
// probe plus the reparented-orphan-shim evidence channel. Shares the
// shim-scope helpers in ctr_tasks.go.
package ctr

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// ctrMetaOrphanMinAge is the "dead for >15m" evidence bar for KR3
// orphan shims — a shim whose init died seconds ago is a normal
// teardown in flight, not corruption.
const ctrMetaOrphanMinAge = 15 * time.Minute

// ctrMetaJournalWindow is the KR3 journal lookback — corruption
// signatures only need the recent window; a stale hit from days ago
// must not latch.
const ctrMetaJournalWindow = "3 minutes ago"

// ctrMetaCorruptRe is the KR3 journal signature set — bbolt/meta.db
// corruption phrases containerd logs when its bolt store won't open.
var ctrMetaCorruptRe = regexp.MustCompile(
	`failed to loadmeta|invalid freelist page|bbolt|meta\.db: Somethings wrong`)

// CtrMetaCheck is the W10-KR3 containerd meta.db corruption
// guard as a Check; it owns the evidence streak
// (ex-Hygiene.ctrMetaFails). Two evidence channels, either
// sufficient for state-containerd-corrupt (KubeletRuntimeStall
// altStateKey — a corrupt store survives k0sworker restarts, so the
// NHC→SNR path needs the latch, not just a restart):
//
//   - journalctl -u k0sworker -u containerd --since "3 minutes ago"
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
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckCtrMeta, "gated").Inc()
		return
	}
	evidence := ""
	journalFn := c.d.Cfg.Ctr.MetaJournalFn
	if journalFn == nil && c.d.Cfg.Systemd != nil {
		journalFn = func(ctx context.Context) (string, error) {
			return c.d.Cfg.Systemd.ExecCombined(ctx, "journalctl",
				"-u", "k0sworker.service", "-u", "containerd.service",
				"--since", ctrMetaJournalWindow, "--no-pager")
		}
	}
	if journalFn != nil {
		out, err := journalFn(ctx)
		if err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: containerd-meta journal probe failed: %v — journal half inconclusive",
				err))
		} else if m := ctrMetaCorruptRe.FindString(out); m != "" {
			evidence = "journal: " + m
		}
	}
	if orphans := countMetaOrphanShims(c.d, e.PidsOnce()); orphans > 0 {
		if evidence != "" {
			evidence += "; "
		}
		evidence += fmt.Sprintf("%d orphan shim(s) ppid=1", orphans)
	}
	if evidence != "" {
		c.fails++
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: containerd meta.db corruption evidence (%s) — run %d/%d",
			evidence, c.fails, c.d.Cfg.ConsecNeeded))
		if c.fails >= c.d.Cfg.ConsecNeeded {
			c.d.State.Enter(hoststate.LatchContainerdCorrupt, evidence)
		}
	} else {
		c.fails = 0
		c.d.State.Exit(hoststate.LatchContainerdCorrupt, nil)
	}
	c.d.Cycles.WithLabelValues(wdeps.CheckCtrMeta, "ok").Inc()
}

// countMetaOrphanShims counts containerd-shim-runc-v2 processes that
// look like meta.db-loss orphans: in-scope for THIS containerd
// (ctrShimScope — never a foreign daemon's shim), reparented to PID
// 1 (containerd forgot them), older than ctrMetaOrphanMinAge, and
// whose k8s.io task dir still exists with a dead/missing init —
// wdeps.CheckCtrTasks owns the missing-dir orphan case and live-init dirs
// are normal tasks, so both are excluded here.
func countMetaOrphanShims(d *wdeps.Deps, pids []int) int {
	n := 0
	for _, pid := range pids {
		argv := d.Proc.Cmdline(pid)
		if len(argv) == 0 ||
			!strings.Contains(strings.Join(argv, " "), "containerd-shim-runc-v2") {
			continue
		}
		ns, sid, inScope := ctrShimScope(d, argv)
		if !inScope || ns != "k8s.io" || sid == "" {
			continue
		}
		_, ppid, ok := d.ProcStatStatePPID(pid)
		if !ok || ppid != 1 {
			continue
		}
		if d.ProcAge(pid) < ctrMetaOrphanMinAge {
			continue
		}
		dir := shimTaskDir(d, ns, sid)
		fi, err := os.Stat(dir)
		if err != nil || !fi.IsDir() {
			continue // dir gone → wdeps.CheckCtrTasks' orphan-shim path
		}
		if d.Cfg.Seams.NowFn().Sub(fi.ModTime()) < ctrMetaOrphanMinAge {
			continue
		}
		if ctrTaskInitLive(d, dir) {
			continue
		}
		n++
	}
	return n
}

// ctrTaskInitLive reports whether the task dir's init.pid names a
// live process — the same liveness rule wdeps.CheckCtrTasks applies.
func ctrTaskInitLive(d *wdeps.Deps, dir string) bool {
	data, err := os.ReadFile(filepath.Join(dir, "init.pid"))
	if err != nil {
		return false
	}
	ipid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || ipid <= 0 {
		return false
	}
	return d.PidLive(ipid)
}

// --- W10-KR1 consumer: host-level OOM → event + metric ---

// lastHostOOMEventFile dedups SystemOOMVictim events — the marker
// files are cumulative, so "already emitted" is a count/epoch pair.

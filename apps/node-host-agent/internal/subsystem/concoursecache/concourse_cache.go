// concourse_cache.go — native Go port of the prune.sh ConfigMap the
// concourse-workdir-janitor component used to run inside every
// concourse-worker pod via pods/exec SPDY
// (infrastructure/components/node-ops/concourse-workdir-janitor/
// script-cm.yaml — deleted by the same change).
//
// node-host-agent already runs on every node with the openebs hostdir
// mounted, so the shared-cache inside each worker PVC —
// <openebsRoot>/pvc-*/shared-cache — is pruned directly on the host:
// no pods/exec grant, no script ConfigMap, no bash inside the worker.
// The caller should schedule Sweep every
// DefaultInterval (15m — tighter than the 30m cadence
// the prune had inside the janitor run).
//
// The bucket rules are the script's 1:1 — same ages, same size caps,
// same dir-first ordering (see pruneSharedCache). Safety notes kept
// from the script:
//   - The ownership/perm invariant is enforced on shared-cache + ONE
//     level only. Files deeper in the tree are always created by uid
//     4294967294 (only unprivileged task containers see /shared-cache),
//     so a recursive chown of ~500k files is wasted I/O.
//   - NEVER touch go-mod/mise/ci-tool — they are scaffolded by
//     init-rm and cost real money to rebuild; the script deliberately
//     had no bucket for them and neither does this port.
//   - Size caps free oldest-first exactly like
//     `find -printf '%T@' | sort -n`; du -sk semantics are kept via
//     allocated blocks (st_blocks), not apparent size.
//
// This file holds the pruner's constants, Config and construction;
// the sweep orchestration lives in sweep.go, the bucket mechanics in
// prune.go and the du/find fs helpers in fsutil.go.
package concoursecache

import (
	"context"
	"os"
	"regexp"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/concourse"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// pvcNameRe is the last-deletion-belt name check — exactly
// pvc-<uuid>, duplicated from sweeper (the orphan-dir sweeper owns
// the same contract). Kept as a copy rather than an exported symbol
// so this package carries no sweeper dependency; the regexp is one
// line and the openebs pvc-* naming convention is stable.
var pvcNameRe = regexp.MustCompile(
	`^pvc-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// DefaultInterval is the cadence the caller should
// schedule — 15m vs the 30m the prune ran inside the janitor.
const DefaultInterval = 15 * time.Minute

// prune.sh constants. Size thresholds were KiB (du -sk); here bytes.
const (
	ccOwner       = concourse.CacheOwner
	ccPerm        = concourse.CachePerm
	ccGoBuildHigh = 15 << 30 // 15728640 KiB
	ccGoBuildLow  = 8 << 30  //  8388608 KiB
	ccBuildHigh   = 4 << 30  //  4194304 KiB
	ccBuildLow    = 2 << 30  //  2097152 KiB
	ccNodeDepsHi  = 6 << 30  //  6291456 KiB
	ccNodeDepsLow = 4 << 30  //  4194304 KiB

	// Filesystem-pressure thresholds (used percent) for the H3 early
	// trigger — see Config.DiskHighPct/DiskCritPct.
	ccDiskHighPct = 75
	ccDiskCritPct = 85
	// ccCritFloorAge bounds the crit escalation: ages collapse to
	// this floor, not 0, so artifacts being written right now
	// (in-flight lock files / staging dirs) survive even a crit
	// prune. The cache is rebuildable — an active install isn't.
	ccCritFloorAge = 5 * time.Minute
)

// Config carries the pruner's knobs — every field maps
// to a prune.sh constant and a zero value falls back to the script
// default, so a bare Config{} IS the production config.
type Config struct {
	// Ownership/perm invariant forced on shared-cache + its first
	// level (chown 4294967294:4294967294, chmod 0777). Set both to -1
	// to skip chown entirely (unprivileged dev runs).
	OwnerUID, OwnerGID int
	Mode               os.FileMode

	GoBuildMaxAge   time.Duration // find -mtime +2
	GoBuildHighMark int64         // du > 15GiB
	GoBuildLowMark  int64         // trim oldest files to <= 8GiB

	ArtifactMaxAge time.Duration // build+coverage -mtime +1
	BuildHighMark  int64         // du > 4GiB
	BuildLowMark   int64         // oldest <key> dirs to <= 2GiB

	StaleMaxAge time.Duration // affected+ytt -mtime +2
	GraphMaxAge time.Duration // nx+moon -mtime +7
	ToolMaxAge  time.Duration // trivy/sonar/… -mtime +14

	NodeDepsDirMaxAge time.Duration // <cksum> dirs -mtime +7
	NodeDepsLockAge   time.Duration // .lock-*/.tmp-*/staging -mmin +60
	NodeDepsHighMark  int64         // du > 6GiB
	NodeDepsLowMark   int64         // oldest <cksum> dirs to <= 4GiB

	// DiskHighPct/DiskCritPct are used-percent thresholds on the
	// filesystem holding a shared-cache — the H3 early trigger. The
	// pressure reading is max(used bytes %, used inodes %): a cache
	// tree of hundreds of thousands of tiny files lands ENOSPC on
	// inode exhaustion while `df` still shows free GBs, so both
	// readings share the one trigger.
	//   >= DiskHighPct: escalate — every age limit halves and the
	//     size caps engage at their LOW marks.
	//   >= DiskCritPct: emergency — every file inside the prunable
	//     buckets is eligible (age limits collapse to 0); the buckets
	//     are all reconstructible caches while a full filesystem
	//     wedges kubelet/containerd outright.
	// A statfs failure fails open to the normal limits — the regular
	// cadence prune is the baseline, escalation is a bonus.
	DiskHighPct, DiskCritPct float64

	// statfsFn reads filesystem stats for the pressure check — seam
	// for tests; nil → syscall.Statfs.
	statfsFn func(path string, st *syscall.Statfs_t) error
	// Clock supplies the current time — the shared timex.Cell seam; nil → system time.
	Clock *timex.Cell
}

func (c *Config) applyDefaults() {
	// -1,-1 opts out of chown; the zero value means the script's
	// 4294967294 — chown to root was never a supported mode.
	if c.OwnerUID == 0 && c.OwnerGID == 0 {
		c.OwnerUID, c.OwnerGID = ccOwner, ccOwner
	}
	if c.Mode == 0 {
		c.Mode = ccPerm
	}
	// find -mtime +N matches floor(age_days) > N, i.e. age >= (N+1)*24h
	// — one day LATER than a naive N*24h read.
	if c.GoBuildMaxAge <= 0 {
		c.GoBuildMaxAge = 72 * time.Hour // -mtime +2
	}
	if c.GoBuildHighMark <= 0 {
		c.GoBuildHighMark = ccGoBuildHigh
	}
	if c.GoBuildLowMark <= 0 {
		c.GoBuildLowMark = ccGoBuildLow
	}
	if c.ArtifactMaxAge <= 0 {
		c.ArtifactMaxAge = 48 * time.Hour // -mtime +1
	}
	if c.BuildHighMark <= 0 {
		c.BuildHighMark = ccBuildHigh
	}
	if c.BuildLowMark <= 0 {
		c.BuildLowMark = ccBuildLow
	}
	if c.StaleMaxAge <= 0 {
		c.StaleMaxAge = 72 * time.Hour // -mtime +2
	}
	if c.GraphMaxAge <= 0 {
		c.GraphMaxAge = 8 * 24 * time.Hour // -mtime +7
	}
	if c.ToolMaxAge <= 0 {
		c.ToolMaxAge = 15 * 24 * time.Hour // -mtime +14
	}
	if c.NodeDepsDirMaxAge <= 0 {
		c.NodeDepsDirMaxAge = 8 * 24 * time.Hour // -mtime +7
	}
	if c.NodeDepsLockAge <= 0 {
		c.NodeDepsLockAge = 61 * time.Minute // -mmin +60
	}
	if c.NodeDepsHighMark <= 0 {
		c.NodeDepsHighMark = ccNodeDepsHi
	}
	if c.NodeDepsLowMark <= 0 {
		c.NodeDepsLowMark = ccNodeDepsLow
	}
	if c.DiskHighPct <= 0 {
		c.DiskHighPct = ccDiskHighPct
	}
	if c.DiskCritPct <= 0 {
		c.DiskCritPct = ccDiskCritPct
	}
	if c.statfsFn == nil {
		c.statfsFn = syscall.Statfs
	}
	if c.Clock == nil {
		c.Clock = timex.NewCell(nil)
	}
}

// Pruner prunes the Concourse shared-cache inside every
// worker PVC — <openebsRoot>/pvc-*/shared-cache — directly on the
// host, the native replacement for exec'ing prune.sh into each pod.
type Pruner struct {
	cfg Config

	cycles       *prometheus.CounterVec // result: ok|abort
	filesDeleted *prometheus.CounterVec // bucket label
	bytesFreed   prometheus.Counter
}

// New returns a pruner and registers its metrics
// on reg — same contract as the orphan sweeper's New.
func New(cfg Config, reg prometheus.Registerer) (*Pruner, error) {
	cfg.applyDefaults()
	p := &Pruner{cfg: cfg}
	p.cycles = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_concourse_cache_cycles_total",
		Help: "Concourse shared-cache prune passes by result (ok|abort).",
	}, []string{"result"})
	p.filesDeleted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_concourse_cache_files_deleted_total",
		Help: "Files removed by the shared-cache pruner, per bucket.",
	}, []string{"bucket"})
	p.bytesFreed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "node_host_agent_concourse_cache_bytes_freed_total",
		Help: "Bytes freed by the shared-cache pruner (file sizes/du).",
	})
	if err := subframe.RegisterAll(reg,
		p.cycles, p.filesDeleted, p.bytesFreed); err != nil {
		return nil, err
	}
	return p, nil
}

// SweepSharedCache runs one prune pass over
// <openebsRoot>/pvc-*/shared-cache with the script defaults — the
// convenience entry point for callers that need no metrics or custom
// thresholds.
func SweepSharedCache(ctx context.Context, openebsRoot string) error {
	p, err := New(Config{}, nil)
	if err != nil {
		return err
	}
	return p.Sweep(ctx, openebsRoot)
}

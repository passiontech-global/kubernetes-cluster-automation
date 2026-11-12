// Package sweeper ports the openebs-orphan-sweeper DaemonSet script
// (passiontech-fluxcd infrastructure/base/node-ops/openebs-orphan-sweeper.yaml)
// 1:1 into Go.
//
// Why it exists: the openebs-hostpath provisioner does NOT remove the
// on-disk data when a PV is deleted under reclaimPolicy=Delete — the PV
// object disappears but /var/openebs/local/pvc-<uid>/ stays forever
// (incident 2026-10-29: ~200G of orphaned work dirs and 742 volumes +
// 634 overlays left on one node, skewing nodefs reporting 62% vs ~10%).
// It must run per-node (the dir is host filesystem) with hostPID so the
// host mount table is visible at /proc/1/mounts.
//
// Case 2 — Released PV still an object: the node-local provisioner is
// responsible for removing the dir + deleting the PV object on
// reclaimPolicy=Delete, but if it died/was evicted mid-flight the
// Released PV lingers with the dir intact. The sweeper takes over: the
// claimRef PVC is already NotFound (Released = PVC deleted; a Released
// PV never rebinds) → strip finalizers, delete the PV object, then the
// normal orphan path below removes the dir. Only ever acts when
// reclaimPolicy=Delete — Retain may be data worth keeping.
//
// SAFETY — fail closed, always. Read carefully before editing:
//   - Only directories matching exactly `pvc-<uuid>` are considered —
//     any other name (quota.lock, hand-made dirs) is skipped.
//   - The PV list is fetched fresh each cycle; an EMPTY list while
//     pvc-* dirs exist on disk is abnormal → ABORT the whole cycle.
//   - The dir must be older than MinAge (60m) — avoids racing PV
//     provisioning.
//   - Before deleting, the PV is re-GET: the dir is removed only on an
//     explicit IsNotFound — a PV that reappeared, or ANY other API
//     error, skips.
//   - MaxDelete bounds destructive ops per cycle — the Released-PV
//     object delete AND the dir rm each spend a slot — caps the
//     damage if the logic is ever wrong.
//   - The host mount table (MountsFile, /proc/1/mounts via hostPID) is
//     checked before rm — snapshotted once per cycle AND re-read
//     immediately before each rm: any mount point at or inside the
//     dir → skip. That is the only reliable --one-file-system guard.
//   - Released PV: deleted only when reclaimPolicy=Delete AND the
//     claimRef PVC is explicitly NotFound — Released+Retain or any API
//     error → skip.
//   - Every decision (DELETE/SKIP/ABORT) is logged.
package sweeper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/nodecoord"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// pvcNameRe is the last-deletion-belt name check — exactly pvc-<uuid>,
// matching the shell version's grep -Eq pattern.
var pvcNameRe = regexp.MustCompile(
	`^pvc-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Default values mirror the DaemonSet env defaults. The base-dir
// default is envnames.DefaultSweepBaseDir — shared with
// concoursecache since both read EnvSweepBaseDir.
const (
	defaultMinAge         = 60 * time.Minute
	defaultMaxDelete      = 10
	defaultInterval       = time.Hour
	defaultMountsFile     = "/proc/1/mounts"
	defaultRequestTimeout = 30 * time.Second
)

// Skip reasons (Prometheus label values). One label per distinct
// fail-closed bail-out so a stuck skip reason is visible in metrics
// instead of only in logs.
const (
	skipNameMismatch    = "name_mismatch"     // not pvc-<uuid>
	skipTooYoung        = "too_young"         // dir younger than MinAge
	skipPVInUse         = "pv_in_use"         // PV exists, not Released+Delete
	skipClaimRefUnclear = "claimref_unclear"  // Released PV, claimRef PVC not clearly gone
	skipPVPatchFailed   = "pv_patch_failed"   // finalizer strip failed
	skipPVDeleteFailed  = "pv_delete_failed"  // PV delete call failed
	skipPVStillPresent  = "pv_still_present"  // re-GET succeeded — PV back
	skipPVGetError      = "pv_get_error"      // re-GET errored, not a clean NotFound
	skipMounted         = "mounted"           // host mount inside dir
	skipStatError       = "stat_error"        // os.Stat/Info failed — treated like too young
	skipMountsUnread    = "mounts_unreadable" // host mount table unreadable
)

// Config carries the sweeper's knobs — all test-injectable.
type Config struct {
	// Base is the shared watchdog-subsystem block — only the sweep
	// cadence and the clock cell are consumed (subframe.FromDeps);
	// the rest of the block is carried but unused — the sweeper
	// touches no watchdog state, systemd or conf.
	subframe.Base
	BaseDir        string // host dir holding pvc-* volumes
	MinAge         time.Duration
	MaxDelete      int
	MountsFile     string        // host mount table (/proc/1/mounts under hostPID)
	RequestTimeout time.Duration // per-call apiserver deadline
	Client         kubernetes.Interface
	// Coord is the L1↔L3 coordination handle (platform/nodecoord) —
	// nil disables the maintenance hold (tests, minimal wiring).
	// When set, Sweep consults HoldLocalAction before the
	// destructive half: a cluster upgrade / kured drain stamps
	// AnnoClusterMaintenanceUntil and L1 must not delete volumes
	// mid-migration.
	Coord *nodecoord.Coord

	// statfsFn measures used bytes on the BaseDir filesystem — seam for
	// tests; nil → syscall.Statfs.
	statfsFn func(path string) (uint64, error)
}

// applyDefaults fills zero-valued knobs with the production defaults.
func (c *Config) applyDefaults() {
	if c.BaseDir == "" {
		c.BaseDir = envnames.DefaultSweepBaseDir
	}
	// A trailing "/" would defeat the mount-boundary string compare
	// (mount table entries are canonical paths).
	c.BaseDir = strings.TrimRight(c.BaseDir, "/")
	if c.MinAge <= 0 {
		c.MinAge = defaultMinAge
	}
	if c.MaxDelete <= 0 {
		c.MaxDelete = defaultMaxDelete
	}
	if c.Interval <= 0 {
		c.Interval = defaultInterval
	}
	if c.MountsFile == "" {
		c.MountsFile = defaultMountsFile
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = defaultRequestTimeout
	}
	if c.statfsFn == nil {
		c.statfsFn = usedBytes
	}
	if c.Clock == nil {
		c.Clock = timex.NewCell(nil)
	}
}

// Sweeper runs the periodic orphan-dir cleanup.
type Sweeper struct {
	cfg Config

	cycles       *prometheus.CounterVec // result: ok|abort
	dirsDeleted  prometheus.Counter
	bytesFreed   prometheus.Counter
	skips        *prometheus.CounterVec // reason label
	dirsExamined prometheus.Gauge
	duration     prometheus.Gauge
}

// New returns a Sweeper and registers its metrics on reg.
func New(cfg Config, reg prometheus.Registerer) (*Sweeper, error) {
	// A nil Client only surfaces as a panic on the first PV List —
	// fail at construction instead.
	if cfg.Client == nil {
		return nil, errors.New("sweeper: Config.Client is required")
	}
	cfg.applyDefaults()
	s := &Sweeper{cfg: cfg}

	s.cycles = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_sweeper_cycles_total",
		Help: "Sweeper cycles by result (ok|abort).",
	}, []string{"result"})
	s.dirsDeleted = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "node_host_agent_sweeper_dirs_deleted_total",
		Help: "Orphan pvc-* host directories removed.",
	})
	s.bytesFreed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "node_host_agent_sweeper_bytes_freed_total",
		Help: "Filesystem bytes freed, measured via statfs before/after rm.",
	})
	s.skips = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_sweeper_skips_total",
		Help: "Candidate dirs skipped, by fail-closed reason.",
	}, []string{"reason"})
	s.dirsExamined = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_sweeper_dirs_examined",
		Help: "pvc-* candidate dirs seen in the last cycle.",
	})
	s.duration = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_sweeper_cycle_duration_seconds",
		Help: "Duration of the last sweep cycle.",
	})

	if err := subframe.RegisterAll(reg,
		s.cycles, s.dirsDeleted, s.bytesFreed, s.skips, s.dirsExamined,
		s.duration); err != nil {
		return nil, fmt.Errorf("register sweeper metrics: %w", err)
	}
	return s, nil
}

// Name identifies the subsystem for logging.
func (s *Sweeper) Name() string { return "sweeper" }

// Run sweeps immediately, then every Interval until ctx is cancelled.
// Matches the shell loop: first sweep at pod start, then sleep.
func (s *Sweeper) Run(ctx context.Context) {
	cycle.Every("sweeper", s.cfg.Interval, s.Sweep).Run(ctx)
}

// usedBytes reports used bytes on the filesystem holding path via
// syscall.Statfs — the same value `df -k` reports (blocks - bfree).
func usedBytes(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return (st.Blocks - st.Bfree) * uint64(st.Bsize), nil
}

// listPVDirs returns directory names under BaseDir starting with "pvc-"
// — the same set the shell glob "$BASE"/pvc-* yields (dirs only).
func (s *Sweeper) listPVDirs() ([]os.DirEntry, error) {
	entries, err := os.ReadDir(s.cfg.BaseDir)
	if err != nil {
		return nil, err
	}
	var dirs []os.DirEntry
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "pvc-") {
			dirs = append(dirs, e)
		}
	}
	return dirs, nil
}

// mountPoints reads + parses the host mount table (MountsFile —
// /proc/1/mounts under hostPID) once per sweep: the
// rm --one-file-system guard below used to re-read and re-parse it
// for every candidate dir.
func (s *Sweeper) mountPoints() ([]string, error) {
	data, err := os.ReadFile(s.cfg.MountsFile)
	if err != nil {
		return nil, err
	}
	var mounts []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		mounts = append(mounts, unescapeMountField(fields[1]))
	}
	return mounts, nil
}

// mountedInside reports whether any mount point in the parsed host
// mount table sits at or inside dir — the rm --one-file-system
// guard. dir is normalized first: a pod-mode SWEEP_BASE_DIR carries
// the /host hostRoot prefix while /proc/1/mounts speaks HOST paths;
// comparing them un-normalized makes the guard silently miss every
// live mount (and rm straight through its contents).
func mountedInside(dir string, mounts []string) bool {
	dir = fsx.HostSidePath(dir)
	for _, mp := range mounts {
		if mp == dir || strings.HasPrefix(mp, dir+"/") {
			return true
		}
	}
	return false
}

// unescapeMountField decodes the octal escapes /proc/*/mounts applies
// to mount paths (space→\040, tab→\011, newline→\012, backslash→\134).
func unescapeMountField(s string) string {
	r := strings.NewReplacer(
		`\134`, `\`,
		`\040`, " ",
		`\011`, "\t",
		`\012`, "\n",
	)
	return r.Replace(s)
}

// apiCtx returns a per-call apiserver context with RequestTimeout —
// like kubectl --request-timeout, so a hung API call can't stall the
// loop forever.
func (s *Sweeper) apiCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, s.cfg.RequestTimeout)
}

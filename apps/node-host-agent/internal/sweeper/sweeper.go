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
//   - MaxDelete bounds deletions per cycle — caps the damage if the
//     logic is ever wrong.
//   - The host mount table (MountsFile, /proc/1/mounts via hostPID) is
//     checked before rm: any mount point at or inside the dir → skip.
//     That is the only reliable --one-file-system guard.
//   - Released PV: deleted only when reclaimPolicy=Delete AND the
//     claimRef PVC is explicitly NotFound — Released+Retain or any API
//     error → skip.
//   - Every decision (DELETE/SKIP/ABORT) is logged.
package sweeper

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// pvcNameRe is the last-deletion-belt name check — exactly pvc-<uuid>,
// matching the shell version's grep -Eq pattern.
var pvcNameRe = regexp.MustCompile(
	`^pvc-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Default values mirror the DaemonSet env defaults.
const (
	defaultBaseDir        = "/var/openebs/local"
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
	BaseDir        string // host dir holding pvc-* volumes
	MinAge         time.Duration
	MaxDelete      int
	Interval       time.Duration
	MountsFile     string        // host mount table (/proc/1/mounts under hostPID)
	RequestTimeout time.Duration // per-call apiserver deadline
	Client         kubernetes.Interface

	// statfsFn measures used bytes on the BaseDir filesystem — seam for
	// tests; nil → syscall.Statfs.
	statfsFn func(path string) (uint64, error)
	// nowFn supplies the current time — seam for tests; nil → time.Now.
	nowFn func() time.Time
}

// applyDefaults fills zero-valued knobs with the production defaults.
func (c *Config) applyDefaults() {
	if c.BaseDir == "" {
		c.BaseDir = defaultBaseDir
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
	if c.nowFn == nil {
		c.nowFn = time.Now
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

	if reg != nil {
		for _, c := range []prometheus.Collector{
			s.cycles, s.dirsDeleted, s.bytesFreed, s.skips, s.dirsExamined, s.duration,
		} {
			if err := reg.Register(c); err != nil {
				return nil, fmt.Errorf("register sweeper metrics: %w", err)
			}
		}
	}
	return s, nil
}

// Name identifies the subsystem for logging.
func (s *Sweeper) Name() string { return "sweeper" }

// Run sweeps immediately, then every Interval until ctx is cancelled.
// Matches the shell loop: first sweep at pod start, then sleep.
func (s *Sweeper) Run(ctx context.Context) {
	s.Sweep(ctx)
	t := time.NewTicker(s.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Sweep(ctx)
		}
	}
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

// mountedInside reports whether any mount point in the host mount table
// sits at or inside dir — the rm --one-file-system guard.
func (s *Sweeper) mountedInside(dir string) (bool, error) {
	data, err := os.ReadFile(s.cfg.MountsFile)
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		mp := unescapeMountField(fields[1])
		if mp == dir || strings.HasPrefix(mp, dir+"/") {
			return true, nil
		}
	}
	return false, nil
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

// Sweep executes one cleanup cycle. All fail-closed decisions are
// counted under skips{reason} and logged; the cycle result lands on
// cycles{result}.
func (s *Sweeper) Sweep(ctx context.Context) {
	log := slog.With("subsystem", "sweeper")
	start := s.cfg.nowFn()
	defer func() { s.duration.Set(s.cfg.nowFn().Sub(start).Seconds()) }()

	fi, err := os.Stat(s.cfg.BaseDir)
	if err != nil || !fi.IsDir() {
		log.Info("skip cycle: base dir absent", "base", s.cfg.BaseDir)
		s.cycles.WithLabelValues("ok").Inc()
		return
	}

	uStart, err := s.cfg.statfsFn(s.cfg.BaseDir)
	if err == nil {
		log.Info("nodefs used before sweep", "gib", float64(uStart)/(1<<30))
	}

	// PV list once per cycle. An empty list while pvc-* dirs exist on
	// disk is abnormal → ABORT the whole cycle (fail closed).
	dirs, err := s.listPVDirs()
	if err != nil {
		log.Error("ABORT: cannot list base dir", "error", err)
		s.cycles.WithLabelValues("abort").Inc()
		return
	}
	if len(dirs) == 0 {
		// No pvc-* candidates on disk → nothing can match a PV, so
		// skip the whole-cluster PV list entirely (the common case:
		// orphan dirs are the exception, not the norm).
		s.dirsExamined.Set(0)
		s.cycles.WithLabelValues("ok").Inc()
		log.Info("sweep done", "dirs", 0, "deleted", 0)
		return
	}
	apiCtx, cancel := s.apiCtx(ctx)
	pvList, err := s.cfg.Client.CoreV1().PersistentVolumes().
		List(apiCtx, metav1.ListOptions{})
	cancel()
	if err != nil {
		log.Error("ABORT: cannot list PVs", "error", err)
		s.cycles.WithLabelValues("abort").Inc()
		return
	}
	if len(pvList.Items) == 0 && len(dirs) > 0 {
		log.Error("ABORT: pvlist empty but pvc-* dirs exist — suspected API error",
			"dirs", len(dirs))
		s.cycles.WithLabelValues("abort").Inc()
		return
	}
	pvByName := make(map[string]*corev1.PersistentVolume, len(pvList.Items))
	for i := range pvList.Items {
		pvByName[pvList.Items[i].Name] = &pvList.Items[i]
	}

	ndel := 0
	ndir := 0
	for _, d := range dirs {
		if ctx.Err() != nil {
			return
		}
		ndir++
		name := d.Name()
		// Name must be exactly pvc-<uuid> — the last deletion belt.
		if !pvcNameRe.MatchString(name) {
			log.Info("SKIP: not a pvc-<uuid> name", "dir", name)
			s.skips.WithLabelValues(skipNameMismatch).Inc()
			continue
		}
		pv, pvPresent := pvByName[name]

		// Dir must be older than MinAge — avoids racing PV provisioning.
		info, err := d.Info()
		if err != nil {
			log.Info("SKIP: stat failed", "dir", name, "error", err)
			s.skips.WithLabelValues(skipStatError).Inc()
			continue
		}
		if s.cfg.nowFn().Sub(info.ModTime()) <= s.cfg.MinAge {
			log.Info("SKIP: younger than min age", "dir", name,
				"minAge", s.cfg.MinAge.String())
			s.skips.WithLabelValues(skipTooYoung).Inc()
			continue
		}

		if pvPresent {
			// PV object still exists — only Released+Delete is an
			// orphan (provisioner died mid-flight, incident 2026-10-29).
			// Bound/Available/Retain → dir in use or owned data, skip.
			if pv.Status.Phase != corev1.VolumeReleased ||
				pv.Spec.PersistentVolumeReclaimPolicy != corev1.PersistentVolumeReclaimDelete {
				s.skips.WithLabelValues(skipPVInUse).Inc()
				continue
			}
			// Released = PVC deleted — verify claimRef PVC is
			// explicitly NotFound before acting (any API error → skip).
			var cns, cname string
			if pv.Spec.ClaimRef != nil {
				cns = pv.Spec.ClaimRef.Namespace
				cname = pv.Spec.ClaimRef.Name
			}
			if cns != "" && cname != "" {
				apiCtx, cancel := s.apiCtx(ctx)
				_, err := s.cfg.Client.CoreV1().PersistentVolumeClaims(cns).
					Get(apiCtx, cname, metav1.GetOptions{})
				cancel()
				switch {
				case apierrors.IsNotFound(err):
					// claimRef clearly gone — proceed.
				case err == nil:
					log.Info("SKIP: PV Released but claimRef PVC still exists",
						"dir", name, "pvc", cns+"/"+cname)
					s.skips.WithLabelValues(skipClaimRefUnclear).Inc()
					continue
				default:
					log.Info("SKIP: PV Released but claimRef PVC not clearly gone",
						"dir", name, "pvc", cns+"/"+cname, "error", err)
					s.skips.WithLabelValues(skipClaimRefUnclear).Inc()
					continue
				}
			}
			// A Released PV can hold the pv-protection finalizer when
			// the provisioner was evicted at the wrong moment — strip,
			// then delete; the re-GET below returns NotFound → rm dir.
			log.Info("PV Released+Delete, claimRef gone — deleting PV object",
				"pv", name, "pvc", orDash(cns)+"/"+orDash(cname))
			apiCtx, cancel := s.apiCtx(ctx)
			_, err = s.cfg.Client.CoreV1().PersistentVolumes().Patch(apiCtx, name,
				types.MergePatchType,
				[]byte(`{"metadata":{"finalizers":null}}`),
				metav1.PatchOptions{})
			cancel()
			if err != nil {
				log.Info("SKIP: patch finalizers failed", "dir", name, "error", err)
				s.skips.WithLabelValues(skipPVPatchFailed).Inc()
				continue
			}
			apiCtx, cancel = s.apiCtx(ctx)
			err = s.cfg.Client.CoreV1().PersistentVolumes().
				Delete(apiCtx, name, metav1.DeleteOptions{})
			cancel()
			if err != nil {
				log.Info("SKIP: delete pv failed", "dir", name, "error", err)
				s.skips.WithLabelValues(skipPVDeleteFailed).Inc()
				continue
			}
		}

		// Re-check: delete only on an explicit NotFound — a PV that
		// reappeared or ANY other API error → skip.
		apiCtx, cancel = s.apiCtx(ctx)
		_, err = s.cfg.Client.CoreV1().PersistentVolumes().
			Get(apiCtx, name, metav1.GetOptions{})
		cancel()
		if err == nil {
			s.skips.WithLabelValues(skipPVStillPresent).Inc()
			continue
		}
		if !apierrors.IsNotFound(err) {
			log.Info("SKIP: get pv error, not a clear NotFound",
				"dir", name, "error", err)
			s.skips.WithLabelValues(skipPVGetError).Inc()
			continue
		}

		if ndel >= s.cfg.MaxDelete {
			log.Info("STOP: cap MAX_DELETE reached", "maxDelete", s.cfg.MaxDelete)
			break
		}

		// Mount-boundary guard: any mount point at or inside the dir →
		// never remove. An unreadable mount table fails closed too.
		dirPath := s.cfg.BaseDir + "/" + name
		mounted, err := s.mountedInside(dirPath)
		if err != nil {
			log.Info("SKIP: cannot read host mount table",
				"dir", name, "error", err)
			s.skips.WithLabelValues(skipMountsUnread).Inc()
			continue
		}
		if mounted {
			log.Info("SKIP: mount found inside dir", "dir", name)
			s.skips.WithLabelValues(skipMounted).Inc()
			continue
		}

		u0, _ := s.cfg.statfsFn(s.cfg.BaseDir)
		log.Info("DELETE: PV absent, dir older than min age",
			"dir", dirPath, "pv", name)
		if err := os.RemoveAll(dirPath); err != nil {
			log.Error("rm dir failed", "dir", name, "error", err)
			continue
		}
		ndel++
		s.dirsDeleted.Inc()
		u1, err := s.cfg.statfsFn(s.cfg.BaseDir)
		if err == nil && u1 < u0 {
			freed := u0 - u1
			s.bytesFreed.Add(float64(freed))
			log.Info("dir removed", "dir", name, "freedGiB", float64(freed)/(1<<30))
		}
	}

	s.dirsExamined.Set(float64(ndir))
	s.cycles.WithLabelValues("ok").Inc()
	uEnd, err := s.cfg.statfsFn(s.cfg.BaseDir)
	if err == nil {
		log.Info("sweep done", "dirs", ndir, "deleted", ndel,
			"nodefsGiB_before", float64(uStart)/(1<<30),
			"nodefsGiB_after", float64(uEnd)/(1<<30))
		return
	}
	log.Info("sweep done", "dirs", ndir, "deleted", ndel)
}

func orDash(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

// etcdguard.go — embedded-etcd quota self-defence:
//
//	The cicd cluster runs k0s embedded etcd; it once hit the
//	backend quota (mvcc: database space exceeded — runbook
//	k0s-etcd-rescue-runbook.md) while the remedy (eventpurge +
//	compact + defrag + alarm disarm) sat behind manual CLI
//	commands. The guard automates that: every cycle on hosts
//	whose K0sDir carries bin/etcdctl + pki/etcd/ca.crt (kine
//	hosts have neither and no-op silently) it reads
//	`endpoint status -w json` — plus `alarm list` while under
//	the size trigger — and exports the db-size / nospace gauges.
//	A NOSPACE alarm or dbSize >= EtcdDBSizeLimit spends the
//	last-etcd-guard budget (EtcdGuardMinRun, 1h) on eventpurge.Run
//	+ etcdmaint.Run with OnlineOnly, all inside a bounded ctx —
//	the offline defrag stops k0scontroller and is NEVER a
//	background action.
package etcd

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/etcdmaint"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/eventpurge"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

// GuardCheck is the embedded-etcd quota self-defence as a
// Check — stateless: the eventpurge+rescue cadence lives in the
// last-etcd-guard budget.
type GuardCheck struct {
	d *cdeps.Deps
}

// Name returns the check label / log context.
func (c *GuardCheck) Name() string { return cdeps.CheckEtcd }

// Run executes one etcdguard cycle.
func (c *GuardCheck) Run(ctx context.Context) {
	if _, err := os.Stat(filepath.Join(c.d.Cfg.K0sDir, "bin", "etcdctl")); err != nil {
		c.d.Cycles.WithLabelValues(cdeps.CheckEtcd, "no_etcdctl").Inc()
		return
	}
	if _, err := os.Stat(filepath.Join(c.d.Cfg.K0sDir,
		"pki", "etcd", "ca.crt")); err != nil {
		c.d.Cycles.WithLabelValues(cdeps.CheckEtcd, "no_etcd_pki").Inc()
		return
	}
	// backup-health: the snapshot verifier rides this embedded-etcd
	// gate — a controller with no local etcd has no snapshot
	// dirs to verify.
	c.VerifySnapshots()

	dbSize, dbUse, err := c.etcdStatus(ctx)
	if err != nil {
		// etcd unreachable — nothing measurable; the wedge/feeder
		// guards own the control-plane-down story.
		c.d.State.AppendLogWarn(fmt.Sprintf(
			"etcdguard: endpoint status failed (endpoint=%s): %v — quota check skipped",
			c.d.Cfg.EtcdGuard.Endpoint, err))
		c.d.Cycles.WithLabelValues(cdeps.CheckEtcd, "status_error").Inc()
		return
	}
	c.d.EtcdDBSize.Set(float64(dbSize))
	c.d.EtcdDBUse.Set(float64(dbUse))

	// The alarm-list probe only runs while dbSize is below the
	// trigger: over-limit the action decision is already made, so a
	// second etcdctl would only double the routine probe cost —
	// against a hung etcd each call can burn its whole command
	// timeout. A skipped probe leaves the nospace gauge at its last
	// value, the same "keep last, never force-clear a
	// possibly-armed alarm" semantics as a probe error.
	var nospace bool
	if dbSize < c.d.Cfg.EtcdGuard.DBSizeLimit {
		ns, aerr := c.etcdNospaceArmed(ctx)
		if aerr != nil {
			// A failed alarm read must not hide a real alarm —
			// treat the size signal as authoritative this cycle,
			// surface the error once in the log, and LEAVE the
			// gauge at its last value.
			c.d.State.AppendLogWarn(fmt.Sprintf("etcdguard: alarm list failed: %v", aerr))
		} else if ns {
			nospace = true
			c.d.EtcdNospace.Set(1)
		} else {
			c.d.EtcdNospace.Set(0)
		}
	}

	var reason string
	switch {
	case nospace:
		reason = "nospace-alarm"
	case dbSize >= c.d.Cfg.EtcdGuard.DBSizeLimit:
		reason = fmt.Sprintf("dbSize=%d>=%d", dbSize, c.d.Cfg.EtcdGuard.DBSizeLimit)
	default:
		c.d.Cycles.WithLabelValues(cdeps.CheckEtcd, "ok").Inc()
		return
	}

	if !c.d.State.RateOK(cdeps.FileRateEtcdGuard,
		c.d.Cfg.EtcdGuard.MinRun) {
		c.d.State.SuspectLog(cdeps.CheckEtcd, fmt.Sprintf(
			"etcdguard: %s but in guard cooldown (<%dm), skip",
			reason, int(c.d.Cfg.EtcdGuard.MinRun.Minutes())),
			c.d.Cfg.SuspectLogCadence)
		c.d.Cycles.WithLabelValues(cdeps.CheckEtcd, "cooldown").Inc()
		return
	}
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: etcdguard %s — evpurge stale events + ONLINE-ONLY "+
			"etcd rescue (offline defrag forbidden)", reason))
	// Budget spent before the action — a kill mid-rescue must not
	// allow a second run inside the window (feeder G6 parity).
	c.d.State.RateSpend(cdeps.FileRateEtcdGuard)
	out := &guardLogWriter{d: c.d}

	// The whole remediation runs under a bounded ctx: eventpurge is
	// unbounded pagination + delete work against a possibly
	// degraded apiserver and the rescue is ~12 sequential etcdctl
	// calls — on the process-lifetime ctx either could stall this
	// (synchronous) cycle for hours. Both steps are idempotent and
	// the rate budget was already spent, so exhausting the deadline
	// only defers the remainder to the next EtcdGuardMinRun window.
	gctx, gcancel := context.WithTimeout(ctx, cdeps.DefaultEtcdGuardBudget)
	defer gcancel()

	// Pre-maintenance snapshot: the online compact+defrag rewrites
	// the backend db — without a verified fresh snapshot in
	// EtcdBackupDir a defrag fault is unrecoverable on a
	// single-member etcd. Rate-limited to once per hour; a failed
	// save or an invalid snapshot aborts the whole remediation —
	// keep last-good, retry at the next guard window.
	if !c.savePreMaintSnapshot(gctx) {
		c.d.Cycles.WithLabelValues(cdeps.CheckEtcd, "snapshot_error").Inc()
		return
	}

	// Stale apiserver events are the classic quota-filler after a
	// control-plane outage — purge first so the rescue's compaction
	// has garbage to drop. Cutoff keeps the apiserver's own 1h event
	// TTL: only GC debt is deleted, fresh events survive.
	perr := c.d.Cfg.EvpurgeRunFn(gctx, eventpurge.Config{
		API:      "https://" + c.d.Cfg.Hub.SelfEndpoint,
		CAFile:   c.d.Cfg.AdminCA,
		CertFile: c.d.Cfg.AdminCert,
		KeyFile:  c.d.Cfg.AdminKey,
	}, c.d.Cfg.Clock.Now().Add(-cdeps.EventStaleAge), out)
	out.flush()
	if perr != nil {
		// Logged on its own — a purge miss does NOT fail the cycle
		// when the quota-remediating step still lands below.
		c.d.State.AppendLogWarn(fmt.Sprintf("etcdguard: evpurge failed: %v", perr))
	}
	// remediated tracks the step that actually relieves the quota:
	// the online rescue (compact+defrag). eventpurge only drops event
	// GC debt so the rescue has garbage to free — when the rescue
	// ran, its result IS the verdict, even if eventpurge failed
	// upstream (the purge failure stays logged above either way).
	var remediated bool
	// A dead gctx here means eventpurge (or a cancelled parent) ate
	// the whole budget — spawn no further calls that can only fail;
	// the rescue is idempotent and retries in the next window.
	if gctx.Err() == nil {
		rerr := c.d.Cfg.EtcdRescueFn(gctx, etcdmaint.Config{
			K0sDir:   c.d.Cfg.K0sDir,
			Endpoint: c.d.Cfg.EtcdGuard.Endpoint,
			// OnlineOnly: this is background auto-maintenance — the
			// systemctl-stop + standalone-etcd defrag would take the
			// control plane down and stays a manual rescue-etcd
			// action.
			OnlineOnly: true,
			// The guard is a loop, not an operator: cap each spawned
			// command far below etcdmaint's interactive default
			// (defaultCallTimeout = 10m) so ~12 sequential calls
			// stay near the guard budget instead of ~2h.
			CallTimeout: cdeps.DefaultEtcdGuardCallTimeout,
		}, out)
		out.flush()
		if rerr != nil {
			c.d.State.AppendLogWarn(fmt.Sprintf("etcdguard: rescue incomplete: %v", rerr))
		}
		remediated = rerr == nil
	} else {
		// The budget died inside eventpurge — the rescue never ran,
		// so the cycle is incomplete, not a clean ok.
		remediated = false
	}
	if errors.Is(gctx.Err(), context.DeadlineExceeded) {
		c.d.State.AppendLogWarn(fmt.Sprintf(
			"etcdguard: run budget (%s) exhausted — remaining steps "+
				"deferred to the next %s window",
			cdeps.DefaultEtcdGuardBudget, c.d.Cfg.EtcdGuard.MinRun))
	}
	c.d.Actions.WithLabelValues(cdeps.CheckEtcd, "evpurge_rescue").Inc()
	if remediated {
		c.d.Cycles.WithLabelValues(cdeps.CheckEtcd, "ok").Inc()
	} else {
		c.d.Cycles.WithLabelValues(cdeps.CheckEtcd, "remediate_error").Inc()
	}
}

// etcdPreMaintSnapInterval caps the pre-maintenance snapshot cadence
// — one `etcdctl snapshot save` per hour (the guard itself is
// hourly, so this usually bounds one save per remediation window).
const etcdPreMaintSnapInterval = time.Hour

// etcdPremaintMinFreeRatio — snapshot creation requires this much
// free on the backup filesystem when no previous premaint snapshot
// pins a byte estimate (parity with the kine backup verifier's
// >30%-free gate: a full disk must not make it worse).
const etcdPremaintMinFreeRatio = 0.30

// etcdPremaintKeep is the premaint-*.db retention bound under
// EtcdBackupDir — the newest two cover the last two remediation
// windows.
const etcdPremaintKeep = 2

// premaintSnapshots returns the premaint-*.db snapshots under dir,
// newest first by the name's unix timestamp (files without a
// parsable stamp sort last).
func premaintSnapshots(dir string) []string {
	m, err := filepath.Glob(filepath.Join(dir, "premaint-*.db"))
	if err != nil {
		return nil
	}
	ts := func(p string) int64 {
		base := filepath.Base(p)
		n, err := strconv.ParseInt(
			strings.TrimSuffix(strings.TrimPrefix(base, "premaint-"), ".db"), 10, 64)
		if err != nil {
			return -1
		}
		return n
	}
	slices.SortFunc(m, func(a, b string) int { return cmp.Compare(ts(b), ts(a)) })
	return m
}

// savePreMaintSnapshot captures a verified etcd snapshot into
// EtcdBackupDir BEFORE the guard's online compact+defrag: the defrag
// rewrites the backend db, so a failed/empty snapshot means no
// rollback point on a single-member etcd and the remediation must
// NOT proceed. true when a fresh valid snapshot exists (either just
// saved this window or a previous premaint snapshot that still
// passes `snapshot status`). The budget spends on the ATTEMPT — a
// failing save retries no more than once per window. A statfs
// headroom gate (kine backup parity) refuses to write onto a nearly
// full backup fs: free >= 1.1x the newest existing snapshot's size,
// else the 30%-free ratio. After a successful save all but the
// newest etcdPremaintKeep premaint snapshots are pruned.
func (c *GuardCheck) savePreMaintSnapshot(ctx context.Context) bool {
	d := c.d
	if err := os.MkdirAll(d.Cfg.EtcdBackupDir, 0o700); err != nil {
		d.State.AppendLogWarn(fmt.Sprintf(
			"etcdguard: pre-maintenance snapshot dir %s: %v — compact+defrag aborted",
			d.Cfg.EtcdBackupDir, err))
		return false
	}
	// Headroom gate before every attempt — the incoming save tracks
	// the live db size, which the newest existing snapshot estimates.
	freeB, totalB, ferr := d.Cfg.StatFSFn(d.Cfg.EtcdBackupDir)
	if ferr != nil {
		d.State.AppendLogWarn(fmt.Sprintf(
			"etcdguard: pre-maintenance snapshot statfs %s: %v — compact+defrag aborted",
			d.Cfg.EtcdBackupDir, ferr))
		return false
	}
	prev := premaintSnapshots(d.Cfg.EtcdBackupDir)
	var need int64
	if len(prev) > 0 {
		if fi, err := os.Stat(prev[0]); err == nil && fi.Size() > 0 {
			need = fi.Size() + fi.Size()/10 // 1.1x
		}
	}
	if need == 0 {
		need = int64(etcdPremaintMinFreeRatio * float64(totalB))
	}
	if freeB < need {
		d.State.AppendLogWarn(fmt.Sprintf(
			"etcdguard: backup fs low on space (free=%d need=%d) — snapshot skipped, compact+defrag aborted",
			freeB, need))
		return false
	}
	if d.State.RateOK(cdeps.FileRateEtcdPreMaintSnap, etcdPreMaintSnapInterval) {
		name := filepath.Join(d.Cfg.EtcdBackupDir, fmt.Sprintf(
			"premaint-%d.db", d.Cfg.Clock.Now().Unix()))
		d.State.RateSpend(cdeps.FileRateEtcdPreMaintSnap)
		if _, err := d.Cfg.EtcdctlFn(ctx, "snapshot", "save", name); err != nil {
			d.State.AppendLogWarn(fmt.Sprintf(
				"etcdguard: pre-maintenance snapshot save failed: %v — compact+defrag aborted", err))
			return false
		}
		// Verify what was actually written — etcdctl can exit 0 on a
		// truncated stream. `snapshot status` parses the file; the
		// size check catches a zero-byte artifact either way.
		if fi, err := os.Stat(name); err != nil || fi.Size() == 0 {
			d.State.AppendLogWarn(fmt.Sprintf(
				"etcdguard: pre-maintenance snapshot %s missing/empty — compact+defrag aborted", name))
			return false
		}
		if _, err := d.Cfg.EtcdctlFn(ctx, "snapshot", "status", name); err != nil {
			d.State.AppendLogWarn(fmt.Sprintf(
				"etcdguard: pre-maintenance snapshot %s failed verification: %v — compact+defrag aborted",
				name, err))
			return false
		}
		d.State.AppendLog(
			"ACTION: etcdguard pre-maintenance snapshot saved to " + name)
		d.Actions.WithLabelValues(cdeps.CheckEtcd, "premaint_snapshot").Inc()
		// Retention: one fresh dump per remediation window with no
		// expiry would fill the backup fs — keep only the newest two.
		if n := prunePremaint(d.Cfg.EtcdBackupDir); n > 0 {
			d.State.AppendLog(fmt.Sprintf(
				"etcdguard: pruned %d old pre-maintenance snapshots", n))
		}
		return true
	}
	// Inside the hourly budget — the snapshot from the current window
	// is fresh enough; confirm the NEWEST premaint snapshot is still
	// present, non-empty AND passes `snapshot status` before letting
	// the destructive half run (a concurrent cleaner could have
	// wiped or truncated it — any non-empty file under the dir is no
	// proof of a usable rollback point).
	if len(prev) == 0 {
		d.State.AppendLogWarn(
			"etcdguard: no premaint-*.db snapshot under " + d.Cfg.EtcdBackupDir +
				" — compact+defrag aborted")
		return false
	}
	newest := prev[0]
	if fi, err := os.Stat(newest); err != nil || fi.Size() == 0 {
		d.State.AppendLogWarn(fmt.Sprintf(
			"etcdguard: pre-maintenance snapshot %s missing/empty — compact+defrag aborted", newest))
		return false
	}
	if _, err := d.Cfg.EtcdctlFn(ctx, "snapshot", "status", newest); err != nil {
		d.State.AppendLogWarn(fmt.Sprintf(
			"etcdguard: pre-maintenance snapshot %s failed verification: %v — compact+defrag aborted",
			newest, err))
		return false
	}
	return true
}

// prunePremaint deletes all but the newest etcdPremaintKeep
// premaint-*.db snapshots under dir — oldest first by name — and
// returns how many were removed. Best-effort: an unremovable file is
// skipped, never fatal to the guard.
func prunePremaint(dir string) int {
	snaps := premaintSnapshots(dir)
	if len(snaps) <= etcdPremaintKeep {
		return 0
	}
	removed := 0
	for _, f := range snaps[etcdPremaintKeep:] {
		if err := os.Remove(f); err == nil {
			removed++
		}
	}
	return removed
}

// VerifySnapshots is the backup-health embedded-etcd backup check: the
// newest snapshot under the configured dir (or the two k0s
// defaults — <K0sDir>/etcd/snapshots and EtcdBackupDir, the
// host-root-joined /var/backups/etcd) must
// exist and be non-empty. Its age lands on
// node_host_agent_controllerhygiene_etcd_snapshot_age_seconds; a
// missing or empty snapshot is a suspect-log, never an action —
// snapshot creation belongs to the backup tooling, the agent only
// verifies the pipeline still runs.
func (c *GuardCheck) VerifySnapshots() {
	dirs := []string{
		filepath.Join(c.d.Cfg.K0sDir, "etcd", "snapshots"),
		c.d.Cfg.EtcdBackupDir,
	}
	if c.d.Cfg.EtcdSnapshotDir != "" {
		dirs = []string{c.d.Cfg.EtcdSnapshotDir}
	}
	var newest string
	var newestMT time.Time
	var newestSize int64
	for _, dir := range dirs {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, ent := range ents {
			if ent.IsDir() {
				continue
			}
			fi, err := ent.Info()
			if err != nil || !fi.ModTime().After(newestMT) {
				continue
			}
			newest = filepath.Join(dir, ent.Name())
			newestMT = fi.ModTime()
			newestSize = fi.Size()
		}
	}
	if newest == "" {
		c.d.State.SuspectLog(cdeps.CheckEtcd,
			"suspect: no etcd snapshot found under "+strings.Join(dirs, ", ")+
				" — etcd snapshot pipeline may be down (backup-health)",
			c.d.Cfg.SuspectLogCadence)
		return
	}
	age := c.d.Cfg.Clock.Now().Sub(newestMT)
	c.d.EtcdSnapAge.Set(age.Seconds())
	if newestSize == 0 {
		c.d.State.SuspectLog(cdeps.CheckEtcd, fmt.Sprintf(
			"suspect: newest etcd snapshot %s is empty (0 bytes) — restore path would fail",
			newest), c.d.Cfg.SuspectLogCadence)
	}
}

// etcdStatus fetches `endpoint status -w json` and returns the db
// file size + in-use size of element[0] (same JSON shape
// etcdmaint.parseStatusJSON consumes).
func (c *GuardCheck) etcdStatus(ctx context.Context) (dbSize, dbUse int64, err error) {
	b, err := c.d.Cfg.EtcdctlFn(ctx, "endpoint", "status", "-w", "json")
	if err != nil {
		return 0, 0, err
	}
	var arr []struct {
		Status struct {
			DBSize      int64 `json:"dbSize"`
			DBSizeInUse int64 `json:"dbSizeInUse"`
		} `json:"Status"`
	}
	if err := json.Unmarshal(b, &arr); err != nil {
		return 0, 0, fmt.Errorf("parse endpoint status: %w", err)
	}
	if len(arr) == 0 {
		return 0, 0, errors.New("parse endpoint status: empty endpoint list")
	}
	return arr[0].Status.DBSize, arr[0].Status.DBSizeInUse, nil
}

// etcdNospaceArmed reports whether `alarm list` carries a NOSPACE
// entry — the memberID:xxx alarm:NOSPACE grep the manual flow used.
func (c *GuardCheck) etcdNospaceArmed(ctx context.Context) (bool, error) {
	b, err := c.d.Cfg.EtcdctlFn(ctx, "alarm", "list")
	if err != nil {
		return false, err
	}
	return strings.Contains(string(b), "NOSPACE"), nil
}

// guardLogWriter adapts the eventpurge/etcdmaint io.Writer output to
// the watchdog log — each completed line lands as its own timestamped
// appendLog entry (the "<rfc3339> <msg>" filelog contract), prefixed
// so the sub-command output is attributable in the NPD tail.
type guardLogWriter struct {
	d   *cdeps.Deps
	buf strings.Builder
}

func (w *guardLogWriter) Write(p []byte) (int, error) {
	w.buf.Write(p)
	for {
		s := w.buf.String()
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			return len(p), nil
		}
		if line := strings.TrimSpace(s[:i]); line != "" {
			w.d.State.AppendLog("etcdguard: " + line)
		}
		w.buf.Reset()
		w.buf.WriteString(s[i+1:])
	}
}

// flush emits any trailing partial line — called after each sub-run
// so a stream ending without '\n' still reaches the log.
func (w *guardLogWriter) flush() {
	if line := strings.TrimSpace(w.buf.String()); line != "" {
		w.d.State.AppendLog("etcdguard: " + line)
	}
	w.buf.Reset()
}

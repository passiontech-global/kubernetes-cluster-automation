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
package controllerhygiene

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/etcdmaint"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/eventpurge"
)

// etcdguard knobs (embedded-etcd quota self-defence — cicd
// controllers; kine hosts lack <K0sDir>/bin/etcdctl and no-op).
const (
	checkEtcd              = "etcd-quota"      // prometheus check label
	fileRateEtcdGuard      = "last-etcd-guard" // eventpurge+rescue budget
	defaultEtcdEndpoint    = "https://127.0.0.1:2379"
	defaultEtcdDBSizeLimit = int64(1610612736) // 1.5 GiB
	defaultEtcdGuardMinRun = time.Hour         // last-etcd-guard budget
	defaultEtcdctlBudget   = 60 * time.Second  // ctx cap per etcdctl call
	etcdctlCmdTimeout      = "30s"             // etcdctl --command-timeout
	// Bound on the whole eventpurge+rescue remediation block: eventpurge
	// is unbounded pagination + delete work at the apiserver's pace
	// and the rescue is ~12 sequential etcdctl calls — driven by
	// the process-lifetime ctx, a degraded backend could stall one
	// (synchronous) cycle for hours. Both steps are idempotent and
	// last-etcd-guard is spent up front, so exhausting this only
	// defers the remainder to the next EtcdGuardMinRun window.
	defaultEtcdGuardBudget = 10 * time.Minute
	// Each rescue-spawned command gets a far shorter cap than
	// etcdmaint's defaultCallTimeout (10m — sized for an operator
	// at a shell): ~12 sequential calls then stay near the guard
	// budget instead of ~2h.
	defaultEtcdGuardCallTimeout = time.Minute
	// eventStaleAge is the apiserver's own 1h event TTL — anything
	// older is GC debt the purge may safely delete (fresh, debuggable
	// events survive the guard's eventpurge pass).
	eventStaleAge = time.Hour
)

// etcdGuardCheck is the embedded-etcd quota self-defence as a
// Check — stateless: the eventpurge+rescue cadence lives in the
// last-etcd-guard budget.
type etcdGuardCheck struct {
	d *deps
}

// Name returns the check label / log context.
func (c *etcdGuardCheck) Name() string { return checkEtcd }

// Run executes one etcdguard cycle.
func (c *etcdGuardCheck) Run(ctx context.Context) {
	if _, err := os.Stat(filepath.Join(c.d.cfg.K0sDir, "bin", "etcdctl")); err != nil {
		c.d.cycles.WithLabelValues(checkEtcd, "no_etcdctl").Inc()
		return
	}
	if _, err := os.Stat(filepath.Join(c.d.cfg.K0sDir,
		"pki", "etcd", "ca.crt")); err != nil {
		c.d.cycles.WithLabelValues(checkEtcd, "no_etcd_pki").Inc()
		return
	}
	// W13-ST2: the snapshot verifier rides this embedded-etcd
	// gate — a controller with no local etcd has no snapshot
	// dirs to verify.
	c.verifySnapshots()

	dbSize, dbUse, err := c.etcdStatus(ctx)
	if err != nil {
		// etcd unreachable — nothing measurable; the wedge/feeder
		// guards own the control-plane-down story.
		c.d.state.AppendLogWarn(fmt.Sprintf(
			"etcdguard: endpoint status failed (endpoint=%s): %v — quota check skipped",
			c.d.cfg.EtcdGuard.Endpoint, err))
		c.d.cycles.WithLabelValues(checkEtcd, "status_error").Inc()
		return
	}
	c.d.etcdDBSize.Set(float64(dbSize))
	c.d.etcdDBUse.Set(float64(dbUse))

	// The alarm-list probe only runs while dbSize is below the
	// trigger: over-limit the action decision is already made, so a
	// second etcdctl would only double the routine probe cost —
	// against a hung etcd each call can burn its whole command
	// timeout. A skipped probe leaves the nospace gauge at its last
	// value, the same "keep last, never force-clear a
	// possibly-armed alarm" semantics as a probe error.
	var nospace bool
	if dbSize < c.d.cfg.EtcdGuard.DBSizeLimit {
		ns, aerr := c.etcdNospaceArmed(ctx)
		if aerr != nil {
			// A failed alarm read must not hide a real alarm —
			// treat the size signal as authoritative this cycle,
			// surface the error once in the log, and LEAVE the
			// gauge at its last value.
			c.d.state.AppendLogWarn(fmt.Sprintf("etcdguard: alarm list failed: %v", aerr))
		} else if ns {
			nospace = true
			c.d.etcdNospace.Set(1)
		} else {
			c.d.etcdNospace.Set(0)
		}
	}

	var reason string
	switch {
	case nospace:
		reason = "nospace-alarm"
	case dbSize >= c.d.cfg.EtcdGuard.DBSizeLimit:
		reason = fmt.Sprintf("dbSize=%d>=%d", dbSize, c.d.cfg.EtcdGuard.DBSizeLimit)
	default:
		c.d.cycles.WithLabelValues(checkEtcd, "ok").Inc()
		return
	}

	if !c.d.state.RateOK(fileRateEtcdGuard,
		c.d.cfg.EtcdGuard.MinRun) {
		c.d.state.SuspectLog(checkEtcd, fmt.Sprintf(
			"etcdguard: %s but in guard cooldown (<%dm), skip",
			reason, int(c.d.cfg.EtcdGuard.MinRun.Minutes())),
			c.d.cfg.SuspectLogCadence)
		c.d.cycles.WithLabelValues(checkEtcd, "cooldown").Inc()
		return
	}
	c.d.state.AppendLog(fmt.Sprintf(
		"ACTION: etcdguard %s — evpurge stale events + ONLINE-ONLY "+
			"etcd rescue (offline defrag forbidden)", reason))
	// Budget spent before the action — a kill mid-rescue must not
	// allow a second run inside the window (feeder G6 parity).
	c.d.state.RateSpend(fileRateEtcdGuard)
	out := &guardLogWriter{d: c.d}

	// The whole remediation runs under a bounded ctx: eventpurge is
	// unbounded pagination + delete work against a possibly
	// degraded apiserver and the rescue is ~12 sequential etcdctl
	// calls — on the process-lifetime ctx either could stall this
	// (synchronous) cycle for hours. Both steps are idempotent and
	// the rate budget was already spent, so exhausting the deadline
	// only defers the remainder to the next EtcdGuardMinRun window.
	gctx, gcancel := context.WithTimeout(ctx, defaultEtcdGuardBudget)
	defer gcancel()

	// Stale apiserver events are the classic quota-filler after a
	// control-plane outage — purge first so the rescue's compaction
	// has garbage to drop. Cutoff keeps the apiserver's own 1h event
	// TTL: only GC debt is deleted, fresh events survive.
	perr := c.d.cfg.evpurgeRunFn(gctx, eventpurge.Config{
		API:      "https://" + c.d.cfg.Hub.SelfEndpoint,
		CAFile:   c.d.cfg.AdminCA,
		CertFile: c.d.cfg.AdminCert,
		KeyFile:  c.d.cfg.AdminKey,
	}, c.d.cfg.nowFn().Add(-eventStaleAge), out)
	out.flush()
	if perr != nil {
		// Logged on its own — a purge miss does NOT fail the cycle
		// when the quota-remediating step still lands below.
		c.d.state.AppendLogWarn(fmt.Sprintf("etcdguard: evpurge failed: %v", perr))
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
		rerr := c.d.cfg.etcdRescueFn(gctx, etcdmaint.Config{
			K0sDir:   c.d.cfg.K0sDir,
			Endpoint: c.d.cfg.EtcdGuard.Endpoint,
			// OnlineOnly: this is background auto-maintenance — the
			// systemctl-stop + standalone-etcd defrag would take the
			// control plane down and stays a manual rescue-etcd
			// action.
			OnlineOnly: true,
			// The guard is a loop, not an operator: cap each spawned
			// command far below etcdmaint's interactive default
			// (defaultCallTimeout = 10m) so ~12 sequential calls
			// stay near the guard budget instead of ~2h.
			CallTimeout: defaultEtcdGuardCallTimeout,
		}, out)
		out.flush()
		if rerr != nil {
			c.d.state.AppendLogWarn(fmt.Sprintf("etcdguard: rescue incomplete: %v", rerr))
		}
		remediated = rerr == nil
	} else {
		// The budget died inside eventpurge — the rescue never ran,
		// so the cycle is incomplete, not a clean ok.
		remediated = false
	}
	if errors.Is(gctx.Err(), context.DeadlineExceeded) {
		c.d.state.AppendLogWarn(fmt.Sprintf(
			"etcdguard: run budget (%s) exhausted — remaining steps "+
				"deferred to the next %s window",
			defaultEtcdGuardBudget, c.d.cfg.EtcdGuard.MinRun))
	}
	c.d.actions.WithLabelValues(checkEtcd, "evpurge_rescue").Inc()
	if remediated {
		c.d.cycles.WithLabelValues(checkEtcd, "ok").Inc()
	} else {
		c.d.cycles.WithLabelValues(checkEtcd, "remediate_error").Inc()
	}
}

// verifySnapshots is the W13-ST2 embedded-etcd backup check: the
// newest snapshot under the configured dir (or the two k0s
// defaults — <K0sDir>/etcd/snapshots and /var/backups/etcd) must
// exist and be non-empty. Its age lands on
// node_host_agent_controllerhygiene_etcd_snapshot_age_seconds; a
// missing or empty snapshot is a suspect-log, never an action —
// snapshot creation belongs to the backup tooling, the agent only
// verifies the pipeline still runs.
func (c *etcdGuardCheck) verifySnapshots() {
	dirs := []string{
		filepath.Join(c.d.cfg.K0sDir, "etcd", "snapshots"),
		"/var/backups/etcd",
	}
	if c.d.cfg.EtcdSnapshotDir != "" {
		dirs = []string{c.d.cfg.EtcdSnapshotDir}
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
		c.d.state.SuspectLog(checkEtcd,
			"suspect: no etcd snapshot found under "+strings.Join(dirs, ", ")+
				" — etcd snapshot pipeline may be down (W13-ST2)",
			c.d.cfg.SuspectLogCadence)
		return
	}
	age := c.d.cfg.nowFn().Sub(newestMT)
	c.d.etcdSnapAge.Set(age.Seconds())
	if newestSize == 0 {
		c.d.state.SuspectLog(checkEtcd, fmt.Sprintf(
			"suspect: newest etcd snapshot %s is empty (0 bytes) — restore path would fail",
			newest), c.d.cfg.SuspectLogCadence)
	}
}

// etcdStatus fetches `endpoint status -w json` and returns the db
// file size + in-use size of element[0] (same JSON shape
// etcdmaint.parseStatusJSON consumes).
func (c *etcdGuardCheck) etcdStatus(ctx context.Context) (dbSize, dbUse int64, err error) {
	b, err := c.d.cfg.etcdctlFn(ctx, "endpoint", "status", "-w", "json")
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
func (c *etcdGuardCheck) etcdNospaceArmed(ctx context.Context) (bool, error) {
	b, err := c.d.cfg.etcdctlFn(ctx, "alarm", "list")
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
	d   *deps
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
			w.d.state.AppendLog("etcdguard: " + line)
		}
		w.buf.Reset()
		w.buf.WriteString(s[i+1:])
	}
}

// flush emits any trailing partial line — called after each sub-run
// so a stream ending without '\n' still reaches the log.
func (w *guardLogWriter) flush() {
	if line := strings.TrimSpace(w.buf.String()); line != "" {
		w.d.state.AppendLog("etcdguard: " + line)
	}
	w.buf.Reset()
}

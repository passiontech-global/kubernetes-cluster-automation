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

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/ops/etcdmaint"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/ops/eventpurge"
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

// checkEtcdQuota runs one etcdguard cycle.
func (h *Hygiene) checkEtcdQuota(ctx context.Context) {
	if _, err := os.Stat(filepath.Join(h.cfg.K0sDir, "bin", "etcdctl")); err != nil {
		h.cycles.WithLabelValues(checkEtcd, "no_etcdctl").Inc()
		return
	}
	if _, err := os.Stat(filepath.Join(h.cfg.K0sDir,
		"pki", "etcd", "ca.crt")); err != nil {
		h.cycles.WithLabelValues(checkEtcd, "no_etcd_pki").Inc()
		return
	}

	dbSize, dbUse, err := h.etcdStatus(ctx)
	if err != nil {
		// etcd unreachable — nothing measurable; the wedge/feeder
		// guards own the control-plane-down story.
		h.state.AppendLogWarn(fmt.Sprintf(
			"etcdguard: endpoint status failed (endpoint=%s): %v — quota check skipped",
			h.cfg.EtcdGuard.Endpoint, err))
		h.cycles.WithLabelValues(checkEtcd, "status_error").Inc()
		return
	}
	h.etcdDBSize.Set(float64(dbSize))
	h.etcdDBUse.Set(float64(dbUse))

	// The alarm-list probe only runs while dbSize is below the
	// trigger: over-limit the action decision is already made, so a
	// second etcdctl would only double the routine probe cost —
	// against a hung etcd each call can burn its whole command
	// timeout. A skipped probe leaves the nospace gauge at its last
	// value, the same "keep last, never force-clear a
	// possibly-armed alarm" semantics as a probe error.
	var nospace bool
	if dbSize < h.cfg.EtcdGuard.DBSizeLimit {
		ns, aerr := h.etcdNospaceArmed(ctx)
		if aerr != nil {
			// A failed alarm read must not hide a real alarm —
			// treat the size signal as authoritative this cycle,
			// surface the error once in the log, and LEAVE the
			// gauge at its last value.
			h.state.AppendLogWarn(fmt.Sprintf("etcdguard: alarm list failed: %v", aerr))
		} else if ns {
			nospace = true
			h.etcdNospace.Set(1)
		} else {
			h.etcdNospace.Set(0)
		}
	}

	var reason string
	switch {
	case nospace:
		reason = "nospace-alarm"
	case dbSize >= h.cfg.EtcdGuard.DBSizeLimit:
		reason = fmt.Sprintf("dbSize=%d>=%d", dbSize, h.cfg.EtcdGuard.DBSizeLimit)
	default:
		h.cycles.WithLabelValues(checkEtcd, "ok").Inc()
		return
	}

	if !h.state.RateOK(fileRateEtcdGuard,
		h.cfg.EtcdGuard.MinRun) {
		h.state.SuspectLog(checkEtcd, fmt.Sprintf(
			"etcdguard: %s but in guard cooldown (<%dm), skip",
			reason, int(h.cfg.EtcdGuard.MinRun.Minutes())),
			h.cfg.SuspectLogCadence)
		h.cycles.WithLabelValues(checkEtcd, "cooldown").Inc()
		return
	}
	h.state.AppendLog(fmt.Sprintf(
		"ACTION: etcdguard %s — evpurge stale events + ONLINE-ONLY "+
			"etcd rescue (offline defrag forbidden)", reason))
	// Budget spent before the action — a kill mid-rescue must not
	// allow a second run inside the window (feeder G6 parity).
	h.state.RateSpend(fileRateEtcdGuard)
	out := &guardLogWriter{h: h}

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
	perr := h.cfg.evpurgeRunFn(gctx, eventpurge.Config{
		API:      "https://" + h.cfg.Hub.SelfEndpoint,
		CAFile:   h.cfg.AdminCA,
		CertFile: h.cfg.AdminCert,
		KeyFile:  h.cfg.AdminKey,
	}, h.cfg.nowFn().Add(-eventStaleAge), out)
	out.flush()
	if perr != nil {
		// Logged on its own — a purge miss does NOT fail the cycle
		// when the quota-remediating step still lands below.
		h.state.AppendLogWarn(fmt.Sprintf("etcdguard: evpurge failed: %v", perr))
	}
	// remediated tracks the step that actually relieves the quota:
	// the online rescue (compact+defrag). eventpurge only drops event
	// GC debt so the rescue has garbage to free — when the rescue
	// ran, its result IS the verdict, even if eventpurge failed
	// upstream (the purge failure stays logged above either way).
	remediated := perr == nil
	// A dead gctx here means eventpurge (or a cancelled parent) ate
	// the whole budget — spawn no further calls that can only fail;
	// the rescue is idempotent and retries in the next window.
	if gctx.Err() == nil {
		rerr := h.cfg.etcdRescueFn(gctx, etcdmaint.Config{
			K0sDir:   h.cfg.K0sDir,
			Endpoint: h.cfg.EtcdGuard.Endpoint,
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
			h.state.AppendLogWarn(fmt.Sprintf("etcdguard: rescue incomplete: %v", rerr))
		}
		remediated = rerr == nil
	} else {
		// The budget died inside eventpurge — the rescue never ran,
		// so the cycle is incomplete, not a clean ok.
		remediated = false
	}
	if errors.Is(gctx.Err(), context.DeadlineExceeded) {
		h.state.AppendLogWarn(fmt.Sprintf(
			"etcdguard: run budget (%s) exhausted — remaining steps "+
				"deferred to the next %s window",
			defaultEtcdGuardBudget, h.cfg.EtcdGuard.MinRun))
	}
	h.actions.WithLabelValues(checkEtcd, "evpurge_rescue").Inc()
	if remediated {
		h.cycles.WithLabelValues(checkEtcd, "ok").Inc()
	} else {
		h.cycles.WithLabelValues(checkEtcd, "remediate_error").Inc()
	}
}

// etcdStatus fetches `endpoint status -w json` and returns the db
// file size + in-use size of element[0] (same JSON shape
// etcdmaint.parseStatusJSON consumes).
func (h *Hygiene) etcdStatus(ctx context.Context) (dbSize, dbUse int64, err error) {
	b, err := h.cfg.etcdctlFn(ctx, "endpoint", "status", "-w", "json")
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
		return 0, 0, fmt.Errorf("parse endpoint status: empty endpoint list")
	}
	return arr[0].Status.DBSize, arr[0].Status.DBSizeInUse, nil
}

// etcdNospaceArmed reports whether `alarm list` carries a NOSPACE
// entry — the memberID:xxx alarm:NOSPACE grep the manual flow used.
func (h *Hygiene) etcdNospaceArmed(ctx context.Context) (bool, error) {
	b, err := h.cfg.etcdctlFn(ctx, "alarm", "list")
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
	h   *Hygiene
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
			w.h.state.AppendLog("etcdguard: " + line)
		}
		w.buf.Reset()
		w.buf.WriteString(s[i+1:])
	}
}

// flush emits any trailing partial line — called after each sub-run
// so a stream ending without '\n' still reaches the log.
func (w *guardLogWriter) flush() {
	if line := strings.TrimSpace(w.buf.String()); line != "" {
		w.h.state.AppendLog("etcdguard: " + line)
	}
	w.buf.Reset()
}

// runtime_clock_jump.go — the clock-jump-session-healer guard
// (wdeps.CheckClockJump). A wall-clock step (NTP makestep, RTC
// catch-up, suspend/resume) invalidates every cached-token session
// at once: konnectivity-agent keeps its token and starts failing
// with 401/x509 while the pod looks Running. When the
// clock-stepped-at marker (written by the clock-step remedy) is
// fresh AND the konnectivity log shows the auth-failure signature,
// recreate the pod so it re-bakes fresh credentials — the same
// remedy the konnectivity IP-drift check uses, on its own 30m
// budget.
package runtime

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/pods"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	// konnLogTailLines bounds the konnectivity log tail the
	// clock-jump healer greps.
	konnLogTailLines = 200
	// clockJumpMarkerFresh is how recent the clock-stepped-at
	// marker must be for pod-session healing — a step older than
	// this either healed already or isn't the cause of a NEW 401
	// (clients recover by token refresh eventually).
	clockJumpMarkerFresh = 10 * time.Minute
	// clockJumpMarkerFile is the marker a clock-step remedy leaves
	// in the watchdog state dir (epoch content, mtime fallback).
	clockJumpMarkerFile = "clock-stepped-at"
)

// konnClockErrorRe matches the auth-expiry signatures a
// konnectivity-agent emits after a wall-clock step threw its
// cached SA token / TLS cert validity window off.
var konnClockErrorRe = regexp.MustCompile(`401 Unauthorized|x509`)

type ClockJumpCheck struct{ d *wdeps.Deps }

// Name returns the check label / WD_SIG key.
func (c *ClockJumpCheck) Name() string { return wdeps.CheckClockJump }

// clockSteppedAt reads the clock-stepped-at marker in the state
// dir — epoch content first, file mtime as the fallback shape.
func clockSteppedAt(d *wdeps.Deps) (time.Time, bool) {
	p := filepath.Join(d.Cfg.WatchdogStateDir, clockJumpMarkerFile)
	data, err := os.ReadFile(p)
	if err != nil {
		return time.Time{}, false
	}
	if ep, err := strconv.ParseInt(
		strings.TrimSpace(string(data)), 10, 64); err == nil && ep > 0 {
		return time.Unix(ep, 0), true
	}
	if fi, err := os.Stat(p); err == nil {
		return fi.ModTime(), true
	}
	return time.Time{}, false
}

// konnPodLog returns a log tail for this node's konnectivity-agent
// pod — the pod log file under PodLogsDir first (kubelet keeps the
// tail even while the apiserver is unreachable), the podLogFn API
// seam as fallback when the file path yields nothing.
func konnPodLog(d *wdeps.Deps, ctx context.Context, p *corev1.Pod) string {
	dir := filepath.Join(d.Cfg.Disk.PodLogsDir,
		p.Namespace+"_"+p.Name+"_"+string(p.UID))
	if logs, err := filepath.Glob(filepath.Join(dir, "*", "*.log")); err == nil {
		var best string
		var bestMod time.Time
		for _, lf := range logs {
			fi, err := os.Stat(lf)
			if err != nil || !fi.ModTime().After(bestMod) {
				continue
			}
			best, bestMod = lf, fi.ModTime()
		}
		if best != "" {
			if data, err := tailFile(best, 64<<10); err == nil && len(data) > 0 {
				return string(data)
			}
		}
	}
	if d.Cfg.Seams.Probe.PodLogFn != nil {
		if out, err := d.Cfg.Seams.Probe.PodLogFn(ctx, p.Namespace, p.Name,
			konnLogTailLines); err == nil {
			return out
		}
	}
	return ""
}

// tailFile reads the last n bytes of path — log tails must not
// slurp a multi-GB 0.log.
func tailFile(path string, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() > n {
		if _, err := f.Seek(-n, io.SeekEnd); err != nil {
			return nil, err
		}
	}
	return io.ReadAll(f)
}

// Run executes one clock-jump round.
func (c *ClockJumpCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckClockJump, "gated").Inc()
		return
	}
	stepped, ok := clockSteppedAt(c.d)
	if !ok || c.d.Cfg.Seams.Host.NowFn().Sub(stepped) > clockJumpMarkerFresh {
		// No recent step — the signature this check heals can't be
		// attributed to a clock jump.
		c.d.Cycles.WithLabelValues(wdeps.CheckClockJump, "ok").Inc()
		return
	}
	if !e.APIOK {
		c.d.Cycles.WithLabelValues(wdeps.CheckClockJump, "abort").Inc()
		return
	}
	var konn *corev1.Pod
	for i := range e.Pods {
		p := &e.Pods[i]
		if p.Namespace == "kube-system" && pods.KonnPodRe.MatchString(p.Name) &&
			p.DeletionTimestamp == nil {
			konn = p
			break
		}
	}
	if konn == nil {
		c.d.Cycles.WithLabelValues(wdeps.CheckClockJump, "ok").Inc()
		return
	}
	logs := konnPodLog(c.d, ctx, konn)
	if !konnClockErrorRe.MatchString(logs) {
		c.d.Cycles.WithLabelValues(wdeps.CheckClockJump, "ok").Inc()
		return
	}
	if !c.d.State.RateTrySpend("last-clock-jump-konn", c.d.Cfg.MinRestartInterval) {
		c.d.State.AppendLog(
			"suspect: clock-jump-session-healer konn auth-fail evidence but recreate cooldown (<30m), skip")
		c.d.Cycles.WithLabelValues(wdeps.CheckClockJump, "ok").Inc()
		return
	}
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: clock-jump-session-healer recreating konnectivity-agent %s/%s - fresh clock-step marker + 401/x509 in log",
		konn.Namespace, konn.Name))
	if pods.DeleteKonnectivityPod(c.d, ctx, e.Pods) {
		c.d.Actions.WithLabelValues(wdeps.CheckClockJump, "pod_delete").Inc()
	}
	c.d.Cycles.WithLabelValues(wdeps.CheckClockJump, "ok").Inc()
}

// konnectivity_heal.go — konnectivity-server probe + heal (G4).
//
// The k0s supervisor runs konnectivity-server as a CHILD of
// k0scontroller — the only restart that does not bounce the whole
// control plane is killing the child (the supervisor respawns it).
// Each cycle the probe checks the :8091/metrics scrape for
// konnectivity_network_proxy_server_ready_backend_connections (the
// gauge mirrors the value, -1 on scrape failure) and the agent UDS
// the worker-side konnectivity-agents dial. A missing UDS or a
// zero-backend reading for konnBadCyclesNeeded consecutive cycles —
// while at least one Ready worker exists to serve — kills the child under the
// last-konnectivity-server-restart 30-minute budget and the shared
// Sig13.Mode gate (off = state only, dry-run = log, enforce = kill).
// The probe rides the ungated-cycle slot dispatched from
// FreezeCheck.Run (see cdeps.CheckCPFreeze) — the child process
// lives independent of the KCM/scheduler freeze logic.

package apiserver

import (
	"context"
	json "encoding/json/v2"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/httpx"
)

const (
	konnMetricsURL       = "http://127.0.0.1:8091/metrics"
	konnReadyMetric      = "konnectivity_network_proxy_server_ready_backend_connections"
	konnGoroutinesMetric = "go_goroutines"
	konnUDSRel           = "konnectivity-server/konnectivity-server.sock"
	konnBadCyclesNeed    = 3
	konnRestartBudget    = 30 * time.Minute
)

// probeKonnectivityServer scrapes :8091/metrics once per cycle, refreshes
// the ready-backends gauge, checks tunnel health (UDS + ready backends),
// and checks for goroutine/RSS leaks.
func (c *FreezeCheck) probeKonnectivityServer(ctx context.Context) {
	d := c.d
	body, err := d.Cfg.KCMMetricsFn(ctx, konnMetricsURL)
	var (
		backends     float64
		ok           bool
		goroutines   float64
		goroutinesOK bool
	)
	if err == nil {
		backends, ok = ParseKonnectivityReadyBackends(body)
		goroutines, goroutinesOK = ParseKonnectivityGoroutines(body)
	}
	if ok {
		d.KonnReadyBackends.Set(backends)
	} else {
		d.KonnReadyBackends.Set(-1)
	}
	c.probeKonnectivityTunnel(ctx, backends, ok)
	c.probeKonnectivityLeak(ctx, goroutines, goroutinesOK)
}

// probeKonnectivityTunnel heals a dead/unconnected tunnel (missing UDS or
// ready_backend_connections==0 for 3 cycles while >=1 Ready worker exists).
func (c *FreezeCheck) probeKonnectivityTunnel(ctx context.Context, backends float64, ok bool) {
	d := c.d
	// The ready-backends gauge and the agent UDS are the evidence —
	// no healthz GET: it fed no verdict (an absent listener on an
	// older konnectivity build was not evidence either way), so the
	// per-cycle request was pure waste.
	sock := filepath.Join(d.Cfg.K0sRunDir, konnUDSRel)
	_, sockErr := os.Stat(sock)
	bad := sockErr != nil || (ok && backends == 0)
	if bad {
		c.konnBadCycles++
	} else {
		c.konnBadCycles = 0
	}
	if c.konnBadCycles < konnBadCyclesNeed {
		return
	}
	if workers := c.readyWorkers(ctx); workers < 1 {
		d.State.AppendLog(fmt.Sprintf(
			"suspect: konnectivity-server unhealthy %d cycles "+
				"(uds_ok=%v backends=%v) but no Ready workers — heal suppressed",
			c.konnBadCycles, sockErr == nil, backends))
		// No worker could use the tunnel, so these were not actionable
		// bad cycles. Clearing the streak stops a cluster-wide outage
		// from tripping the kill the moment the FIRST worker returns.
		c.konnBadCycles = 0
		return
	}
	pid, origStart := c.konnectivityPID()
	if pid == 0 {
		d.State.AppendLog("suspect: konnectivity-server process not found — nothing to kill")
		return
	}
	// L1↔L3 maintenance hold outranks the kill: a kured drain or
	// control-plane upgrade is already bouncing this node's
	// workloads — killing the konnectivity tunnel on top severs
	// worker→apiserver connectivity mid-drain.
	if d.HoldEmergencyHeal(ctx) {
		d.State.AppendLog("suspect: konnectivity-server unhealthy but cluster maintenance in progress — holding kill")
		return
	}
	switch d.Cfg.Sig13.Mode {
	case cdeps.ModeEnforce:
		// Re-verify process identity, cgroup, and starttime right before
		// SIGKILL to close any PID-reuse TOCTOU window across HoldEmergencyHeal.
		if !c.verifyKonnectivityPID(pid, origStart) {
			d.State.AppendLog(fmt.Sprintf(
				"suspect: konnectivity-server pid=%d identity changed before kill — skipped", pid))
			return
		}
		// Check+spend atomically right before the action — off and
		// dry-run modes must not burn the 30-minute restart budget.
		if !d.State.RateTrySpend(cdeps.FileRateKonnRestart, konnRestartBudget) {
			return
		}
		if err := d.Cfg.KillFn(pid, syscall.SIGKILL); err != nil {
			d.State.AppendLogWarn(fmt.Sprintf(
				"suspect: konnectivity-server kill pid=%d failed: %v", pid, err))
			return
		}
		d.State.AppendLog(fmt.Sprintf(
			"ACTION: killed konnectivity-server pid=%d — uds_ok=%v "+
				"ready_backends=%v bad_cycles=%d (k0s supervisor restarts it)",
			pid, sockErr == nil, backends, c.konnBadCycles))
		c.konnBadCycles = 0
		d.Actions.WithLabelValues(cdeps.CheckCPFreeze, "konn_server_kill").Inc()
	case cdeps.ModeDryRun:
		d.State.AppendLog(fmt.Sprintf(
			"DRY-RUN: would kill konnectivity-server pid=%d — uds_ok=%v "+
				"ready_backends=%v bad_cycles=%d",
			pid, sockErr == nil, backends, c.konnBadCycles))
		d.Actions.WithLabelValues(cdeps.CheckCPFreeze, "dryrun").Inc()
		// An action was taken (kill or its dry-run twin) — clear the
		// streak so the next heal must rebuild 3 fresh bad cycles
		// instead of chaining off the spent one every tick.
		c.konnBadCycles = 0
	default:
		// off — the streak + gauge still surface the degradation.
	}
}

// probeKonnectivityLeak detects sustained goroutine or RSS leaks in the
// konnectivity-server child process (3 consecutive cycles over either
// configured threshold) and sends SIGTERM under the shared 30m
// last-konnectivity-server-restart budget so k0s supervisor respawns a
// clean instance without touching kube-apiserver.
func (c *FreezeCheck) probeKonnectivityLeak(ctx context.Context, goroutines float64, goroutinesOK bool) {
	d := c.d
	maxGoroutines := d.Cfg.CPFreeze.KonnectivityMaxGoroutines
	maxRSSMiB := d.Cfg.CPFreeze.KonnectivityMaxRSSMiB
	if maxGoroutines <= 0 && maxRSSMiB <= 0 {
		c.konnLeakCycles = 0
		return
	}
	var (
		pid       int
		origStart string
		rssBytes  uint64
		rssOK     bool
	)
	if maxRSSMiB > 0 {
		pid, origStart = c.konnectivityPID()
		if pid != 0 {
			rssBytes, rssOK = d.ProcVMRSS(pid)
		}
	}
	goroutineLeak := maxGoroutines > 0 && goroutinesOK && goroutines > float64(maxGoroutines)
	rssLeak := maxRSSMiB > 0 && rssOK && rssBytes > uint64(maxRSSMiB)<<20
	if goroutineLeak || rssLeak {
		c.konnLeakCycles++
	} else {
		c.konnLeakCycles = 0
		return
	}
	if c.konnLeakCycles < konnBadCyclesNeed {
		return
	}
	if pid == 0 {
		pid, origStart = c.konnectivityPID()
	}
	if pid == 0 {
		d.State.AppendLog("suspect: konnectivity-server process not found — nothing to kill")
		return
	}
	if d.HoldEmergencyHeal(ctx) {
		d.State.AppendLog("suspect: konnectivity-server leak detected but cluster maintenance in progress — holding SIGTERM")
		return
	}
	var reasons []string
	if goroutineLeak {
		reasons = append(reasons, fmt.Sprintf("goroutines=%.0f>%d", goroutines, maxGoroutines))
	}
	if rssLeak {
		reasons = append(reasons, fmt.Sprintf("rss_mib=%d>%d", rssBytes>>20, maxRSSMiB))
	}
	reason := strings.Join(reasons, " ")

	switch d.Cfg.Sig13.Mode {
	case cdeps.ModeEnforce:
		if !c.verifyKonnectivityPID(pid, origStart) {
			d.State.AppendLog(fmt.Sprintf(
				"suspect: konnectivity-server pid=%d identity changed before SIGTERM — skipped", pid))
			return
		}
		if !d.State.RateTrySpend(cdeps.FileRateKonnRestart, konnRestartBudget) {
			return
		}
		if err := d.Cfg.KillFn(pid, syscall.SIGTERM); err != nil {
			d.State.AppendLogWarn(fmt.Sprintf(
				"suspect: konnectivity-server SIGTERM pid=%d failed: %v", pid, err))
			return
		}
		d.State.AppendLog(fmt.Sprintf(
			"ACTION: terminated konnectivity-server pid=%d (SIGTERM) — %s leak_cycles=%d (k0s supervisor respawns it)",
			pid, reason, c.konnLeakCycles))
		c.konnLeakCycles = 0
		d.Actions.WithLabelValues(cdeps.CheckCPFreeze, "konn_server_leak_kill").Inc()
	case cdeps.ModeDryRun:
		d.State.AppendLog(fmt.Sprintf(
			"DRY-RUN: would terminate konnectivity-server pid=%d (SIGTERM) — %s leak_cycles=%d",
			pid, reason, c.konnLeakCycles))
		d.Actions.WithLabelValues(cdeps.CheckCPFreeze, "dryrun").Inc()
		c.konnLeakCycles = 0
	default:
		// off — observe only.
	}
}

// ParseKonnectivityGoroutines reads the go_goroutines gauge sample out of
// the konnectivity-server :8091/metrics response. ok=false when absent or
// unparseable.
func ParseKonnectivityGoroutines(body string) (float64, bool) {
	for ln := range strings.SplitSeq(body, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "#") || !strings.HasPrefix(ln, konnGoroutinesMetric) {
			continue
		}
		f := strings.Fields(ln)
		if len(f) < 2 || f[0] != konnGoroutinesMetric {
			continue
		}
		if v, err := strconv.ParseFloat(f[1], 64); err == nil &&
			!math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 {
			return v, true
		}
	}
	return 0, false
}

// ParseKonnectivityReadyBackends reads the
// konnectivity_network_proxy_server_ready_backend_connections
// sample out of a metrics body — the metric is unlabeled; comment
// and HELP/TYPE lines never match. ok=false when the series is
// absent (a build that exports no metric is inconclusive, not
// "zero backends").
func ParseKonnectivityReadyBackends(body string) (float64, bool) {
	for ln := range strings.SplitSeq(body, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "#") || !strings.HasPrefix(ln, konnReadyMetric) {
			continue
		}
		f := strings.Fields(ln)
		if len(f) < 2 {
			continue
		}
		if v, err := strconv.ParseFloat(f[len(f)-1], 64); err == nil {
			return v, true
		}
	}
	return 0, false
}

// konnectivityPID locates the supervisor's konnectivity-server child
// — lowest pid whose cmdline basename is konnectivity-server. comm
// would truncate at 15 chars ("konnectivity-se") so the cmdline is
// the reliable name; a pod-side konnectivity-agent argv contains
// "konnectivity-agent", never the server binary.
func (c *FreezeCheck) konnectivityPID() (int, string) {
	pids, err := c.d.Proc.PIDs()
	if err != nil {
		return 0, ""
	}
	slices.Sort(pids)
	for _, pid := range pids {
		args := c.d.Proc.Cmdline(pid)
		if len(args) == 0 {
			continue
		}
		base := args[0]
		if i := strings.LastIndex(base, "/"); i >= 0 {
			base = base[i+1:]
		}
		if base == "konnectivity-server" &&
			c.d.Proc.CgroupContains(pid, cdeps.K0sControllerCgroupSubstr) {
			var startTime string
			if st, ok := c.d.Proc.Stat(pid); ok && len(st.Fields) > 19 {
				startTime = st.Fields[19]
			}
			return pid, startTime
		}
	}
	return 0, ""
}

func (c *FreezeCheck) verifyKonnectivityPID(pid int, origStart string) bool {
	if !c.d.Proc.CgroupContains(pid, cdeps.K0sControllerCgroupSubstr) {
		return false
	}
	if origStart != "" {
		st, ok := c.d.Proc.Stat(pid)
		if !ok || len(st.Fields) <= 19 || st.Fields[19] != origStart {
			return false
		}
	}
	args := c.d.Proc.Cmdline(pid)
	if len(args) == 0 {
		return false
	}
	base := args[0]
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	return base == "konnectivity-server"
}

// isVirtualWorkerNodeLabels filters Liqo / virtual-kubelet /
// external-capacity shadow nodes out of the ready-worker census.
// They report Ready but run no real workload — a virtual node
// cannot dial the tunnel, so treating it as a worker would permit
// a disruptive kill with nobody left to benefit from the heal.
// Presence-based checks (any liqo.io/type or provider value) keep
// the census conservative: undercounting only suppresses a heal.
func isVirtualWorkerNodeLabels(labels map[string]string) bool {
	if labels["liqo.io/type"] != "" || labels["virtual-kubelet.io/provider"] != "" {
		return true
	}
	return labels["type"] == "virtual-kubelet" ||
		labels[corev1.LabelInstanceTypeStable] == "external"
}

// readyWorkers counts Ready, non-control-plane, non-virtual nodes
// via the apiserver client — the heal only makes sense while a
// real worker can actually dial the tunnel; a zero count suppresses
// the kill (a cluster-wide outage is not a konnectivity fault).
func (c *FreezeCheck) readyWorkers(ctx context.Context) int {
	client := c.d.EnsureClient()
	if client == nil {
		return 0
	}
	// SelfAPI is the advertised apiserver address and stays EMPTY on
	// single-control-plane hubs that never set API_SELF — fall back
	// to SelfEndpoint (always populated, loopback probe target) or
	// the URL collapses to "https:///api/v1/nodes" and the heal is
	// suppressed forever.
	endpoint := c.d.Cfg.Hub.SelfAPI
	if endpoint == "" {
		endpoint = c.d.Cfg.Hub.SelfEndpoint
	}
	endpoint = strings.TrimPrefix(endpoint, "https://")
	endpoint = strings.TrimPrefix(endpoint, "http://")
	n := 0
	cont := ""
	for {
		u := "https://" + endpoint + "/api/v1/nodes?limit=500"
		if cont != "" {
			u += "&continue=" + url.QueryEscape(cont)
		}
		qctx, cancel := context.WithTimeout(ctx, c.d.Cfg.QueryTimeout)
		req, err := http.NewRequestWithContext(qctx, http.MethodGet, u, nil)
		if err != nil {
			cancel()
			return 0
		}
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			return 0
		}
		var list struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []struct {
				Metadata struct {
					Labels map[string]string `json:"labels"`
				} `json:"metadata"`
				Status struct {
					Conditions []struct {
						Type   string `json:"type"`
						Status string `json:"status"`
					} `json:"conditions"`
				} `json:"status"`
			} `json:"items"`
		}
		statusOK := resp.StatusCode/100 == 2
		var decErr error
		if statusOK {
			decErr = json.UnmarshalRead(io.LimitReader(resp.Body, 8<<20), &list)
		}
		httpx.DrainAndClose(resp.Body, 64<<10)
		cancel()
		if !statusOK || decErr != nil {
			return 0
		}
		for _, item := range list.Items {
			// Virtual/shadow nodes report Ready but run no real
			// kubelet or konnectivity-agent — counting one as a
			// worker would green-light a tunnel kill during a
			// genuine worker outage.
			if isVirtualWorkerNodeLabels(item.Metadata.Labels) {
				continue
			}
			if _, cp := item.Metadata.Labels["node-role.kubernetes.io/control-plane"]; cp {
				continue
			}
			if _, cp := item.Metadata.Labels["node-role.kubernetes.io/master"]; cp {
				continue
			}
			for _, cond := range item.Status.Conditions {
				if cond.Type == "Ready" && cond.Status == "True" {
					n++
				}
			}
		}
		if list.Metadata.Continue == "" {
			break
		}
		cont = list.Metadata.Continue
	}
	return n
}

// konnectivity_heal.go — konnectivity-server probe + heal (G4).
//
// The k0s supervisor runs konnectivity-server as a CHILD of
// k0scontroller — the only restart that does not bounce the whole
// control plane is killing the child (the supervisor respawns it).
// Each cycle the probe checks the :8091/metrics scrape for
// konnectivity_network_proxy_server_ready_backend_connections (the
// gauge mirrors the value, -1 on scrape failure), the :8092/healthz
// liveness endpoint and the agent UDS the worker-side
// konnectivity-agents dial. A missing UDS or a zero-backend reading
// for konnBadCyclesNeeded consecutive cycles — while at least one
// Ready worker exists to serve — kills the child under the
// last-konnectivity-server-restart 30-minute budget and the shared
// Sig13.Mode gate (off = state only, dry-run = log, enforce = kill).
// The probe rides the ungated-cycle slot dispatched from
// FreezeCheck.Run (see cdeps.CheckCPFreeze) — the child process
// lives independent of the KCM/scheduler freeze logic.

package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

const (
	konnMetricsURL    = "http://127.0.0.1:8091/metrics"
	konnHealthURL     = "http://127.0.0.1:8092/healthz"
	konnReadyMetric   = "konnectivity_network_proxy_server_ready_backend_connections"
	konnUDSRel        = "konnectivity-server/konnectivity-server.sock"
	konnBadCyclesNeed = 3
	konnRestartBudget = 30 * time.Minute
)

// probeKonnectivityServer refreshes the ready-backends gauge and the
// unhealthy streak, then heals when the streak and the ready-worker
// evidence both hold.
func (c *FreezeCheck) probeKonnectivityServer(ctx context.Context) {
	d := c.d
	backends, ok := c.konnReadyBackends(ctx)
	if ok {
		d.KonnReadyBackends.Set(backends)
	} else {
		d.KonnReadyBackends.Set(-1)
	}
	// The healthz endpoint is informational — an absent listener on
	// an older konnectivity build is not evidence either way.
	_ = d.Cfg.CPHealthFn(ctx, konnHealthURL)
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
		return
	}
	pid := c.konnectivityPID()
	if pid == 0 {
		d.State.AppendLog("suspect: konnectivity-server process not found — nothing to kill")
		return
	}
	switch d.Cfg.Sig13.Mode {
	case cdeps.ModeEnforce:
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
		d.Actions.WithLabelValues(cdeps.CheckCPFreeze, "konn_server_kill").Inc()
	case cdeps.ModeDryRun:
		d.State.AppendLog(fmt.Sprintf(
			"DRY-RUN: would kill konnectivity-server pid=%d — uds_ok=%v "+
				"ready_backends=%v bad_cycles=%d",
			pid, sockErr == nil, backends, c.konnBadCycles))
		d.Actions.WithLabelValues(cdeps.CheckCPFreeze, "dryrun").Inc()
	default:
		// off — the streak + gauge still surface the degradation.
	}
}

// konnReadyBackends scrapes the konnectivity-server metrics endpoint
// and reads the ready-backend gauge. ok=false on a scrape or parse
// failure — the series is exported as -1, never a fabricated 0.
func (c *FreezeCheck) konnReadyBackends(ctx context.Context) (float64, bool) {
	body, err := c.d.Cfg.KCMMetricsFn(ctx, konnMetricsURL)
	if err != nil {
		return 0, false
	}
	return ParseKonnectivityReadyBackends(body)
}

// ParseKonnectivityReadyBackends reads the
// konnectivity_network_proxy_server_ready_backend_connections
// sample out of a metrics body — the metric is unlabeled; comment
// and HELP/TYPE lines never match. ok=false when the series is
// absent (a build that exports no metric is inconclusive, not
// "zero backends").
func ParseKonnectivityReadyBackends(body string) (float64, bool) {
	for _, ln := range strings.Split(body, "\n") {
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
func (c *FreezeCheck) konnectivityPID() int {
	pids, err := c.d.Proc.PIDs()
	if err != nil {
		return 0
	}
	sort.Ints(pids)
	for _, pid := range pids {
		args := c.d.Proc.Cmdline(pid)
		if len(args) == 0 {
			continue
		}
		base := args[0]
		if i := strings.LastIndex(base, "/"); i >= 0 {
			base = base[i+1:]
		}
		if base == "konnectivity-server" {
			return pid
		}
	}
	return 0
}

// readyWorkers counts Ready, non-control-plane nodes via the
// apiserver client — the heal only makes sense while a worker can
// actually dial the tunnel; a zero count suppresses the kill (a
// cluster-wide outage is not a konnectivity fault).
func (c *FreezeCheck) readyWorkers(ctx context.Context) int {
	client := c.d.EnsureClient()
	if client == nil {
		return 0
	}
	endpoint := strings.TrimPrefix(c.d.Cfg.Hub.SelfAPI, "https://")
	endpoint = strings.TrimPrefix(endpoint, "http://")
	qctx, cancel := context.WithTimeout(ctx, c.d.Cfg.QueryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(qctx, http.MethodGet,
		"https://"+endpoint+"/api/v1/nodes?limit=500", nil)
	if err != nil {
		return 0
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer func() { _ = resp.Body.Close() }()
	var list struct {
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&list); err != nil {
		return 0
	}
	n := 0
	for _, item := range list.Items {
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
	return n
}

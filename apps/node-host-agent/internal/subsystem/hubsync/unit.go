// unit.go — the remote node-host-agent.service rendering (systemdUnit)
// and its unit-name helper.
package hubsync

import (
	"fmt"
	"path"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
)

// systemdUnit renders the remote node-host-agent.service for target
// t — the standalone-mode unit hub_converge installed:
//
//	ExecStart <remote bin> --standalone --node-name=<name>
//	    --health-probe-bind-address=127.0.0.1:9117
//
// with the host-root / vars / nebula-certs env wiring the pod's
// DaemonSet env provides in-cluster. The probe bind mirrors the
// Loopback-only :9117 — nothing off-host probes a standalone
// target (systemd watchdog rides sd_notify, not HTTP), and the
// port sits clear of both the :9115 metrics listener and the
// :8081/:8091 probe convention the DaemonSet uses.
// node-name is shell-quoted: systemd strips the quotes when splitting
// ExecStart argv, so a config-derived name with spaces stays one
// argument instead of smuggling extra flags.
func systemdUnit(t Target, remoteBinary, remoteVarsDir, remoteCertsDir string) string {
	return fmt.Sprintf(`[Unit]
Description=node-host-agent (standalone host converge agent)
Documentation=https://github.com/passiontech-global/kubernetes-cluster-automation
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=NODE_HOST_AGENT_HOST_ROOT=/
Environment=NODE_HOST_AGENT_HOSTCONFIG_VARS_DIR=%s
Environment=NODE_HOST_AGENT_NEBULA_CERTS_DIR=%s
ExecStart=%s --standalone --node-name=%s --health-probe-bind-address=127.0.0.1:9117
Restart=always
RestartSec=5s
# sd-watchdog self-watchdog: the agent sd_notifies READY=1 + WATCHDOG=1
# while its probe mux answers — a wedged process stops feeding and
# systemd restarts it after 120s. MemoryMax + GOMEMLIMIT bound the
# agent's own footprint on the infra VMs it guards (no kubelet QoS
# outside the cluster).
WatchdogSec=120s
MemoryMax=512M
Environment=GOMEMLIMIT=400MiB

[Install]
WantedBy=multi-user.target
`, remoteVarsDir, remoteCertsDir, remoteBinary, hostutil.ShellQuote(t.Name))
}

// unitName derives the systemd unit name from UnitPath.
func unitName(unitPath string) string {
	return path.Base(strings.TrimSpace(unitPath))
}

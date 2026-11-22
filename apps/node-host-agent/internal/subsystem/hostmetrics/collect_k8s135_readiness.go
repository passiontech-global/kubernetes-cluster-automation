// collect_k8s135_readiness.go — Kubernetes 1.35+ cgroup v2 & kubelet/k0s.yaml
// upgrade readiness audit (K5). Read-only scrape collector plus ticker-driven
// latch maintenance (state-k8s135-readiness-drift).
package hostmetrics

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
	"sigs.k8s.io/yaml"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/k0sconfig"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
)

// defaultKubeletConfigPaths are the host-side kubelet config.yaml
// locations k0s writes, joined under HostRoot by applyDefaults.
var defaultKubeletConfigPaths = []string{
	"/run/k0s/kubelet/config.yaml",
	"/var/lib/k0s/kubelet/config.yaml",
	"/run/k0s/kubelet-config.yaml",
	"/var/lib/k0s/kubelet-config.yaml",
}

// removedKubeletFeatureGates lists kubelet feature gates removed in
// Kubernetes 1.35+ (or earlier) whose presence in featureGates breaks
// kubelet startup on upgrade.
var removedKubeletFeatureGates = map[string]bool{
	"KubeletEnsureSecretPulledImages":        true,
	"DynamicKubeletConfig":                   true,
	"ExecProbeTimeout":                       true,
	"CRIContainerLogRotation":                true,
	"KubeletCredentialProviders":             true,
	"DisableKubeletCloudCredentialProviders": true,
	"CSINodeExpandSecret":                    true,
}

var descK8s135ReadinessDrift = prometheus.NewDesc(
	"node_host_agent_k8s135_readiness_drift",
	"Kubernetes 1.35+ upgrade readiness drift finding (1 = drift; omitted when host is clean).",
	[]string{"node", "reason", "key"}, nil)

type k8s135ReadinessFinding struct {
	Reason string
	Key    string
}

// auditK8s135Readiness inspects cgroup v2 posture, the first existing
// kubelet config YAML, and k0s.yaml spec.workerProfiles[*].values
// (when present, on both controllers and workers) for Kubernetes 1.35+
// upgrade blockers. Missing files and inconclusive sandboxes auto-skip
// cleanly; findings are deduplicated by (Reason, Key) and sorted.
func (c *Collector) auditK8s135Readiness() []k8s135ReadinessFinding {
	seen := make(map[k8s135ReadinessFinding]bool)
	var findings []k8s135ReadinessFinding
	add := func(reason, key string) {
		f := k8s135ReadinessFinding{Reason: reason, Key: key}
		if seen[f] {
			return
		}
		seen[f] = true
		findings = append(findings, f)
	}

	if c.checkCgroupV2Readiness() {
		add("cgroup-v1", "cgroup")
	}
	c.auditKubeletConfig(add)
	c.auditK0sWorkerProfiles(add)

	slices.SortFunc(findings, func(a, b k8s135ReadinessFinding) int {
		if cmp := strings.Compare(a.Reason, b.Reason); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.Key, b.Key)
	})
	return findings
}

// checkCgroupV2Readiness reports true ONLY on positive cgroup v1 evidence
// (statfs CGROUP_SUPER_MAGIC or a /sys/fs/cgroup* mountinfo row with
// fstype == "cgroup"). Empty/inconclusive sandboxes auto-skip cleanly.
func (c *Collector) checkCgroupV2Readiness() bool {
	var st unix.Statfs_t
	var statfsOK bool
	if c.cfg.CgroupRoot != "" {
		if _, err := os.Stat(c.cfg.CgroupRoot); err == nil {
			var stalled bool
			st, stalled, statfsOK = c.probeFS(c.cfg.CgroupRoot)
			_ = stalled
		}
	}
	if statfsOK && st.Type == unix.CGROUP_SUPER_MAGIC {
		return true
	}
	var sawV1, sawV2 bool
	if c.cfg.MountinfoFile != "" {
		if data, err := os.ReadFile(c.cfg.MountinfoFile); err == nil {
			sawV1, sawV2 = parseMountinfoCgroupState(data, c.cfg.CgroupRoot)
		}
	}
	if sawV1 {
		return true
	}
	if statfsOK && st.Type == unix.CGROUP2_SUPER_MAGIC {
		return false
	}
	if sawV2 {
		return false
	}
	if _, err := os.Stat(filepath.Join(c.cfg.CgroupRoot, "cgroup.controllers")); err == nil {
		return false
	}
	return false
}

// parseMountinfoCgroupState scans /proc/1/mountinfo rows for cgroup v1
// ("cgroup") and cgroup v2 ("cgroup2") mounts at or beneath
// /sys/fs/cgroup or cgroupRoot.
func parseMountinfoCgroupState(data []byte, cgroupRoot string) (sawV1, sawV2 bool) {
	cgRoot := ""
	if cgroupRoot != "" {
		cleaned := filepath.Clean(cgroupRoot)
		if cleaned != "/" {
			cgRoot = cleaned
		}
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 7 {
			continue
		}
		sep := -1
		for i := 5; i < len(f); i++ {
			if f[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+1 >= len(f) {
			continue
		}
		mp := filepath.Clean(procfs.UnescapeMountPath(f[4]))
		fstype := f[sep+1]
		isCgroupMount := mp == "/sys/fs/cgroup" ||
			strings.HasPrefix(mp, "/sys/fs/cgroup/") ||
			(cgRoot != "" && (mp == cgRoot || strings.HasPrefix(mp, cgRoot+"/")))
		if !isCgroupMount {
			continue
		}
		switch fstype {
		case "cgroup":
			sawV1 = true
		case "cgroup2":
			sawV2 = true
		}
	}
	return sawV1, sawV2
}

func (c *Collector) auditKubeletConfig(add func(reason, key string)) {
	for _, p := range c.cfg.KubeletConfigPaths {
		resolved, err := k0sconfig.ConfinedHostPath(c.cfg.HostRoot, p)
		if err != nil {
			add("unreadable", "kubelet-config")
			return
		}
		data, err := k0sconfig.ReadConfigBounded(resolved, k0sconfig.MaxConfigBytes)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
				continue
			}
			add("unreadable", "kubelet-config")
			return
		}
		var parsed map[string]any
		if err := yaml.Unmarshal(data, &parsed); err != nil {
			add("unreadable", "kubelet-config")
			return
		}
		auditKubeletConfigMap(parsed, add)
		return
	}
}

func (c *Collector) auditK0sWorkerProfiles(add func(reason, key string)) {
	if c.cfg.K0sConfigFile == "" {
		return
	}
	// Audited independently of K0sUnitFile so worker nodes carrying
	// k0s.yaml are checked too, while node_k0s_config_drift stays
	// controller-gated. Unparseable k0s.yaml skips here to avoid
	// duplicating collectK0sDrift's {unreadable,k0s.yaml}.
	_, parsed, ok := c.k0s.get(c.cfg.HostRoot, c.cfg.K0sConfigFile)
	if !ok {
		return
	}
	spec, ok := parsed["spec"].(map[string]any)
	if !ok {
		return
	}
	profiles, ok := spec["workerProfiles"].([]any)
	if !ok {
		return
	}
	for _, item := range profiles {
		prof, ok := item.(map[string]any)
		if !ok {
			continue
		}
		vals, ok := prof["values"].(map[string]any)
		if !ok {
			continue
		}
		auditKubeletConfigMap(vals, add)
	}
}

func auditKubeletConfigMap(m map[string]any, add func(reason, key string)) {
	if len(m) == 0 {
		return
	}
	if drv, ok := m["cgroupDriver"].(string); ok {
		if d := strings.TrimSpace(drv); d != "" && d != "systemd" {
			add("kubelet-cgroup-driver", "cgroupDriver")
		}
	}
	if v, ok := m["failCgroupV1"].(bool); ok && !v {
		add("kubelet-fail-cgroupv1", "failCgroupV1")
	}
	if fg, ok := m["featureGates"].(map[string]any); ok {
		for gate := range fg {
			if removedKubeletFeatureGates[gate] {
				add("removed-feature-gate", gate)
			}
		}
	}
}

// collectK8s135Readiness emits node_host_agent_k8s135_readiness_drift{node,reason,key} = 1
// ONLY when readiness drift findings exist (omitted completely on clean hosts).
func (c *Collector) collectK8s135Readiness(ch chan<- prometheus.Metric) {
	findings := c.auditK8s135Readiness()
	for _, f := range findings {
		ch <- prometheus.MustNewConstMetric(descK8s135ReadinessDrift,
			prometheus.GaugeValue, 1, c.cfg.NodeName, f.Reason, f.Key)
	}
}

// updateK8s135ReadinessLatch enters state-k8s135-readiness-drift when
// drift findings exist and exits cleanly once resolved.
func (c *Collector) updateK8s135ReadinessLatch() {
	findings := c.auditK8s135Readiness()
	if len(findings) == 0 {
		if c.state.Exit(latchdefs.LatchK8s135ReadinessDrift, nil) {
			c.invalidateSnapshot()
		}
		return
	}
	parts := make([]string, 0, len(findings))
	for _, f := range findings {
		parts = append(parts, f.Reason+"="+f.Key)
	}
	if c.state.EnterFresh(latchdefs.LatchK8s135ReadinessDrift,
		"findings="+strings.Join(parts, ",")) {
		c.invalidateSnapshot()
	}
}

func (c *Collector) invalidateSnapshot() {
	c.snapMu.Lock()
	c.snapMetrics = nil
	c.snapAt = time.Time{}
	c.snapMu.Unlock()
}

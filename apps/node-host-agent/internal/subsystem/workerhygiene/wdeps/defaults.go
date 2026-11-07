// defaults.go — the check-domain default constants gathered here
// because Config.ApplyDefaults and ConfigFromEnv own the wiring:
// every default a check file used to declare next to its check now
// lives beside the applyDefaults method that consumes it (the
// per-domain BEHAVIOURAL constants — thresholds, intervals, regexes —
// still live next to their checks in the domain packages). Names
// are exported only where the parent-package tests reach them; the
// rest stay unexported.
package wdeps

import "time"

const (
	// kubelet domain (was kubelet.go / kubelet_feeder.go /
	// kubelet_syncloop.go). The shared wiring defaults consumed by
	// applyWiringDefaults (pods dir, ctr socket, resolv.conf,
	// k0s data dir, nebula iface) live in config.go instead —
	// defaultSysClassNet set the precedent.
	// DefaultKubeletHealthzURL is the kubelet :10250 probe (05).
	DefaultKubeletHealthzURL  = "https://127.0.0.1:10250/healthz"
	defaultKubeletWatchMinAge = 15 * time.Minute // shell KUBELET_WATCH_MIN_AGE_S=900
	probeGap                  = 2 * time.Second
	defaultKubeletSyncloopURL = "https://127.0.0.1:10250/healthz/syncloop"
	// defaultKubeletMetricsURL is the PLEG series source — same
	// :10250 listener + bearer as the syncloop probe.
	defaultKubeletMetricsURL = "https://127.0.0.1:10250/metrics"
	// DefaultKubeletTokenPath is the SA bearer-token file attached
	// to kubelet's secure-port probes.
	DefaultKubeletTokenPath    = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultKubeletWdInterval   = 15 * time.Second
	DefaultKubeletWdMaxFail    = 4 // consecutive fails → remediate gates (~60s)
	defaultKubeletWdProbeURL   = "http://127.0.0.1:10248/healthz"
	defaultKubeletWdReprobeGap = 3 * time.Second // remediate Gate-0: two probes ~3s apart
	// G4 fallback when no API backends are configured — the
	// worker-local api-local-lb listener (k0s haproxy).
	defaultAPIFallbackURL = "https://localhost:7443/livez"

	// pods domain (was pod_teardown.go).
	defaultStuckDeleteAge = 15 * time.Minute // shell STUCK_DELETE_S=900
	defaultStuckWedgeAge  = 30 * time.Minute // shell STUCK_WEDGE_S=1800
	defaultMaxForceDelete = 5                // bounds per-cycle churn (shell used 3; 5 keeps parity headroom)

	// ctr domain (was ctr_tasks.go).
	defaultCtrTaskRoot     = "/host/run/k0s/containerd/io.containerd.runtime.v2.task/k8s.io"
	defaultSandboxCtlRoot  = "/host/run/k0s/containerd/io.containerd.sandbox.controller.v1.shim"
	defaultMaxCtrTaskClean = 5  // shell cap 5 per cycle
	defaultMaxShimKill     = 10 // shell cap 5; 10 bounds orphan-shim storms with headroom
	defaultCtrIngestDir    = "/host/var/lib/k0s/containerd/io.containerd.content.v1.content/ingest"
	ctrIngestMaxAge        = 3 * time.Hour
	ctrIngestScanInterval  = 6 * time.Hour

	// cilium domain (was cilium_common.go / cilium_envoy.go /
	// cilium_mtu.go / cilium_lrp.go / cilium_agent.go).
	// DefaultCiliumHealthzURL is the cilium-agent :9879 probe (32).
	DefaultCiliumHealthzURL = "http://127.0.0.1:9879/healthz"
	// The DaemonSet mounts host /run at /host/run — /host/var/run is
	// never mounted (host /var/run is a symlink to /run on modern
	// distros but the pod bind-mount does not follow it).
	defaultCiliumSocket        = "/host/run/cilium/cilium.sock"
	defaultCiliumEnvoyReadyURL = "http://127.0.0.1:9964/ready"
	defaultCiliumEnvoyAdminURL = "http://127.0.0.1:9901/stats?filter=update_rejected"
	defaultCiliumIface         = "cilium_net"
	defaultCiliumWG0Iface      = "cilium_wg0"
	defaultCiliumRuntimeConfig = "/host/run/cilium/state/agent-runtime-config.json"
	defaultBPFMapHighRatio     = 0.90
	// The LRP datapath probe targets the kube-dns ClusterIP — the
	// CiliumLocalRedirectPolicy's serviceMatcher redirects
	// 10.96.0.10:53 to the local cache pod, so this exercises the
	// real frontend→backend path from the host netns (socket-LB).
	// 169.254.20.10 only exists in the legacy hostNetwork/iptables
	// mode (calico cluster, where this check is dormant) — probing
	// it on a cilium node always fails → false-positive pod kills.
	defaultLocalDNSProbeAddr = "10.96.0.10:53"
	defaultLocalDNSProbeName = "kubernetes.default.svc.cluster.local"

	// disk domain (was disk_bloat.go).
	k0sDiskHighWatermark          = 0.75
	k0sDiskBloatWatermark         = 0.85
	k0sDiskBloatCriticalWatermark = 0.92
	diskBloatPodThresholdBytes    = int64(15) << 30 // 15 GiB
	diskBloatScanInterval         = 15 * time.Minute
	// defaultPodLogsDir is the /var/log/pods host mount — the
	// BUG-H8 pod-log attribution walk scans it.
	defaultPodLogsDir = "/host/var/log/pods"
	// W13-ST1/KR3 disk-guard defaults: the LocalPV hard-quota
	// multiplier (1.5x PV capacity under disk pressure), the host
	// /run tmpfs path as the agent sees it ("/host/run" in the
	// DaemonSet via EnvHostRunDir's hostPath default) and the
	// journal dir the vacuum exec sees (host mount-ns view —
	// systemd.Exec runs nsenter -m wrapped).
	localPVQuotaRatio       = 1.5
	defaultHostRunDir       = "/run"
	defaultJournalVacuumDir = "/run/log/journal"

	// guards domain (was dstate_scopes.go / psi_thrash.go /
	// spegel_calico_netns.go / journald.go).
	defaultDStateStormThreshold = 5
	zombieStormThreshold        = 500 // <defunct> children of one parent = storm
	defaultPSIFullAvg60         = 25.0
	defaultMemFreeMinRatio      = 0.08
	// defaultNetnsDir is the host /run/netns mount — the CNI
	// netns-file leak reaper scans cni-* entries here.
	defaultNetnsDir = "/host/run/netns"
	// DefaultCalicoFelixReadyURL is the calico-node felix :9099
	// readiness probe.
	DefaultCalicoFelixReadyURL    = "http://127.0.0.1:9099/readiness"
	defaultCalicoOrphanVethThresh = 50 // cali* ifaces above the pod count → leak
	// DefaultJournalUnreadableNeeded is the consecutive-failed-read
	// budget for the journal-unreadable blindness latch (cicd
	// controller incident: broken journald left every journal-based
	// check silently seeing "0 hits").
	DefaultJournalUnreadableNeeded = 5

	// runtime domain (was runtime_resource_guards.go — now the
	// runtime_<name>.go family).
	// defaultCgroupRoot is the host cgroup-v2 unified hierarchy as a
	// host-absolute path — ConfigFromEnv resolves it through
	// hostPath ("/host"-prefixed in the DaemonSet, verbatim on a
	// standalone host) behind NODE_HOST_AGENT_CGROUP_ROOT;
	// ApplyDefaults uses the constant verbatim so a direct-New
	// caller gets the standalone path.
	defaultCgroupRoot         = "/sys/fs/cgroup"
	defaultSystemdSessionsDir = "/run/systemd/sessions"
	// defaultSATokenMinTTLSec is the W13-CP3 projected SA-token TTL
	// floor — kubelet rotates bound tokens on an ~80%-of-TTL
	// refresh, so a Running pod with <10m left means rotation has
	// already stalled.
	defaultSATokenMinTTLSec = int64(600)
)

// CtrImageRmInterval is the shared last-ctr-image-rm budget — the
// 37 image healer and the runtime overlayfs-stale healer both spend
// it, so the interval must be one definition.
const CtrImageRmInterval = 15 * time.Minute

// config.go — the shared workerhygiene Config: the top-level knob
// struct, the subsystem wiring defaults + env rows, and the Seams
// test-seam funcs. The per-domain sub-configs (Kubelet/Teardown/
// Ctr/Cilium/Disk/Net/Pressure/Calico/Journal/Host/Runtime) live in
// config_<domain>.go beside their own defaults and env rows;
// ApplyDefaults below orchestrates them in a fixed order.
package wdeps

import (
	"context"
	"errors"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/probee"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// Subsystem wiring defaults — the /host mount convention mirrors the
// shell DaemonSet host mounts; the per-domain knobs live next to
// their checks.
const (
	DefaultInterval           = 2 * time.Minute
	defaultWatchdogStateDir   = "/host/var/lib/node-watchdog"
	defaultWatchdogLogFile    = "/host/var/log/node-watchdog.log"
	defaultProcRoot           = "/proc" // hostPID:true makes pod /proc == host /proc
	defaultK0sWorkerUnitFile  = "/host/etc/systemd/system/k0sworker.service"
	defaultConsecNeeded       = 2                // shell CONSEC_NEEDED=2
	defaultMinRestartInterval = 30 * time.Minute // shell MIN_RESTART_INTERVAL_S=1800
	// defaultSysClassNet is the host sysfs net mount the iface
	// checks (MTU drift, calico veth, netns reaper) read through.
	defaultSysClassNet = "/sys/class/net"
)

// Config carries the hygiene knobs — all test-injectable. The knobs
// are grouped into per-domain sub-structs mirroring the check
// families (Kubelet/Teardown/Ctr/Cilium/Disk/Net/Pressure/Calico/
// Journal/Host); only the genuinely shared wiring and rate budgets
// stay top-level, and the unexported test-seam funcs live under
// Seams.
type Config struct {
	NodeName          string        // this node (spec.nodeName)
	Interval          time.Duration // check cadence
	WatchdogStateDir  string        // state-*/last-*/consecutive-* files
	WatchdogLogFile   string        // appended watchdog log (NPD filelog)
	ProcRoot          string        // host /proc
	CtrTaskRoot       string        // containerd runtime-v2 task dirs
	SandboxCtlRoot    string        // sandbox-controller shim dirs
	K0sWorkerUnitFile string        // presence gates all checks
	Client            kubernetes.Interface
	// Systemd drives host restarts/probes (nsenter-wrapped inside the
	// container). nil → all systemd-dependent checks degrade to the
	// "cannot determine → keep" branch (log-only).
	Systemd *systemd.Client
	// Watchdog is the parsed node-watchdog.conf — feeds the runner's
	// per-module kill switch (WD_SIG_<NAME>=off) and, through
	// APIBackendIPs, the upstream-stale gate of the watch-wedge
	// check. nil → every check runs (pre-conf behaviour).
	Watchdog *watchdogconf.Config
	// WatchdogSrc, when set, re-reads the conf every Cycle so
	// hostconfig rewrites (WD_SIG_*, API_BACKENDS) apply live —
	// APIBackends below is then refreshed from the file each cycle.
	WatchdogSrc *watchdogconf.Reloader
	// APIBackends are the "ip[:port]" apiserver endpoints module 06
	// gates on — wired from watchdogconf.APIBackendIPs() by main
	// (kept current by WatchdogSrc when set).
	APIBackends []string
	// ConsecNeeded / MinRestartInterval / ProbeGap are the shared
	// budgets every check reads — the consecutive-suspect gate, the
	// per-action rate limit and the inter-probe retry sleep.
	ConsecNeeded       int           // consecutive suspect cycles before action
	MinRestartInterval time.Duration // rate-limit budget for recreating actions
	ProbeGap           time.Duration // sleep between probe retries (05/32)

	// Per-check-domain knob groups.
	Kubelet  KubeletConfig  // 05/06 stall + watch-wedge, T15 feeder, A4 syncloop
	Teardown TeardownConfig // 36-pod-teardown ages + force-delete cap
	Ctr      CtrConfig      // containerd socket/tasks/ingest/meta knobs
	Cilium   CiliumConfig   // 32/35/38 agent, envoy, MTU/WG, BPF maps
	Disk     DiskConfig     // /var/lib/k0s watermarks, disk-bloat, pod logs
	Net      NetConfig      // resolv.conf, /sys/class/net, netns, DNS probes
	Pressure PressureConfig // D-state/zombie storms, PSI memory thrash
	Calico   CalicoConfig   // calico-hygiene felix + orphan-veth knobs
	Journal  JournalConfig  // journald blindness-detector inputs
	Host     HostConfig     // hostmetrics markers + node events (KR1/ST2)
	Runtime  RuntimeConfig  // cgroup/session/io-pressure guard paths

	// Seams are the unexported test seams — every check reads them
	// through h.cfg.Seams so tests re-stub a live Hygiene after New.
	Seams Seams
}

// Seams groups the unexported test-seam funcs. Every one has a
// production default filled by applyDefaults; tests re-stub them on
// the live Hygiene (h.cfg.Seams.<name>) after New.
type Seams struct {
	// KillFn delivers signals — seam for tests (SIGKILL on pause /
	// proxy-agent/shim/cilium pids, and signal-0 liveness probes).
	KillFn func(pid int, sig syscall.Signal) error
	// NowFn supplies the current time — seam for tests.
	NowFn func() time.Time
	// ProbeHTTP does one GET and returns nil only on a 2xx response
	// (BUG-H7 — a 500/503 means the probed service is wedged, not
	// "the listener is alive"). Seam.
	ProbeHTTP func(ctx context.Context, url string, timeout time.Duration) error
	// UnixGet GETs path over a unix socket and returns the body —
	// the cilium-dbg endpoint list replacement (35). Seam.
	UnixGet func(ctx context.Context, socket, path string) ([]byte, error)
	// CtrRmImage removes one image from the k8s.io containerd
	// namespace — the corrupted-layer remedy (37), `k0s ctr
	// --namespace k8s.io images rm --sync <image>` via the systemd
	// exec wrapper. nil → Systemd.Exec default. Seam.
	CtrRmImage func(ctx context.Context, image string) error
	// JournalFn returns the k0sworker journal window — the runner's
	// shared -10min snapshot (05/06). nil → Systemd.Journal.
	JournalFn func(ctx context.Context) (string, error)
	// JournalAnyFn is the A5 second probe — `journalctl -n 1
	// --no-pager` with NO unit filter. An empty k0sworker window is
	// only corruption evidence when journald ITSELF has nothing (or
	// only corrupt warnings) to say — a quiet unit on a healthy
	// journald must not trigger the rotate+vacuum remedy. nil →
	// Systemd.ExecCombined (stderr folded in — journald's own
	// diagnostics, e.g. "File ... is corrupt", never reach stdout).
	JournalAnyFn func(ctx context.Context) (string, error)
	// ProbeBodyOK does one GET and reports whether the trimmed body is
	// exactly "ok" — the :10248 healthz contract (curl -s body compare
	// parity: a wedged kubelet can still answer HTTP with a non-ok
	// body, so any-HTTP-code-alive is not enough here). Seam.
	ProbeBodyOK func(ctx context.Context, url string, timeout time.Duration) bool
	// ProbeHTTPStatus does one GET and returns the status code — the
	// ProbeHTTP variant for endpoints where the CODE is the verdict
	// (syncloop 500 vs healthz 200, envoy /ready 503) or where ANY
	// answer proves liveness (kubelet :10250 /healthz, api /livez —
	// a 401/403 is an auth denial, not a dead listener). bearer != ""
	// attaches an Authorization header (kubelet :10250 requires
	// auth). Seam.
	ProbeHTTPStatus func(ctx context.Context, url, bearer string, timeout time.Duration) (int, error)
	// ProbeUnixSock connects to a unix socket under a deadline — the
	// containerd-socket hang probe (A4). Seam.
	ProbeUnixSock func(ctx context.Context, socket string, timeout time.Duration) error
	// StatfsFn reads fs usage for the ingest-GC disk trigger (A3).
	// Seam for tests (default unix.Statfs).
	StatfsFn func(string, *unix.Statfs_t) error
	// CtrRmIngest removes one stale ingest ref — `k0s ctr -n k8s.io
	// content ingest rm <ref>` via the systemd exec wrapper (A3).
	// nil → Systemd.Exec default. Seam.
	CtrRmIngest func(ctx context.Context, ref string) error
	// CtrPruneContent runs the store-wide content GC — `k0s ctr -n
	// k8s.io content prune` via the systemd exec wrapper (W9). It
	// only fires while /var/lib/k0s sits above the high watermark,
	// on the last-content-gc 6h budget. nil → Systemd.Exec
	// default. Seam.
	CtrPruneContent func(ctx context.Context) error
	// WGAllowedIPsFn returns how many cilium_wg0 peers carry a real
	// allowed-ips set — `wg show cilium_wg0 allowed-ips` parsed
	// (peers at "(none)" are wiped). nil → Systemd.Exec default.
	// Seam for the W5.6 check.
	WGAllowedIPsFn func(ctx context.Context) (int, error)
	// CiliumEncryptPeersFn returns the expected WG peer count —
	// `cilium-dbg encrypt status` parsed. An error or a count <=0
	// makes the caller fall back to ReadyNodes-1. nil →
	// Systemd.Exec default. Seam.
	CiliumEncryptPeersFn func(ctx context.Context) (int, error)
	// HTTPGetBody GETs a plain-HTTP endpoint and returns the body —
	// the envoy admin stats page (W7-H3 xDS NACK guard). Seam.
	HTTPGetBody func(ctx context.Context, url string, timeout time.Duration) ([]byte, error)
	// DNSProbe sends one UDP DNS query for a fixed cluster name to
	// addr and reports whether a well-formed answer returns before
	// the deadline — the node-local-dns :53 datapath probe
	// (W7-H3). Seam.
	DNSProbe func(addr, name string, timeout time.Duration) bool
	// ReniceFn drops one pid to the lowest CPU scheduling priority
	// (renice +19) — the io-pressure throttler's CPU half. Default
	// syscall.Setpriority; tests record instead of renicing.
	ReniceFn func(pid int) error
	// IoniceIdleFn puts one pid in the idle I/O scheduling class
	// (ionice -c 3) — the io-pressure throttler's I/O half. Default
	// the ioprio_set syscall (ionice_other.go reports unsupported
	// off-Linux). Seam.
	IoniceIdleFn func(pid int) error
	// PodLogFn returns a tail of one pod's current log — the
	// clock-jump healer's konnectivity evidence read. Default the
	// kube-client GetLogs call; tests stub with canned output.
	PodLogFn func(ctx context.Context, ns, name string, tailLines int64) (string, error)
}

// applyDefaults fills every unset knob — the per-group methods below
// own their own fields exactly like the old flat pass did.
func (c *Config) ApplyDefaults() {
	c.applyWiringDefaults()
	c.Kubelet.applyDefaults()
	c.Teardown.applyDefaults()
	c.Ctr.applyDefaults()
	c.Cilium.applyDefaults()
	c.Disk.applyDefaults()
	c.Net.applyDefaults()
	c.Pressure.applyDefaults()
	c.Calico.applyDefaults()
	c.Journal.applyDefaults()
	c.Host.applyDefaults(c.WatchdogStateDir)
	c.Runtime.applyDefaults()
	c.Seams.applyDefaults(c)
}

// applyWiringDefaults fills the top-level host paths, cadence and
// shared budgets.
func (c *Config) applyWiringDefaults() {
	if c.Interval <= 0 {
		c.Interval = DefaultInterval
	}
	if c.WatchdogStateDir == "" {
		c.WatchdogStateDir = defaultWatchdogStateDir
	}
	if c.WatchdogLogFile == "" {
		c.WatchdogLogFile = defaultWatchdogLogFile
	}
	if c.ProcRoot == "" {
		c.ProcRoot = defaultProcRoot
	}
	if c.CtrTaskRoot == "" {
		c.CtrTaskRoot = defaultCtrTaskRoot
	}
	if c.SandboxCtlRoot == "" {
		c.SandboxCtlRoot = defaultSandboxCtlRoot
	}
	if c.K0sWorkerUnitFile == "" {
		c.K0sWorkerUnitFile = defaultK0sWorkerUnitFile
	}
	if c.ConsecNeeded <= 0 {
		c.ConsecNeeded = defaultConsecNeeded
	}
	if c.MinRestartInterval <= 0 {
		c.MinRestartInterval = defaultMinRestartInterval
	}
	if c.ProbeGap <= 0 {
		c.ProbeGap = probeGap
	}
}

// wiringEnvKnobs returns the shared host-path env rows — the
// hostPath-joined defaults (NOT the package defaults, which hardcode
// the "/host" DaemonSet prefix and would be wrong on a standalone
// host). These held the head of the pre-split knob table; the
// domain rows follow in ConfigFromEnv's assembly order.
func (c *Config) wiringEnvKnobs(hostPath func(string) string) []envx.Knob {
	return []envx.Knob{
		envx.DurationKnob("NODE_HOST_AGENT_HYGIENE_INTERVAL", &c.Interval, DefaultInterval),
		envx.StringKnob("NODE_HOST_AGENT_PROC_ROOT", &c.ProcRoot, defaultProcRoot),
		envx.StringKnob("NODE_HOST_AGENT_CTR_TASK_ROOT", &c.CtrTaskRoot,
			hostPath("/run/k0s/containerd/io.containerd.runtime.v2.task/k8s.io")),
		envx.StringKnob("NODE_HOST_AGENT_SANDBOX_CTL_ROOT", &c.SandboxCtlRoot,
			hostPath("/run/k0s/containerd/io.containerd.sandbox.controller.v1.shim")),
		envx.StringKnob("NODE_HOST_AGENT_K0S_WORKER_UNIT", &c.K0sWorkerUnitFile,
			hostPath("/etc/systemd/system/k0sworker.service")),
	}
}

// budgetEnvKnobs returns the shared consecutive-suspect / rate-limit
// budget rows — they sat between the calico and runtime rows in the
// pre-split table; ConfigFromEnv keeps that position.
func (c *Config) budgetEnvKnobs() []envx.Knob {
	return []envx.Knob{
		envx.IntKnob("NODE_HOST_AGENT_HYGIENE_CONSEC_NEEDED", &c.ConsecNeeded, defaultConsecNeeded),
		envx.DurationKnob("NODE_HOST_AGENT_HYGIENE_MIN_RESTART_INTERVAL", &c.MinRestartInterval, defaultMinRestartInterval),
	}
}

// applyDefaults fills the production implementations of every test
// seam. cfg carries the already-defaulted knob groups — the systemd
// exec defaults capture c.Systemd, and the cilium encrypt-peers
// default goes through the UnixGet seam + Cilium.Socket.
func (s *Seams) applyDefaults(c *Config) {
	if s.HTTPGetBody == nil {
		// Plain HTTP (no TLS) — the envoy admin stats page lives on
		// loopback :9901. A non-200 is an error: the reject-delta
		// verdict is unreadable, not "zero".
		s.HTTPGetBody = probee.HTTPBody
	}
	if s.DNSProbe == nil {
		s.DNSProbe = probee.DNSQuery
	}
	if s.KillFn == nil {
		s.KillFn = func(pid int, sig syscall.Signal) error {
			return syscall.Kill(pid, sig)
		}
	}
	if s.NowFn == nil {
		s.NowFn = time.Now
	}
	if s.ProbeHTTP == nil {
		// BUG-H7: an HTTP response no longer counts as alive on its
		// own — a wedged cilium-agent :9879/healthz answering 500/503
		// must read as DOWN. Only a 2xx is a pass; insecure TLS stays
		// (kubelet cert SANs don't cover 127.0.0.1, curl -ks parity).
		s.ProbeHTTP = probee.HTTPGet
	}
	if s.UnixGet == nil {
		s.UnixGet = probee.UnixGet
	}
	if s.CtrRmImage == nil {
		sd := c.Systemd
		s.CtrRmImage = func(ctx context.Context, image string) error {
			if sd == nil {
				return errors.New("no systemd client wired")
			}
			_, err := sd.Exec(ctx,
				"k0s", "ctr", "--namespace", "k8s.io", "images", "rm", "--sync", image)
			return err
		}
	}
	if s.JournalFn == nil {
		sd := c.Systemd
		s.JournalFn = func(ctx context.Context) (string, error) {
			if sd == nil {
				// Fail, not empty: a nil client fed the unreadable
				// tracker a fake "journald-wide empty reply" verdict.
				return "", errors.New("no systemd client wired")
			}
			return sd.Journal(ctx, "k0sworker.service", journalWindow)
		}
	}
	if s.JournalAnyFn == nil {
		sd := c.Systemd
		s.JournalAnyFn = func(ctx context.Context) (string, error) {
			if sd == nil {
				return "", errors.New("no systemd client wired")
			}
			return sd.ExecCombined(ctx,
				"journalctl", "-n", "1", "--no-pager")
		}
	}
	if s.ProbeBodyOK == nil {
		// kubelet :10248 contract (curl -s parity): the healthz port is
		// unauthenticated plaintext and the body must be exactly "ok" —
		// a wedged kubelet can still answer HTTP with a non-ok body.
		s.ProbeBodyOK = probee.BodyOK
	}
	if s.ProbeHTTPStatus == nil {
		// Same insecure-TLS transport as ProbeHTTP — the status code
		// is the verdict (syncloop 500, envoy /ready 503).
		s.ProbeHTTPStatus = probee.HTTPStatus
	}
	if s.ProbeUnixSock == nil {
		// A successful dial IS the verdict — a close error (e.g. the
		// peer reset first) must not downgrade it.
		s.ProbeUnixSock = probee.UnixDial
	}
	if s.StatfsFn == nil {
		s.StatfsFn = unix.Statfs
	}
	if s.CtrRmIngest == nil {
		sd := c.Systemd
		s.CtrRmIngest = func(ctx context.Context, ref string) error {
			if sd == nil {
				return errors.New("no systemd client wired")
			}
			_, err := sd.Exec(ctx,
				"k0s", "ctr", "-n", "k8s.io", "content", "ingest", "rm", ref)
			return err
		}
	}
	if s.CtrPruneContent == nil {
		sd := c.Systemd
		s.CtrPruneContent = func(ctx context.Context) error {
			if sd == nil {
				return errors.New("no systemd client wired")
			}
			_, err := sd.Exec(ctx,
				"k0s", "ctr", "-n", "k8s.io", "content", "prune")
			return err
		}
	}
	if s.WGAllowedIPsFn == nil {
		sd := c.Systemd
		s.WGAllowedIPsFn = func(ctx context.Context) (int, error) {
			if sd == nil {
				return 0, errors.New("no systemd client wired")
			}
			out, err := sd.Exec(ctx, "wg", "show", "cilium_wg0", "allowed-ips")
			if err != nil {
				return 0, err
			}
			return ParseWGAllowedIPs(out), nil
		}
	}
	if s.ReniceFn == nil {
		s.ReniceFn = func(pid int) error {
			return syscall.Setpriority(syscall.PRIO_PROCESS, pid, 19)
		}
	}
	if s.IoniceIdleFn == nil {
		s.IoniceIdleFn = ioniceIdle // build-tag split: linux ioprio_set
	}
	if s.PodLogFn == nil {
		s.PodLogFn = func(ctx context.Context, ns, name string, tail int64) (string, error) {
			if c.Client == nil {
				return "", errors.New("no kube client wired")
			}
			res := c.Client.CoreV1().Pods(ns).GetLogs(name,
				&corev1.PodLogOptions{TailLines: &tail}).Do(ctx)
			b, err := res.Raw()
			return string(b), err
		}
	}
	if s.CiliumEncryptPeersFn == nil {
		s.CiliumEncryptPeersFn = func(ctx context.Context) (int, error) {
			// The agent's own API beats `cilium-dbg`: the binary only
			// lives INSIDE the cilium-agent container — an sd.Exec on
			// the host always fails and silently degrades every cycle
			// to the ReadyNodes-1 fallback. /v1/healthz's
			// cluster.nodes[] lists exactly the remote cilium members
			// this node should peer with (virtual/liqo nodes run no
			// agent, so they never appear).
			body, err := s.UnixGet(ctx, c.Cilium.Socket, "/v1/healthz")
			if err != nil {
				return 0, err
			}
			n, ok := ParseCiliumHealthNodes(body)
			if !ok {
				return 0, errors.New("no cluster.nodes in cilium healthz")
			}
			return n, nil
		}
	}
}

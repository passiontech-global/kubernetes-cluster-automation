// Package workerhygiene ports three worker-only node-watchdog shell
// modules (WD_REQUIRES: uptime k0sworker) into one agent subsystem:
//
//   - 36-pod-teardown.sh   — sig16: pods stuck Terminating with zero
//     live containerd tasks get force-deleted (verified object
//     cleanup, never while a task is alive); pods Terminating >30m
//     whose task dirs still exist = node-side wedge →
//     state-pod-teardown-wedged latch for the NPD→NHC→SNR reboot path.
//   - 30-konnectivity.sh   — sig6: konnectivity-agent's
//     agent-identifiers=host=<IP> is baked into env at POD creation —
//     after a node InternalIP change the pod keeps registering the old
//     IP and konnectivity-server can't route dials (kubectl logs/exec
//     timeout while the node looks fine, incident 2026-09-13). Remedy:
//     recreate the konnectivity-agent pod so a fresh sandbox gets the
//     new baked env.
//   - 33-dns-resolv-drift.sh — sig12: kubelet snapshots host
//     /etc/resolv.conf into dnsPolicy:Default pods at sandbox create;
//     a resolv.conf repoint never reaches running pods (incident
//     2026-09-15: node-local-dns kept nameserver 8.8.8.8 → "." forwarded
//     to public DNS → api.passiontech.internal NXDOMAIN ~29h). Remedy:
//     SIGKILL the pod's PAUSE pid — kubelet recreates the sandbox with
//     the fresh resolv.conf (killing the app container keeps the old
//     sandbox and changes nothing).
//
// Differences from the shell versions (documented, behaviour-equivalent):
//   - `k0s ctr tasks ls` / `tasks kill` is replaced by scanning the
//     containerd runtime-v2 task dirs + sandbox-controller shim dirs:
//     config.json carries io.kubernetes.pod.uid / .container.name and
//     init.pid the host pid — the node-side ground truth the modules
//     already used for teardown verification. No ctr socket needed.
//   - /proc reads go through ProcRoot (default /proc — the DaemonSet
//     runs hostPID so in-pod /proc IS host /proc).
//   - consecutive-* counters are in-memory (agent restarts are rare;
//     the hysteresis cost of losing one count is bounded by Interval).
//   - One pod LIST per cycle feeds all three checks — the shell
//     queried per module; sharing gives one consistent apiserver
//     verdict and halves API calls.
package workerhygiene

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

// Defaults mirror the shell modules + the DaemonSet host mounts.
const (
	defaultInterval = 2 * time.Minute
	// minUptimeSeconds mirrors the shell runner's WD_REQUIRES: uptime
	// gate (MIN_UPTIME_S=1200) — no destructive checks in the first
	// 20 minutes after boot.
	minUptimeSeconds          = 1200
	defaultWatchdogStateDir   = "/host/var/lib/node-watchdog"
	defaultWatchdogLogFile    = "/host/var/log/node-watchdog.log"
	defaultProcRoot           = "/proc" // hostPID:true makes pod /proc == host /proc
	defaultCtrTaskRoot        = "/host/run/k0s/containerd/io.containerd.runtime.v2.task/k8s.io"
	defaultSandboxCtlRoot     = "/host/run/k0s/containerd/io.containerd.sandbox.controller.v1.shim"
	defaultHostResolvConf     = "/host/etc/resolv.conf"
	defaultK0sWorkerUnitFile  = "/host/etc/systemd/system/k0sworker.service"
	defaultStuckDeleteAge     = 15 * time.Minute // shell STUCK_DELETE_S=900
	defaultStuckWedgeAge      = 30 * time.Minute // shell STUCK_WEDGE_S=1800
	defaultMaxForceDelete     = 5                // bounds per-cycle churn (shell used 3; 5 keeps parity headroom)
	defaultConsecNeeded       = 2                // shell CONSEC_NEEDED=2
	defaultMinRestartInterval = 30 * time.Minute // shell MIN_RESTART_INTERVAL_S=1800
)

// Check names — prometheus `check` label + log context.
const (
	checkTeardown = "pod-teardown"
	checkKonn     = "konnectivity"
	checkDNS      = "dns-resolv"
)

// Config carries the hygiene knobs — all test-injectable.
type Config struct {
	NodeName           string        // this node (spec.nodeName)
	Interval           time.Duration // check cadence
	Enabled            bool          // false → Run idles until ctx done
	WatchdogStateDir   string        // state-*/last-*/consecutive-* files
	WatchdogLogFile    string        // appended watchdog log (NPD filelog)
	ProcRoot           string        // host /proc
	CtrTaskRoot        string        // containerd runtime-v2 task dirs
	SandboxCtlRoot     string        // sandbox-controller shim dirs
	HostResolvConf     string        // host resolv.conf (dns drift baseline)
	K0sWorkerUnitFile  string        // presence gates ALL THREE checks
	Client             kubernetes.Interface
	StuckDeleteAge     time.Duration // Terminating age → force-delete candidate
	StuckWedgeAge      time.Duration // Terminating age + task dir → wedge latch
	MaxForceDelete     int           // force-delete cap per cycle
	ConsecNeeded       int           // consecutive suspect cycles before action
	MinRestartInterval time.Duration // rate-limit budget for recreating actions

	// killFn delivers signals — seam for tests (SIGKILL on pause /
	// proxy-agent pids, and signal-0 liveness probes).
	killFn func(pid int, sig syscall.Signal) error
	// nowFn supplies the current time — seam for tests.
	nowFn func() time.Time
}

func (c *Config) applyDefaults() {
	if c.Interval <= 0 {
		c.Interval = defaultInterval
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
	if c.HostResolvConf == "" {
		c.HostResolvConf = defaultHostResolvConf
	}
	if c.K0sWorkerUnitFile == "" {
		c.K0sWorkerUnitFile = defaultK0sWorkerUnitFile
	}
	if c.StuckDeleteAge <= 0 {
		c.StuckDeleteAge = defaultStuckDeleteAge
	}
	if c.StuckWedgeAge <= 0 {
		c.StuckWedgeAge = defaultStuckWedgeAge
	}
	if c.MaxForceDelete <= 0 {
		c.MaxForceDelete = defaultMaxForceDelete
	}
	if c.ConsecNeeded <= 0 {
		c.ConsecNeeded = defaultConsecNeeded
	}
	if c.MinRestartInterval <= 0 {
		c.MinRestartInterval = defaultMinRestartInterval
	}
	if c.killFn == nil {
		c.killFn = func(pid int, sig syscall.Signal) error {
			return syscall.Kill(pid, sig)
		}
	}
	if c.nowFn == nil {
		c.nowFn = time.Now
	}
}

// Regexes — anchored where the shell learned to anchor (the konn pod
// name and the DNS pod names MUST be anchored: unanchored ~= filters
// previously matched konnectivity-agent-patcher-* and coredns-* job
// pods → wrong pause killed, incident 2026-09-26).
var (
	// config.json annotation extraction — same pattern shape as the
	// shell sed: key, junk up to the quote, 36-char uid value.
	podUIDRe        = regexp.MustCompile(`"io\.kubernetes\.pod\.uid"[^0-9a-f-]*"([0-9a-f-]{36})"`)
	containerNameRe = regexp.MustCompile(`"io\.kubernetes\.container\.name"[^"]*"([^"]+)"`)
	// --node-ip=<ip> inside the k0sworker unit's ExecStart.
	nodeIPRe = regexp.MustCompile(`--node-ip=([0-9.]+)`)
	// --agent-identifiers=host=<ip> inside proxy-agent cmdline —
	// fallback when environ is unreadable. NEVER grep bare 'host='
	// (matches --proxy-server-host first — the false positive that
	// caused the 163x pause-kill loop of 2026-09-19..23).
	agentHostRe = regexp.MustCompile(`--agent-identifiers=host=([0-9.]+)`)
	// DaemonSet pod names only (anchored — see comment block above).
	konnPodRe = regexp.MustCompile(`^konnectivity-agent-[a-z0-9]+$`)
	dnsPodRe  = regexp.MustCompile(`^(node-local-dns-[a-z0-9]+|coredns-[a-z0-9]+-[a-z0-9]+)$`)
	pidDirRe  = regexp.MustCompile(`^[0-9]+$`)
)

// Hygiene runs the three worker checks on one ticker.
type Hygiene struct {
	cfg Config

	// In-memory consecutive counters — the shell kept these as
	// consecutive-* files; in-agent state survives between cycles and
	// an agent restart just re-arms the count (bounded by Interval).
	wedgeFails int
	konnFails  int
	dnsFails   int

	cycles  *prometheus.CounterVec // check, result
	actions *prometheus.CounterVec // check, action
}

// New returns a Hygiene and registers its metrics on reg.
func New(cfg Config, reg prometheus.Registerer) (*Hygiene, error) {
	cfg.applyDefaults()
	h := &Hygiene{cfg: cfg}

	h.cycles = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_workerhygiene_cycles_total",
		Help: "Worker-hygiene check cycles by check and result (ok|abort|gated).",
	}, []string{"check", "result"})
	h.actions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_workerhygiene_actions_total",
		Help: "Worker-hygiene remediation actions by check and action " +
			"(force_delete|pod_delete|sigkill|pause_kill).",
	}, []string{"check", "action"})

	if reg != nil {
		for _, c := range []prometheus.Collector{h.cycles, h.actions} {
			if err := reg.Register(c); err != nil {
				return nil, fmt.Errorf("register workerhygiene metrics: %w", err)
			}
		}
	}
	return h, nil
}

// Name identifies the subsystem for logging.
func (h *Hygiene) Name() string { return "workerhygiene" }

// Run checks immediately, then every Interval until ctx is cancelled.
func (h *Hygiene) Run(ctx context.Context) {
	if !h.cfg.Enabled {
		// Constructed but disabled — idle instead of returning: the
		// agent restarts a returned Run in a hot loop.
		<-ctx.Done()
		return
	}
	h.Cycle(ctx)
	t := time.NewTicker(h.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.Cycle(ctx)
		}
	}
}

// Cycle runs one round of all three checks. The k0sworker unit file
// gates everything (WD_REQUIRES: k0sworker) — controllers and test
// envs without the unit are a silent no-op. Each check must never
// panic and degrades to no-op on missing files.
func (h *Hygiene) Cycle(ctx context.Context) {
	if _, err := os.Stat(h.cfg.K0sWorkerUnitFile); err != nil {
		h.cycles.WithLabelValues("all", "gated").Inc()
		return
	}
	// uptime gate (WD_REQUIRES: uptime k0sworker — the shell also
	// required uptime >= 1200s): a freshly rebooted node gets grace
	// before any destructive check runs — Terminating ages surviving
	// a reboot must not trigger action inside the first minutes.
	if up, err := h.uptimeSeconds(); err == nil && up < minUptimeSeconds {
		h.cycles.WithLabelValues("all", "uptime_gate").Inc()
		return
	}
	// One LIST feeds teardown + konnectivity-pod-lookup + dns checks.
	// The field selector is still sent (production pre-filter) but the
	// node match is re-checked per pod — the fake clientset ignores
	// selectors, and a wrong match is a wrong kill.
	pods, apiOK := h.listNodePods(ctx)
	h.checkPodTeardown(ctx, pods, apiOK)
	h.checkKonnectivity(ctx, pods)
	h.checkDNSResolvDrift(pods, apiOK)
}

// listNodePods lists pods scheduled to this node; apiOK=false means
// the LIST failed — checks treat it as "apiserver unreachable"
// (inconclusive: keep counters/latches, never act).
func (h *Hygiene) listNodePods(ctx context.Context) ([]corev1.Pod, bool) {
	list, err := h.cfg.Client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + h.cfg.NodeName,
	})
	if err != nil {
		return nil, false
	}
	pods := make([]corev1.Pod, 0, len(list.Items))
	for i := range list.Items {
		if list.Items[i].Spec.NodeName == h.cfg.NodeName {
			pods = append(pods, list.Items[i])
		}
	}
	return pods, true
}

// --- watchdog file helpers (lib.sh parity) ---
// state-<name>   : latch file, content = epoch of entry
// last-*         : rate-limit budget, content = epoch of last spend
// watchdog log   : "<rfc3339> <msg>" appended to WatchdogLogFile,
//                  mirrored to slog.

// appendLog mirrors lib.sh log(): "<date -Is> <msg>" appended to the
// watchdog log (NPD filelog tails it — message text is a contract),
// plus a slog mirror for `kubectl logs` debugging. Best-effort: an
// unwritable log file never fails a check.
func (h *Hygiene) appendLog(msg string) {
	slog.Info(msg, "subsystem", "workerhygiene")
	f, err := os.OpenFile(h.cfg.WatchdogLogFile,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", h.cfg.nowFn().Format(time.RFC3339), msg)
}

func (h *Hygiene) statePath(name string) string {
	return filepath.Join(h.cfg.WatchdogStateDir, "state-"+name)
}

// stateExists reports whether the latch file is present (e.g. the
// node-overloaded latch written by the shell runner).
func (h *Hygiene) stateExists(name string) bool {
	_, err := os.Stat(h.statePath(name))
	return err == nil
}

// stateEnter creates state-<name> with the current epoch — only when
// absent (the file's mtime/content is when the condition STARTED) and
// logs the transition once, lib.sh STATE-ENTER parity.
func (h *Hygiene) stateEnter(name, extra string) {
	p := h.statePath(name)
	if _, err := os.Stat(p); err == nil {
		return
	}
	content := strconv.FormatInt(h.cfg.nowFn().Unix(), 10) + "\n"
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return
	}
	if err := os.Rename(tmp, p); err != nil {
		return
	}
	if extra != "" {
		h.appendLog(fmt.Sprintf("STATE-ENTER: %s %s", name, extra))
	} else {
		h.appendLog(fmt.Sprintf("STATE-ENTER: %s", name))
	}
}

// stateExit removes state-<name> if present and logs the transition —
// clears the NPD permanent condition.
func (h *Hygiene) stateExit(name string) {
	p := h.statePath(name)
	if _, err := os.Stat(p); err != nil {
		return
	}
	if err := os.Remove(p); err != nil {
		return
	}
	h.appendLog(fmt.Sprintf("STATE-EXIT: %s", name))
}

// rateOK reports whether the rate budget file is absent, unparseable,
// or older than interval — lib.sh rate_ok parity (garbage → 0 → ok).
func (h *Hygiene) rateOK(name string, interval time.Duration) bool {
	data, err := os.ReadFile(filepath.Join(h.cfg.WatchdogStateDir, name))
	if err != nil {
		return true
	}
	last, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return true
	}
	return h.cfg.nowFn().Unix()-last >= int64(interval.Seconds())
}

// rateSpend writes the current epoch to the budget file.
func (h *Hygiene) rateSpend(name string) {
	p := filepath.Join(h.cfg.WatchdogStateDir, name)
	content := strconv.FormatInt(h.cfg.nowFn().Unix(), 10) + "\n"
	_ = os.WriteFile(p, []byte(content), 0o644)
}

// --- /proc + containerd task helpers ---

// procFile joins ProcRoot/<pid>/<elems...>.
func (h *Hygiene) procFile(pid int, elems ...string) string {
	parts := append([]string{h.cfg.ProcRoot, strconv.Itoa(pid)}, elems...)
	return filepath.Join(parts...)
}

// pidLive mirrors the shell liveness check: kill -0 succeeds AND the
// /proc/<pid>/stat state field is not "Z" (zombie). An unreadable or
// unparseable stat after a successful kill -0 counts as LIVE — fail
// toward not-killing / not-force-deleting on uncertainty. The stat
// state field is parsed after the LAST ')' because comm (field 2) can
// contain spaces and parens (same trick as read_cpu_jiffies).
func (h *Hygiene) pidLive(pid int) bool {
	if pid <= 0 {
		return false
	}
	if h.cfg.killFn(pid, 0) != nil {
		return false
	}
	data, err := os.ReadFile(h.procFile(pid, "stat"))
	if err != nil {
		return true
	}
	s := string(data)
	if i := strings.LastIndexByte(s, ')'); i >= 0 {
		if f := strings.Fields(s[i+1:]); len(f) > 0 {
			return f[0] != "Z"
		}
	}
	return true
}

// procPIDs lists the numeric pid dirs under ProcRoot.
// uptimeSeconds parses <ProcRoot>/uptime — a read failure returns an
// error and Cycle proceeds (fail-open like the shell's missing-uptime
// edge: gating on a parse failure would silently disable the checks).
func (h *Hygiene) uptimeSeconds() (float64, error) {
	data, err := os.ReadFile(filepath.Join(h.cfg.ProcRoot, "uptime"))
	if err != nil {
		return 0, err
	}
	up, err := strconv.ParseFloat(strings.Fields(string(data))[0], 64)
	if err != nil {
		return 0, err
	}
	return up, nil
}

func (h *Hygiene) procPIDs() []int {
	entries, err := os.ReadDir(h.cfg.ProcRoot)
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range entries {
		if !e.IsDir() || !pidDirRe.MatchString(e.Name()) {
			continue
		}
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

// procCmdline returns the argv of pid (NUL-separated in /proc).
func (h *Hygiene) procCmdline(pid int) []string {
	data, err := os.ReadFile(h.procFile(pid, "cmdline"))
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
}

// procEnvValue reads KEY=<value> from /proc/<pid>/environ.
func (h *Hygiene) procEnvValue(pid int, key string) string {
	data, err := os.ReadFile(h.procFile(pid, "environ"))
	if err != nil {
		return ""
	}
	prefix := key + "="
	for _, e := range strings.Split(string(data), "\x00") {
		if v, ok := strings.CutPrefix(e, prefix); ok {
			return v
		}
	}
	return ""
}

// ctrTask is one containerd task dir (runtime-v2 task or sandbox
// controller shim) — the node-side ground truth for "are tasks of
// this pod still around", replacing `ctr tasks ls` so no ctr socket
// is needed inside the agent pod.
type ctrTask struct {
	uid  string // io.kubernetes.pod.uid annotation
	name string // io.kubernetes.container.name annotation ("pause"/"POD" = sandbox infra)
	pid  int    // init.pid contents
	live bool   // kill -0 ok and not zombie
}

// buildTaskMap scans CtrTaskRoot/*/ and SandboxCtlRoot/*/ once per
// cycle and groups task dirs by pod UID — shared by the teardown and
// dns checks. Missing roots/files are skipped, never fatal.
func (h *Hygiene) buildTaskMap() map[string][]ctrTask {
	m := map[string][]ctrTask{}
	for _, root := range []string{h.cfg.CtrTaskRoot, h.cfg.SandboxCtlRoot} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			d := filepath.Join(root, e.Name())
			cfgData, err := os.ReadFile(filepath.Join(d, "config.json"))
			if err != nil {
				continue
			}
			um := podUIDRe.FindSubmatch(cfgData)
			if um == nil {
				continue
			}
			t := ctrTask{uid: string(um[1])}
			if nm := containerNameRe.FindSubmatch(cfgData); nm != nil {
				t.name = string(nm[1])
			}
			if pidData, err := os.ReadFile(filepath.Join(d, "init.pid")); err == nil {
				if pid, err := strconv.Atoi(strings.TrimSpace(string(pidData))); err == nil {
					t.pid = pid
					t.live = h.pidLive(pid)
				}
			}
			m[t.uid] = append(m[t.uid], t)
		}
	}
	return m
}

// countLive returns how many tasks of a UID still have a live init
// pid — the force-delete precondition (zero live tasks = verified
// container death, status.containerStatuses is only last-known).
func countLive(tasks []ctrTask) int {
	n := 0
	for _, t := range tasks {
		if t.live {
			n++
		}
	}
	return n
}

// --- Check 1: pod-teardown (36-pod-teardown.sh) ---

// podHasPVC reports whether the pod mounts a persistentVolumeClaim —
// force-deleting a PVC consumer on a wrong "dead" verdict risks a
// dual-mount of an RWO volume.
func podHasPVC(p *corev1.Pod) bool {
	for _, v := range p.Spec.Volumes {
		// PVC + generic ephemeral volumes share the same dual-mount
		// risk class on a wrong "dead" verdict.
		if v.PersistentVolumeClaim != nil || v.Ephemeral != nil {
			return true
		}
	}
	return false
}

// isMirrorPod reports kubelet-static mirror pods — deleting the
// mirror object changes nothing on disk.
func isMirrorPod(p *corev1.Pod) bool {
	_, ok := p.Annotations["kubernetes.io/config.mirror"]
	return ok
}

// forceDeletePod removes the pod object with grace 0 + Background
// propagation — reached only after zero-live-task verification, so it
// is pure object cleanup (no split-brain/dual-mount risk).
func (h *Hygiene) forceDeletePod(ctx context.Context, p *corev1.Pod) error {
	// Log line is an NPD contract: ends in "force-delete pod ..." so
	// the StuckPodForceDeleted filelog pattern still fires.
	h.appendLog(fmt.Sprintf(
		"POD-TEARDOWN-FORCE-DELETE: force-delete pod %s/%s (uid %.8s) - Terminating %ds, zero live tasks",
		p.Namespace, p.Name, string(p.UID),
		int64(h.cfg.nowFn().Sub(p.DeletionTimestamp.Time).Seconds())))
	return h.cfg.Client.CoreV1().Pods(p.Namespace).Delete(ctx, p.Name,
		metav1.DeleteOptions{
			GracePeriodSeconds: ptr.To[int64](0),
			PropagationPolicy:  ptr.To(metav1.DeletePropagationBackground),
		})
}

func (h *Hygiene) checkPodTeardown(ctx context.Context, pods []corev1.Pod, apiOK bool) {
	if !apiOK {
		// Inconclusive — shell "exit 0" semantics: abort silently,
		// keep counters and latches (no state_exit flap on API blip).
		h.cycles.WithLabelValues(checkTeardown, "abort").Inc()
		return
	}
	tasks := h.buildTaskMap()
	now := h.cfg.nowFn()
	wedged := 0
	ndel := 0
	for i := range pods {
		p := &pods[i]
		if p.DeletionTimestamp == nil {
			continue
		}
		uid := string(p.UID)
		age := now.Sub(p.DeletionTimestamp.Time)
		// Wedge evidence is measured on pod level: Terminating long
		// past StuckWedgeAge AND containerd still holds a task dir
		// (live or not) — sig7/force-delete had their chance; only a
		// reboot clears a shim/kernel-level wedge.
		if age >= h.cfg.StuckWedgeAge && len(tasks[uid]) >= 1 {
			wedged++
		}
		if age < h.cfg.StuckDeleteAge {
			continue
		}
		// Rule C: external resources or kubelet mirrors → never
		// force-delete (finalizer = another controller owns cleanup;
		// PVC = dual-mount risk; mirror = pointless).
		if len(p.Finalizers) > 0 || podHasPVC(p) || isMirrorPod(p) {
			continue
		}
		if countLive(tasks[uid]) > 0 {
			continue // a live task exists — kubelet may still be tearing down
		}
		if ndel >= h.cfg.MaxForceDelete {
			continue // per-cycle cap bounds the blast radius
		}
		if err := h.forceDeletePod(ctx, p); err != nil {
			h.appendLog(fmt.Sprintf("suspect: force-delete %s/%s failed: %v",
				p.Namespace, p.Name, err))
			continue
		}
		ndel++
		h.actions.WithLabelValues(checkTeardown, "force_delete").Inc()
	}

	switch {
	case wedged >= 1:
		h.wedgeFails++
		if h.wedgeFails >= h.cfg.ConsecNeeded {
			if h.stateExists("node-overloaded") {
				// Suppression parity: a wedge under overload is a
				// symptom — rebooting would dump 100% of its load
				// onto the remaining nodes (amplifier). Log-only,
				// once per suppression episode.
				if !h.stateExists("pod-teardown-wedged") {
					h.appendLog(fmt.Sprintf(
						"pod-teardown-wedged suppressed-overloaded stuck=%d", wedged))
				}
			} else {
				h.stateEnter("pod-teardown-wedged", fmt.Sprintf("stuck=%d", wedged))
			}
		} else {
			h.appendLog(fmt.Sprintf("suspect: pod-teardown-wedged stuck=%d (check %d/%d)",
				wedged, h.wedgeFails, h.cfg.ConsecNeeded))
		}
	default:
		h.wedgeFails = 0
		h.stateExit("pod-teardown-wedged")
	}
	h.cycles.WithLabelValues(checkTeardown, "ok").Inc()
}

// --- Check 2: konnectivity IP drift (30-konnectivity.sh) ---

// k0sWorkerNodeIP reads --node-ip=<ip> out of the k0sworker unit —
// the node's InternalIP konnectivity-agent should have baked in.
func (h *Hygiene) k0sWorkerNodeIP() string {
	data, err := os.ReadFile(h.cfg.K0sWorkerUnitFile)
	if err != nil {
		return ""
	}
	if m := nodeIPRe.FindSubmatch(data); m != nil {
		return string(m[1])
	}
	return ""
}

// isProxyAgent matches `pgrep -f 'proxy-agent --'` on the joined
// cmdline (the bare "/proxy-agent" prefix covers argv[0]-only forms).
func isProxyAgent(argv []string) bool {
	// Shell parity: `pgrep -f 'proxy-agent --'` — the trailing
	// space/dash keeps /proxy-agent-foo lookalikes out.
	joined := strings.Join(argv, " ")
	return strings.HasPrefix(joined, "/proxy-agent ") ||
		strings.Contains(joined, "proxy-agent --")
}

// proxyAgentHost returns the host identifier baked into the agent:
// NODE_IP from environ (downward status.hostIP, set at pod create),
// falling back to --agent-identifiers=host=<ip> on the cmdline.
func (h *Hygiene) proxyAgentHost(pid int, argv []string) string {
	if v := h.procEnvValue(pid, "NODE_IP"); v != "" {
		return v
	}
	if m := agentHostRe.FindStringSubmatch(strings.Join(argv, " ")); m != nil {
		return m[1]
	}
	return ""
}

// deleteKonnectivityPod deletes this node's konnectivity-agent pod in
// kube-system (grace 0) — the Go equivalent of SIGKILL on its pause
// task: the DaemonSet recreates the pod with freshly baked env.
// Anchored name match + namespace pin (see konnPodRe comment).
func (h *Hygiene) deleteKonnectivityPod(ctx context.Context, pods []corev1.Pod) bool {
	for i := range pods {
		p := &pods[i]
		if p.Namespace != "kube-system" || !konnPodRe.MatchString(p.Name) ||
			p.DeletionTimestamp != nil {
			continue
		}
		if err := h.cfg.Client.CoreV1().Pods(p.Namespace).Delete(ctx, p.Name,
			metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)}); err != nil {
			continue // a stale entry must not block the next candidate
		}
		return true
	}
	return false
}

func (h *Hygiene) checkKonnectivity(ctx context.Context, pods []corev1.Pod) {
	nodeIP := h.k0sWorkerNodeIP()
	// Healthy = ANY proxy-agent process baked with the current node
	// IP. Scan ALL processes, never take the first match: an orphaned
	// agent (task dir gone, process alive under a dead shim) keeps its
	// old NODE_IP and usually has the lower pid — first-match would
	// read the orphan's environ and report "stale" forever
	// (incident 2026-09-19..23: 163 pause kills). Only when NO
	// process matches do we suspect.
	healthy := false
	agentHost := ""
	stalePID := 0
	for _, pid := range h.procPIDs() {
		argv := h.procCmdline(pid)
		if !isProxyAgent(argv) {
			continue
		}
		phost := h.proxyAgentHost(pid, argv)
		if nodeIP != "" && phost == nodeIP {
			healthy = true
			break
		}
		if phost != "" && agentHost == "" {
			agentHost = phost
			stalePID = pid
		}
	}

	if healthy || nodeIP == "" || agentHost == "" {
		// Healthy or inconclusive (no node-ip parsed / no proxy-agent
		// found — e.g. konnectivity not deployed): reset, drop latch.
		h.konnFails = 0
		h.stateExit("konnectivity-ip-mismatch")
		h.cycles.WithLabelValues(checkKonn, "ok").Inc()
		return
	}

	h.konnFails++
	h.stateEnter("konnectivity-ip-mismatch",
		fmt.Sprintf("host=%s node-ip=%s", agentHost, nodeIP))
	if h.konnFails >= h.cfg.ConsecNeeded &&
		h.rateOK("last-konn-restart", h.cfg.MinRestartInterval) {
		// Spend BEFORE acting — a failed action still consumed the
		// budget (conservative, rate_spend parity).
		h.rateSpend("last-konn-restart")
		h.konnFails = 0
		// NPD contract: "recreating konnectivity-agent ..." fires the
		// KonnectivityStaleId filelog pattern.
		h.appendLog(fmt.Sprintf(
			"KONNECTIVITY-IP-RESTART: recreating konnectivity-agent sandbox - stale identifier host=%s != node-ip=%s",
			agentHost, nodeIP))
		if h.deleteKonnectivityPod(ctx, pods) {
			h.actions.WithLabelValues(checkKonn, "pod_delete").Inc()
		} else if stalePID > 0 {
			// No API pod found (list failed or pod renamed) — kill
			// the stale proxy-agent directly. Least-bad: a container
			// restart alone can't fix env baked at pod create, but
			// it still clears a hung agent while humans look.
			_ = h.cfg.killFn(stalePID, syscall.SIGKILL)
			h.actions.WithLabelValues(checkKonn, "sigkill").Inc()
		}
	} else {
		// NPD contract: "konnectivity stale identifier ..." fires the
		// same KonnectivityStaleId pattern while accumulating.
		h.appendLog(fmt.Sprintf(
			"suspect: konnectivity stale identifier host=%s != node-ip=%s (check %d/%d)",
			agentHost, nodeIP, h.konnFails, h.cfg.ConsecNeeded))
	}
	h.cycles.WithLabelValues(checkKonn, "ok").Inc()
}

// --- Check 3: DNS resolv.conf drift (33-dns-resolv-drift.sh) ---

// nameserverSet returns the sorted-unique nameserver IPs of a
// resolv.conf file. ok=false when the file contains
// "svc.cluster.local" — a ClusterFirst resolv.conf is NOT a host
// snapshot and must be skipped (killing those pauses killed innocent
// job pods — incident 2026-09-26).
func nameserverSet(path string) (ns []string, clusterLocal bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	if strings.Contains(string(data), "svc.cluster.local") {
		return nil, true
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" && !seen[f[1]] {
			seen[f[1]] = true
			ns = append(ns, f[1])
		}
	}
	sort.Strings(ns)
	return ns, false
}

func equalNS(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// dnsStale is one drifted DNS pod: the pause pid to SIGKILL and the
// pod name for logging.
type dnsStale struct {
	pod string
	pid int
}

// pausePIDOf finds the live pause (sandbox infra) task pid for a pod
// UID — container name "pause" (CRI) or "POD" (containerd internal
// name) in the task config.json annotations.
func pausePIDOf(tasks []ctrTask) int {
	for _, t := range tasks {
		if t.live && (t.name == "pause" || t.name == "POD") {
			return t.pid
		}
	}
	return 0
}

func (h *Hygiene) checkDNSResolvDrift(pods []corev1.Pod, apiOK bool) {
	if !apiOK {
		// Same inconclusive rule as teardown: a failed LIST keeps
		// counters and the latch (no flap on API blip).
		h.cycles.WithLabelValues(checkDNS, "abort").Inc()
		return
	}
	hostNS, _ := nameserverSet(h.cfg.HostResolvConf)
	tasks := h.buildTaskMap()

	var stale []dnsStale
	if len(hostNS) > 0 { // empty host set → nothing to compare (shell parity)
		for i := range pods {
			p := &pods[i]
			if p.Status.Phase != corev1.PodRunning ||
				!dnsPodRe.MatchString(p.Name) {
				continue
			}
			pid := pausePIDOf(tasks[string(p.UID)])
			if pid == 0 {
				continue // no live pause task — can't see the pod's resolv.conf
			}
			// Read the POD's resolv.conf through the pause mount ns —
			// ProcRoot/<pid>/root is the task's filesystem view.
			podNS, clusterLocal := nameserverSet(
				h.procFile(pid, "root/etc/resolv.conf"))
			if clusterLocal || len(podNS) == 0 {
				continue
			}
			if !equalNS(podNS, hostNS) {
				stale = append(stale, dnsStale{pod: p.Name, pid: pid})
			}
		}
	}

	if len(stale) == 0 {
		h.dnsFails = 0
		h.stateExit("dns-resolv-stale")
		h.cycles.WithLabelValues(checkDNS, "ok").Inc()
		return
	}

	specs := make([]string, 0, len(stale))
	for _, s := range stale {
		specs = append(specs, fmt.Sprintf("%s:pid=%d", s.pod, s.pid))
	}
	staleStr := strings.Join(specs, " ")
	// Latch first — the state file is what NPD's permanent
	// DnsResolvStale condition checks; the counter gates the action.
	h.stateEnter("dns-resolv-stale", staleStr)
	h.dnsFails++
	switch {
	case h.dnsFails >= h.cfg.ConsecNeeded &&
		h.rateOK("last-dnsresolv-restart", h.cfg.MinRestartInterval):
		h.rateSpend("last-dnsresolv-restart") // spend BEFORE action (lib.sh)
		for _, s := range stale {
			// SIGKILL on the PAUSE pid — NOT the app container
			// (restarting the app keeps the old sandbox +
			// resolv.conf; the pod object itself is fine).
			h.appendLog(fmt.Sprintf(
				"DNS-RESOLV-RESTART: killing pause %d (%s) - dns-resolv-stale, resolv.conf pod stale vs host",
				s.pid, s.pod))
			_ = h.cfg.killFn(s.pid, syscall.SIGKILL)
			h.actions.WithLabelValues(checkDNS, "pause_kill").Inc()
		}
		h.dnsFails = 0
	default:
		h.appendLog(fmt.Sprintf("suspect: dns-resolv-stale %s (check %d/%d)",
			staleStr, h.dnsFails, h.cfg.ConsecNeeded))
	}
	h.cycles.WithLabelValues(checkDNS, "ok").Inc()
}

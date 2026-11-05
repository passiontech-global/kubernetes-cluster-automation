package workerhygiene

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/hoststate"
)

// psiMemoryFullAvg60 parses <ProcRoot>/pressure/memory — the
// `full avg60=` value of the memory pressure stall (percent). PSI
// files look like:
//
//	some avg10=1.23 avg60=4.56 avg300=0.78 total=12345
//	full avg10=0.89 avg60=26.10 avg300=0.54 total=6789
//
// ok=false when the file is unreadable or carries no full avg60
// (PSI disabled on this kernel — the whole check is then dormant).
func (h *Hygiene) psiMemoryFullAvg60() (float64, bool) {
	data, err := os.ReadFile(filepath.Join(h.cfg.ProcRoot, "pressure", "memory"))
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "full" {
			continue
		}
		for _, kv := range f[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok || k != "avg60" {
				continue
			}
			if x, err := strconv.ParseFloat(v, 64); err == nil {
				return x, true
			}
		}
	}
	return 0, false
}

// memInfo holds the <ProcRoot>/meminfo fields the memory checks
// consume — all values in kB as reported by the kernel.
type memInfo struct {
	totalKB     int64
	availKB     int64
	slabUnrecKB int64 // SUnreclaim — slab the kernel cannot reclaim
	parsed      bool  // at least MemTotal + MemAvailable seen
}

// readMeminfo parses <ProcRoot>/meminfo once for every consumer —
// MemTotal/MemAvailable drive the free-ratio floor, SUnreclaim the
// W9-KR3 slab-leak guard. ok=false semantics live on the callers:
// a missing MemTotal or MemAvailable means "unreadable".
func (h *Hygiene) readMeminfo() memInfo {
	var m memInfo
	data, err := os.ReadFile(filepath.Join(h.cfg.ProcRoot, "meminfo"))
	if err != nil {
		return m
	}
	var total, avail, slab int64
	var sawTotal, sawAvail bool
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			total, sawTotal = v, true
		case "MemAvailable:":
			avail, sawAvail = v, true
		case "SUnreclaim:":
			slab = v
		}
	}
	if !sawTotal || !sawAvail || total <= 0 {
		return m
	}
	m.totalKB, m.availKB, m.slabUnrecKB, m.parsed = total, avail, slab, true
	return m
}

// guardKernelSlabLeak is the W9-KR3 kernel slab-leak guard: while
// SUnreclaim/MemTotal sits above slabLeakEnterRatio the
// state-kernel-slab-leak latch is held and a 1h-budgeted
// drop_caches write ("2" — dentries+inodes) tries to hand the
// reclaimable share back. The latch is the PSI evictor's circuit
// breaker — a kernel leaking unreclaimable slab is a kernel bug,
// not a pod-size problem, and evicting workloads cannot fix it.
// Hysteresis: enter >0.35, clear <=0.25; between the two the latch
// (and its drop-caches cadence) simply persists. Returns true while
// the latch is held.
func (h *Hygiene) guardKernelSlabLeak(m memInfo) bool {
	ratio := float64(m.slabUnrecKB) / float64(m.totalKB)
	latched := h.state.Exists(hoststate.LatchKernelSlabLeak)
	switch {
	case ratio > slabLeakEnterRatio:
		if !latched {
			// NPD contract parity: the ACTION line announces the
			// latch entry (nodereporter maps STATE-ENTER too).
			h.state.AppendLog(fmt.Sprintf(
				"ACTION kernel-slab-leak: sunreclaim_ratio=%.3f sunreclaim_kb=%d memtotal_kb=%d",
				ratio, m.slabUnrecKB, m.totalKB))
		}
		latched = true
	case ratio <= slabLeakClearRatio:
		if latched {
			h.state.Exit(hoststate.LatchKernelSlabLeak, nil)
		}
		latched = false
	}
	if !latched {
		return false
	}
	// stateEnter refreshes the latch mtime every cycle it is held —
	// the janitor's 24h reap must not retire a live condition.
	h.state.Enter(hoststate.LatchKernelSlabLeak,
		fmt.Sprintf("sunreclaim_ratio=%.3f", ratio))
	if h.state.RateTrySpend("last-slab-drop-caches", slabDropCachesInterval) {
		h.dropKernelCaches()
	}
	return true
}

// dropKernelCaches writes "2" to <ProcRoot>/sys/vm/drop_caches —
// frees dentries/inodes/slab caches. Best-effort: a write failure
// is logged suspect and never counted as an action — the budget
// marker is already spent either way (rate_spend parity).
func (h *Hygiene) dropKernelCaches() {
	p := filepath.Join(h.cfg.ProcRoot, "sys", "vm", "drop_caches")
	if err := os.WriteFile(p, []byte("2\n"), 0o644); err != nil {
		h.state.AppendLog(fmt.Sprintf(
			"suspect: kernel-slab-leak drop_caches write %s failed: %v",
			p, err))
		return
	}
	h.state.AppendLog("ACTION: kernel-slab-leak wrote 2 to sys/vm/drop_caches")
	h.actions.WithLabelValues(checkPSIThrash, "drop_caches").Inc()
}

// procRSS reads /proc/<pid>/status VmRSS in bytes — the resident
// footprint used to rank eviction victims.
func (h *Hygiene) procRSS(pid int) int64 {
	data, err := os.ReadFile(h.proc.File(pid, "status"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 2 {
			if kb, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				return kb << 10 // VmRSS is reported in kB
			}
		}
	}
	return 0
}

// psiEvictExcludedNamespaces are namespaces the PSI evictor never
// touches — system daemons, CNI/mesh control planes, storage
// operators, cert/secrets plumbing, the flux delivery layer and the
// database quorum namespaces. Evicting from these under memory
// pressure removes the very components needed to recover.
var psiEvictExcludedNamespaces = map[string]bool{
	"kube-system":      true,
	"node-ops":         true,
	"medik8s":          true,
	"cilium":           true,
	"linkerd":          true,
	"linkerd-cni":      true,
	"openebs":          true,
	"cert-manager":     true,
	"external-secrets": true,
	"operators":        true,
	"everest-system":   true,
	"scylla":           true,
	"scylla-manager":   true,
	"flux-system":      true,
}

// psiEvictCriticalPriorityClasses — pods the scheduler marked
// untouchable; evicting them fights the cluster's own guarantees.
var psiEvictCriticalPriorityClasses = map[string]bool{
	"system-node-critical":    true,
	"system-cluster-critical": true,
}

// dbQuorumTokens mark StatefulSet-owned pods carrying database /
// quorum state — losing one replica under memory pressure can cost
// quorum, far worse than the memory it frees. Matched
// case-insensitively against label keys AND values.
var dbQuorumTokens = []string{
	"scylla", "dragonfly", "rabbitmq", "pxc", "psmdb", "postgresql",
}

// minEvictRSSBytes is the victim floor — below 512 MiB RSS a pod is
// not worth an eviction: the API churn + PDB slot buys back almost
// nothing while the thrash persists.
const minEvictRSSBytes = 512 * 1024 * 1024

// ownedByStatefulSet reports whether any ownerReference is a
// StatefulSet — the tiering hint for victim preference.
func ownedByStatefulSet(p *corev1.Pod) bool {
	for _, ref := range p.OwnerReferences {
		if ref.Kind == "StatefulSet" {
			return true
		}
	}
	return false
}

// carriesDBQuorumLabel reports whether the pod's labels name a
// database/quorum workload (dbQuorumTokens, case-insensitive over
// keys and values).
func carriesDBQuorumLabel(p *corev1.Pod) bool {
	for k, v := range p.Labels {
		lk, lv := strings.ToLower(k), strings.ToLower(v)
		for _, tok := range dbQuorumTokens {
			if strings.Contains(lk, tok) || strings.Contains(lv, tok) {
				return true
			}
		}
	}
	return false
}

// highestRSSPod returns the eviction victim for the
// psi-memory-thrash guard: the eligible non-system pod on this node
// whose summed /proc VmRSS is largest, subject to the W8-W1 safety
// rails —
//
//   - minEvictRSSBytes floor: no candidate >= 512 MiB RSS → no
//     eviction at all (victim=nil).
//   - psiEvictExcludedNamespaces + critical priority classes are
//     never candidates.
//   - StatefulSet pods carrying database/quorum labels are never
//     candidates (quorum loss >> memory freed).
//   - Tiered pick: BestEffort/Burstable pods NOT owned by a
//     StatefulSet are preferred; Guaranteed pods and other
//     StatefulSet pods are the fallback tier — evicting them is
//     still better than letting the kernel OOM killer choose.
//
// Pids are attributed to pods via the same /proc/<pid>/cgroup uid
// extraction the zombie check uses.
func (h *Hygiene) highestRSSPod(pods []corev1.Pod, pids []int) (victim *corev1.Pod, rss int64) {
	type candidate struct {
		pod       *corev1.Pod
		rss       int64
		preferred bool // Burstable/BestEffort && !StatefulSet-owned
	}
	byUID := map[string]*candidate{}
	for i := range pods {
		p := &pods[i]
		if p.DeletionTimestamp != nil || psiEvictExcludedNamespaces[p.Namespace] ||
			psiEvictCriticalPriorityClasses[p.Spec.PriorityClassName] ||
			(ownedByStatefulSet(p) && carriesDBQuorumLabel(p)) {
			continue
		}
		byUID[string(p.UID)] = &candidate{
			pod: p,
			// Guaranteed QoS (or empty — the API always sets the
			// class on real pods; empty only shows in tests) is
			// never "preferred" — empty stays preferred because a
			// fake/legacy pod without the class is not provably
			// Guaranteed.
			preferred: p.Status.QOSClass != corev1.PodQOSGuaranteed &&
				!ownedByStatefulSet(p),
		}
	}
	if len(byUID) == 0 || len(pids) == 0 {
		return nil, 0
	}
	for _, pid := range pids {
		uid := h.podUIDForPID(pid)
		if uid == "unknown" {
			continue
		}
		if c, ok := byUID[uid]; ok {
			c.rss += h.procRSS(pid)
		}
	}
	// Tiered selection: preferred candidates first; only when none
	// clears the RSS floor does the fallback tier compete.
	for _, wantPreferred := range []bool{true, false} {
		var best *candidate
		for _, c := range byUID {
			if c.preferred != wantPreferred || c.rss < minEvictRSSBytes {
				continue
			}
			if best == nil || c.rss > best.rss {
				best = c
			}
		}
		if best != nil {
			return best.pod, best.rss
		}
	}
	return nil, 0
}

// psiThrashCheck is the W2 memory-thrash evictor as a Check; it
// owns the thrash streak (ex-Hygiene.psiThrashFails).
type psiThrashCheck struct {
	h     *Hygiene
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *psiThrashCheck) Name() string { return checkPSIThrash }

// Run executes one psi-memory-thrash round.
func (c *psiThrashCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.h.cycles.WithLabelValues(checkPSIThrash, "gated").Inc()
		return
	}
	avg60, psiOK := c.h.psiMemoryFullAvg60()
	m := c.h.readMeminfo()
	if !m.parsed {
		// meminfo unreadable — inconclusive, keep streak/latch
		// exactly like a failed probe (a transient read error must
		// not clear a live latch).
		c.h.cycles.WithLabelValues(checkPSIThrash, "abort").Inc()
		return
	}
	// W9-KR3: the slab-leak guard runs on EVERY readable-meminfo
	// cycle — its latch is this check's eviction circuit breaker,
	// and it must arm even on kernels without PSI or while PSI is
	// quiet (a kernel slab leak is a kernel problem, not a PSI one).
	slabLeaking := c.h.guardKernelSlabLeak(m)
	if !psiOK {
		// PSI disabled on this kernel — the whole thrash check is
		// dormant, but the slab guard above still evaluated.
		c.h.cycles.WithLabelValues(checkPSIThrash, "abort").Inc()
		return
	}
	free := float64(m.availKB) / float64(m.totalKB)
	thrash := avg60 > c.h.cfg.Pressure.PSIFullAvg60 && free < c.h.cfg.Pressure.MemFreeMinRatio
	if !thrash {
		c.fails = 0
		c.h.state.Exit(hoststate.LatchPSIMemoryThrash, nil)
		c.h.cycles.WithLabelValues(checkPSIThrash, "ok").Inc()
		return
	}
	c.fails++
	if c.fails < c.h.cfg.ConsecNeeded {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: psi-memory-thrash psi_full_avg60=%.1f mem_free=%.3f (check %d/%d)",
			avg60, free, c.fails, c.h.cfg.ConsecNeeded))
		c.h.cycles.WithLabelValues(checkPSIThrash, "ok").Inc()
		return
	}
	if !c.h.state.Exists(hoststate.LatchPSIMemoryThrash) {
		// NPD contract: nodereporter maps this line to the
		// NodeMemoryPSIThrashing Event + problem_counter — logged
		// once per latch entry (checkCiliumMTU parity).
		c.h.state.AppendLog(fmt.Sprintf(
			"ACTION psi-memory-thrash: psi_full_avg60=%.1f mem_free=%.3f fails=%d",
			avg60, free, c.fails))
	}
	c.h.state.Enter(hoststate.LatchPSIMemoryThrash,
		fmt.Sprintf("psi_full_avg60=%.1f mem_free=%.3f", avg60, free))
	if !e.apiOK {
		c.h.state.AppendLog("suspect: psi-memory-thrash but API unreachable — skip pod evict")
		c.h.cycles.WithLabelValues(checkPSIThrash, "ok").Inc()
		return
	}
	if slabLeaking {
		// The kernel is leaking unreclaimable slab — evicting a
		// pod cannot fix that and would only remove capacity the
		// node needs to recover. drop_caches owns the reclaim;
		// the latch stays so the condition remains visible.
		c.h.state.AppendLog("suspect: psi-memory-thrash pod evict suppressed - kernel-slab-leak latched")
		c.h.cycles.WithLabelValues(checkPSIThrash, "ok").Inc()
		return
	}
	victim, rss := c.h.highestRSSPod(e.pods, e.pidsOnce())
	if victim == nil {
		// No eligible victim above the RSS floor — latch only;
		// the kernel OOM verdict then stands (nothing ours worth
		// giving it).
		c.h.cycles.WithLabelValues(checkPSIThrash, "ok").Inc()
		return
	}
	if !c.h.state.RateTrySpend("last-psi-evict", psiEvictInterval) {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: psi-memory-thrash victim %s/%s rss=%d - in evict cooldown (<15m), skip",
			victim.Namespace, victim.Name, rss))
		c.h.cycles.WithLabelValues(checkPSIThrash, "ok").Inc()
		return
	}
	// Budget spent atomically BEFORE the eviction (rate_spend
	// parity). policy/v1 Eviction — NOT a raw pod delete: the
	// apiserver enforces the victim's PodDisruptionBudget
	// atomically, so a PDB-protected pod is refused instead of
	// silently disrupted.
	ev := &policyv1.Eviction{
		ObjectMeta: metav1.ObjectMeta{
			Name:      victim.Name,
			Namespace: victim.Namespace,
		},
	}
	c.h.state.AppendLog(fmt.Sprintf(
		"ACTION: psi-memory-thrash evicted pod %s/%s - rss=%d bytes, psi_full_avg60=%.1f mem_free=%.3f",
		victim.Namespace, victim.Name, rss, avg60, free))
	if err := c.h.cfg.Client.PolicyV1().Evictions(victim.Namespace).
		Evict(ctx, ev); err != nil {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: psi-memory-thrash evict %s/%s failed: %v",
			victim.Namespace, victim.Name, err))
	} else {
		c.h.actions.WithLabelValues(checkPSIThrash, "pod_evict").Inc()
	}
	c.h.cycles.WithLabelValues(checkPSIThrash, "ok").Inc()
}

// checkPSIThrash forwards to the migrated Check — tests written
// before the interface still call the old method shape.
func (h *Hygiene) checkPSIThrash(ctx context.Context, pods []corev1.Pod,
	apiOK bool, pidsOnce func() []int, workerActive bool) {
	h.psiThrash.Run(ctx, &cycleEnv{
		pods: pods, apiOK: apiOK, pidsOnce: pidsOnce,
		workerActive: workerActive})
}

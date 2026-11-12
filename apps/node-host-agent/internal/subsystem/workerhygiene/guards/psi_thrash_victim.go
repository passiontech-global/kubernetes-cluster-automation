// psi_thrash_victim.go — psi-memory-thrash victim selection: the
// eviction-floor const, the disqualification rails (evictablePodOnNode)
// and the tiered highest-RSS pick (highestRSSPod). Split out of
// psi_thrash.go — the guard itself keeps the PSI/memory evidence
// probes; this file owns "which pod, if any, takes the eviction".

package guards

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// MinEvictMemBytes is the victim floor — below 512 MiB of pod
// cgroup memory.current a pod is not worth an eviction: the API
// churn + PDB slot buys back almost nothing while the thrash
// persists.
const MinEvictMemBytes = 512 * 1024 * 1024

// evictablePodOnNode applies the psi-thrash-victim-selection safety
// rails that disqualify a pod outright: terminating pods, excluded
// namespaces, critical priority classes — and, as an INDEPENDENT
// gate, any pod carrying database/quorum labels. wdeps.CarriesDBQuorumLabel
// does not depend on the owner kind: a CNPG/Percona pod is never a
// victim and never "preferred" no matter which CRD owns it, because
// quorum loss costs far more than the memory an eviction frees.
func evictablePodOnNode(p *corev1.Pod) bool {
	return p.DeletionTimestamp == nil &&
		!wdeps.EvictProtectedNamespaces[p.Namespace] &&
		!wdeps.EvictCriticalPriorityClasses[p.Spec.PriorityClassName] &&
		!wdeps.CarriesDBQuorumLabel(p)
}

// highestRSSPod returns the eviction victim for the
// psi-memory-thrash guard: the eligible non-system pod on this node
// whose pod-cgroup memory.current is largest, subject to the psi-thrash-victim-selection safety
// rails —
//
//   - MinEvictMemBytes floor: no candidate >= 512 MiB memory.current
//     → no eviction at all (victim=nil).
//   - psiEvictExcludedNamespaces + critical priority classes are
//     never candidates.
//   - Pods carrying database/quorum labels are never candidates —
//     wdeps.CarriesDBQuorumLabel is an independent gate inside
//     evictablePodOnNode, not tied to the owner kind (quorum loss >>
//     memory freed).
//   - Tiered pick: BestEffort/Burstable pods NOT owned by a
//     StatefulSet are preferred; Guaranteed pods and other
//     StatefulSet pods are the fallback tier — evicting them is
//     still better than letting the kernel OOM killer choose.
//
// Pids are attributed to pods via the same /proc/<pid>/cgroup uid
// extraction the zombie check uses.
func highestRSSPod(d *wdeps.Deps, pods []corev1.Pod, pids []int) (victim *corev1.Pod, mem int64) {
	type candidate struct {
		pod       *corev1.Pod
		mem       int64
		preferred bool // Burstable/BestEffort && !StatefulSet-owned
	}
	byUID := map[string]*candidate{}
	for i := range pods {
		p := &pods[i]
		if !evictablePodOnNode(p) {
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
				!wdeps.OwnedByStatefulSet(p),
		}
	}
	if len(byUID) == 0 || len(pids) == 0 {
		return nil, 0
	}
	// One pod cgroup read per pod — memory.current already accounts
	// every container in the pod, so per-pid reads would only repeat
	// the same number. First-seen cgroup rel wins; every pid of a pod
	// resolves to the same pod<uid> component.
	relByUID := map[string]string{}
	for _, pid := range pids {
		uid := podUIDForPID(d, pid)
		if uid == "unknown" {
			continue
		}
		if _, ok := byUID[uid]; !ok {
			continue
		}
		if _, seen := relByUID[uid]; !seen {
			relByUID[uid] = podCgroupRel(d, pid, uid)
		}
	}
	for uid, rel := range relByUID {
		if c, ok := byUID[uid]; ok {
			c.mem = podMemoryCurrent(d, rel)
		}
	}
	// Tiered selection: preferred candidates first; only when none
	// clears the memory floor does the fallback tier compete.
	for _, wantPreferred := range []bool{true, false} {
		var best *candidate
		for _, c := range byUID {
			if c.preferred != wantPreferred || c.mem < MinEvictMemBytes {
				continue
			}
			if best == nil || c.mem > best.mem {
				best = c
			}
		}
		if best != nil {
			return best.pod, best.mem
		}
	}
	return nil, 0
}

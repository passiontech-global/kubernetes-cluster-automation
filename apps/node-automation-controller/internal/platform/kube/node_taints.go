// node_taints.go — the shared taint-set predicates the health and
// node domains need when reasoning about remediation/fencing state
// (remediation-taint-detect/T2). Pure helpers over corev1.Node; callers must not fork
// their own taint literals — remediation keys live in annos.go.
package kube

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// UnschedulableTaintKey is the well-known NoSchedule taint
// `kubectl taint nodes <n> node.kubernetes.io/unschedulable:NoSchedule`
// places — the "out of service" marker that complements
// spec.Unschedulable (which cordon alone sets). Its TimeAdded is the
// only clock for "how long has this cordon been live" (node.go).
const UnschedulableTaintKey = "node.kubernetes.io/unschedulable"

// External-contract taint keys — owned by tooling outside this
// controller (Cilium, the dead-node sweeper's fencing class, medik8s
// SNR); values are ops contracts and must never change. The internal
// passiontech.dev/* remediation keys live in annos.go.
const (
	// TaintCiliumAgentNotReady is the NoSchedule taint the Cilium
	// agent stamps on its node until the local cilium pod reports
	// ready — the stale copy ciliumtaintreaper reaps once the pod
	// is verifiably healthy.
	TaintCiliumAgentNotReady = "node.cilium.io/agent-not-ready"
	// TaintNodeOutOfService is the fencing taint the dead-node
	// sweeper (and any operator following the SIG-Storage
	// out-of-service convention) stamps to keep workloads off a
	// dead node — volumeattachmentcleaner treats it as the "keep
	// the VA" fence for the same reason.
	TaintNodeOutOfService = "node.kubernetes.io/out-of-service"
	// TaintMedik8sOutOfService is medik8s SelfNodeRemediation's
	// fencing twin of TaintNodeOutOfService.
	TaintMedik8sOutOfService = "node.medik8s.io/out-of-service"
)

// outOfServiceTaintKeys are the fencing taints the dead-node
// sweeper and the medik8s SelfNodeRemediation operator stamp when
// they pull a node out of service — distinct from RemediationTaints
// (which mark "still trying to recover") these mean "do not put
// workloads back here". remediation-taint-detect callers treat a node carrying any
// of them exactly like a remediation-tainted one: fenced, not
// healthy.
var outOfServiceTaintKeys = []string{
	TaintNodeOutOfService,    // deadnodesweeper fence
	TaintMedik8sOutOfService, // medik8s SNR fence
}

// remediationMedik8sTaintPrefix covers the per-rule taints the
// medik8s SelfNodeRemediation operator stamps
// (remediation.medik8s.io/<rulename>) — SNR's fencing vocabulary,
// matched by prefix because the rule names are user-defined.
const remediationMedik8sTaintPrefix = "remediation.medik8s.io/"

// HasRemediationTaint reports whether the node carries any
// remediation taint from RemediationTaints (kubelet-unresponsive,
// network-partitioned, node-hang-precordon, cpu-steal) —
// deliberately EXCLUDING the node.kubernetes.io/unschedulable
// out-of-service taint so NodeActivelyCordoned can exempt fenced
// nodes without exempting genuine operator cordons (fenced-node-recovery).
func HasRemediationTaint(n *corev1.Node) bool {
	for _, t := range n.Spec.Taints {
		for _, rt := range RemediationTaints {
			if t.Key == rt {
				return true
			}
		}
	}
	return false
}

// HasRemediationOrOutOfServiceTaint reports whether the node carries
// ANY remediation or fencing taint: every key in RemediationTaints
// (kubelet-unresponsive, network-partitioned, node-hang-precordon,
// cpu-steal), the out-of-service fences (node.kubernetes.io/
// out-of-service, node.medik8s.io/out-of-service), the
// remediation.medik8s.io/* SNR taints, or the unschedulable
// out-of-service taint. Unlike spec.Unschedulable this survives a
// manual uncordon race and — critically — does NOT imply an
// operator/user cordon: a node fenced by nodehealth/SNR carries only
// remediation taints, and treating it as cordoned would block its
// own recovery for the full cordon window (fenced-node-recovery).
func HasRemediationOrOutOfServiceTaint(n *corev1.Node) bool {
	return hasRemediationOrOutOfServiceTaint(n, true)
}

// HasRemediationOrFenceTaint is HasRemediationOrOutOfServiceTaint
// MINUS the plain node.kubernetes.io/unschedulable cordon marker:
// that taint is the cordon evidence NodeActivelyCordoned itself
// ages, so exempting a node for carrying it would read EVERY
// cordoned node as fenced and disable the active-drain verdict
// outright. The remaining set — the four remediation taints, both
// out-of-service fences and the remediation.medik8s.io/* SNR taints —
// is exactly the automated fencing vocabulary (dead-node sweeper,
// medik8s SNR, nodehealth verdicts): a node carrying one is fenced
// by an actor that will not uncordon it as part of a drain, so its
// spec.Unschedulable must not hold the maintenance mutex (a dead
// node fenced while unschedulable would otherwise read as an
// active cordon forever — no unschedulable TimeAdded, or a fresh
// one re-stamped each sweep).
func HasRemediationOrFenceTaint(n *corev1.Node) bool {
	return hasRemediationOrOutOfServiceTaint(n, false)
}

func hasRemediationOrOutOfServiceTaint(n *corev1.Node, includeUnschedulable bool) bool {
	for _, t := range n.Spec.Taints {
		for _, rt := range RemediationTaints {
			if t.Key == rt {
				return true
			}
		}
		for _, oos := range outOfServiceTaintKeys {
			if t.Key == oos {
				return true
			}
		}
		if (includeUnschedulable && t.Key == UnschedulableTaintKey) ||
			strings.HasPrefix(t.Key, remediationMedik8sTaintPrefix) {
			return true
		}
	}
	return false
}

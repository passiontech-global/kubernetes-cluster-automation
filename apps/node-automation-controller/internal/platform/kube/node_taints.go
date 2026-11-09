// node_taints.go — the shared taint-set predicates the health and
// node domains need when reasoning about remediation/fencing state
// (W19-T1/T2). Pure helpers over corev1.Node; callers must not fork
// their own taint literals — remediation keys live in annos.go.
package kube

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// TaintNodeUnschedulable is the well-known NoSchedule taint
// `kubectl taint nodes <n> node.kubernetes.io/unschedulable:NoSchedule`
// places — the "out of service" marker that complements
// spec.Unschedulable (which cordon alone sets).
const TaintNodeUnschedulable = "node.kubernetes.io/unschedulable"

// outOfServiceTaintKeys are the fencing taints the dead-node
// sweeper and the medik8s SelfNodeRemediation operator stamp when
// they pull a node out of service — distinct from RemediationTaints
// (which mark "still trying to recover") these mean "do not put
// workloads back here". W19-T1 callers treat a node carrying any
// of them exactly like a remediation-tainted one: fenced, not
// healthy.
var outOfServiceTaintKeys = []string{
	"node.kubernetes.io/out-of-service", // deadnodesweeper fence
	"node.medik8s.io/out-of-service",    // medik8s SNR fence
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
// nodes without exempting genuine operator cordons (W19-T2).
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
// own recovery for the full cordon window (W19-T2).
func HasRemediationOrOutOfServiceTaint(n *corev1.Node) bool {
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
		if t.Key == TaintNodeUnschedulable ||
			strings.HasPrefix(t.Key, remediationMedik8sTaintPrefix) {
			return true
		}
	}
	return false
}

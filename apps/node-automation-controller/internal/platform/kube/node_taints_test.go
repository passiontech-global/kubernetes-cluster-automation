// node_taints_test.go — coverage for the remediation/fencing taint
// predicates: HasRemediationTaint (the recoverable set, excluding
// out-of-service marks) and HasRemediationOrOutOfServiceTaint (the
// full fenced set incl. SNR prefix taints and the unschedulable
// out-of-service marker).
package kube

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func tainted(keys ...string) *corev1.Node {
	n := &corev1.Node{}
	for _, k := range keys {
		n.Spec.Taints = append(n.Spec.Taints, corev1.Taint{Key: k})
	}
	return n
}

func TestHasRemediationOrOutOfServiceTaint(t *testing.T) {
	for _, tc := range []struct {
		name string
		node *corev1.Node
		want bool
	}{
		{"untainted node", tainted(), false},
		{"unrelated taint", tainted("dedicated=gpu:NoSchedule"), false},
		{"kubelet-unresponsive remediation", tainted(TaintKubeletUnresponsive), true},
		{"network-partitioned remediation", tainted(TaintNetworkPartitioned), true},
		{"node-hang precordon remediation", tainted(TaintNodeHangPreCordon), true},
		{"cpu-steal remediation", tainted(TaintCPUSteal), true},
		{"deadnodesweeper out-of-service fence",
			tainted("node.kubernetes.io/out-of-service"), true},
		{"medik8s out-of-service fence",
			tainted("node.medik8s.io/out-of-service"), true},
		{"SNR per-rule remediation taint",
			tainted("remediation.medik8s.io/kernel-deadlock"), true},
		{"unschedulable out-of-service taint", tainted(TaintNodeUnschedulable), true},
		// Prefix match must not over-match a lookalike key.
		{"near-miss prefix is not SNR", tainted("remediation.medik8s.ioX/foo"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasRemediationOrOutOfServiceTaint(tc.node); got != tc.want {
				t.Fatalf("HasRemediationOrOutOfServiceTaint = %v, want %v", got, tc.want)
			}
		})
	}
}

// The narrower HasRemediationTaint deliberately excludes the
// out-of-service fences — the recoverable-only set callers use when
// "still trying to heal" is the question (NodeActivelyCordoned uses
// the wider HasRemediationOrFenceTaint instead).
func TestHasRemediationTaintExcludesOutOfService(t *testing.T) {
	for _, key := range []string{
		"node.kubernetes.io/out-of-service",
		"node.medik8s.io/out-of-service",
		"remediation.medik8s.io/kernel-deadlock",
		TaintNodeUnschedulable,
	} {
		if HasRemediationTaint(tainted(key)) {
			t.Fatalf("HasRemediationTaint(%q) = true — fence taints must stay out", key)
		}
	}
	if !HasRemediationTaint(tainted(TaintKubeletUnresponsive)) {
		t.Fatal("HasRemediationTaint missed a remediation taint")
	}
}

// HasRemediationOrFenceTaint is the cordon-exempt set
// NodeActivelyCordoned uses: every automated fence (remediation
// taints, both out-of-service keys, SNR prefix taints) EXCEPT the
// plain unschedulable cordon marker — exempting on that key would
// read every cordoned node as fenced.
func TestHasRemediationOrFenceTaint(t *testing.T) {
	for _, tc := range []struct {
		name string
		node *corev1.Node
		want bool
	}{
		{"untainted node", tainted(), false},
		{"unrelated taint", tainted("dedicated=gpu:NoSchedule"), false},
		{"kubelet-unresponsive remediation", tainted(TaintKubeletUnresponsive), true},
		{"cpu-steal remediation", tainted(TaintCPUSteal), true},
		{"deadnodesweeper out-of-service fence",
			tainted("node.kubernetes.io/out-of-service"), true},
		{"medik8s out-of-service fence",
			tainted("node.medik8s.io/out-of-service"), true},
		{"SNR per-rule remediation taint",
			tainted("remediation.medik8s.io/kernel-deadlock"), true},
		// The cordon marker itself must NOT exempt — it is the
		// evidence NodeActivelyCordoned ages.
		{"unschedulable cordon taint alone", tainted(TaintNodeUnschedulable), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasRemediationOrFenceTaint(tc.node); got != tc.want {
				t.Fatalf("HasRemediationOrFenceTaint = %v, want %v", got, tc.want)
			}
		})
	}
}

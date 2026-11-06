// stall_plan.go — the workload-layer verification and scale plan for
// helm_stall_unwedge.go: proves the surge-deadlock shape (replicas
// >=2, effective maxUnavailable==0, new-RS pods Pending on anti-
// affinity, old-RS pods carrying REQUIRED podAntiAffinity matching
// the new pod labels on every blocked node), enforces the
// availability floor and PDB gates, and returns the minimum old-
// ReplicaSet scale-down that provably frees one node. Every off-
// shape read is a fail-closed refusal, never an action.
package helmreleaseunlocker

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// stallPlan is the verified remediation plan for a surge-deadlocked
// Deployment: which old ReplicaSet to scale and by how much.
type stallPlan struct {
	target         *appsv1.ReplicaSet // old RS holding the blocking pods
	targetReplicas int32              // its current .spec.replicas
	remove         int                // pods to shed — frees >=1 node guaranteed
	blocking       int                // old pods holding nodes via required anti-affinity
	nodes          int                // distinct nodes those pods occupy
	pending        int                // new-RS pods unschedulable on anti-affinity
}

// deadlockPlan verifies the workload-layer signature and returns the
// scale plan, or a refusal reason. Every refusal is a deliberate
// fail-closed: the HR stays stalled for a human rather than risk a
// wrong-target scale-down.
func (u *helmReleaseUnlocker) deadlockPlan(ctx context.Context,
	dep *appsv1.Deployment) (*stallPlan, string, error) {
	replicas := int(ptr.Deref(dep.Spec.Replicas, 1))
	if replicas <= 1 {
		return nil, fmt.Sprintf("deployment %s/%s has replicas=%d — no surge window to open",
			dep.Namespace, dep.Name, replicas), nil
	}
	if dep.Spec.Strategy.Type == appsv1.RecreateDeploymentStrategyType {
		return nil, fmt.Sprintf("deployment %s/%s uses Recreate — no surge pods exist",
			dep.Namespace, dep.Name), nil
	}
	maxUnavailable := deployMaxUnavailable(dep)
	if maxUnavailable > 0 {
		return nil, fmt.Sprintf(
			"deployment %s/%s resolves maxUnavailable=%d — it can drain old pods itself, not this deadlock",
			dep.Namespace, dep.Name, maxUnavailable), nil
	}

	rss, err := u.cs.AppsV1().ReplicaSets(dep.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, "", fmt.Errorf("list replicasets in %s: %w", dep.Namespace, err)
	}
	pods, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.Pods(u.cs, dep.Namespace))
	if err != nil {
		return nil, "", fmt.Errorf("list pods in %s: %w", dep.Namespace, err)
	}

	// ReplicaSets owned by this Deployment, newest revision first.
	var owned []*appsv1.ReplicaSet
	for i := range rss.Items {
		rs := &rss.Items[i]
		if ref := metav1.GetControllerOf(rs); ref != nil &&
			ref.Kind == "Deployment" && ref.Name == dep.Name {
			owned = append(owned, rs)
		}
	}
	if len(owned) < 2 {
		return nil, fmt.Sprintf(
			"deployment %s/%s has %d ReplicaSets — no old/new pair to relieve",
			dep.Namespace, dep.Name, len(owned)), nil
	}
	sort.Slice(owned, func(i, j int) bool {
		return rsRevision(owned[i]) > rsRevision(owned[j])
	})
	newRS := owned[0]
	if ptr.Deref(newRS.Spec.Replicas, 0) <= 0 {
		return nil, fmt.Sprintf(
			"newest ReplicaSet %s has desired replicas 0 — no surge pod is trying to schedule",
			newRS.Name), nil
	}
	newPods := podsOwnedBy(pods, newRS)
	pendingBlocked := 0
	pendingOther := 0
	for _, p := range newPods {
		if p.Spec.NodeName != "" || p.DeletionTimestamp != nil {
			continue // scheduled already — not part of the stall
		}
		if podBlockedByAffinity(p) {
			pendingBlocked++
		} else {
			pendingOther++
		}
	}
	switch {
	case pendingBlocked == 0 && pendingOther > 0:
		return nil, fmt.Sprintf(
			"new ReplicaSet %s pods are Pending for a non-affinity reason — not this deadlock",
			newRS.Name), nil
	case pendingBlocked == 0:
		return nil, fmt.Sprintf(
			"new ReplicaSet %s has no unscheduled pods — the stall is not a scheduling deadlock",
			newRS.Name), nil
	}

	// Old side: pods of every older RS whose TEMPLATE carries
	// required podAntiAffinity matching the new pod labels — only
	// those can reject the surge pod ("didn't satisfy existing pods
	// anti-affinity rules"). Preferred terms never hard-block.
	newLabels := newRS.Spec.Template.Labels
	var target *appsv1.ReplicaSet
	targetBlocking := -1
	blocking := 0
	nodes := map[string]bool{}
	for _, rs := range owned[1:] {
		if !requiredAntiAffinityMatches(&rs.Spec.Template, newLabels) {
			continue
		}
		rsBlocking := 0
		for _, p := range podsOwnedBy(pods, rs) {
			if p.Spec.NodeName == "" || p.DeletionTimestamp != nil {
				continue // unscheduled/dying pods block nothing
			}
			rsBlocking++
			nodes[p.Spec.NodeName] = true
		}
		blocking += rsBlocking
		if rsBlocking > targetBlocking {
			target, targetBlocking = rs, rsBlocking
		}
	}
	if blocking == 0 || target == nil {
		return nil, fmt.Sprintf(
			"no old ReplicaSet pods carry required anti-affinity matching the new pod labels for %s/%s — preferred-only terms do not block",
			dep.Namespace, dep.Name), nil
	}
	if targetBlocking != blocking {
		// Blocking pods spread over several old ReplicaSets — a
		// single scale-down cannot guarantee a freed node, and
		// scaling several RSes is a bigger availability cut than
		// this module is willing to make. Refuse to a human.
		return nil, fmt.Sprintf(
			"blocking pods for %s/%s span multiple old ReplicaSets (%d of %d on %s) — refusing",
			dep.Namespace, dep.Name, targetBlocking, blocking, target.Name), nil
	}

	// Removing k arbitrary pods from `blocking` pods on `nodes`
	// distinct nodes frees >=1 node for sure once survivors <
	// nodes: k = blocking - nodes + 1. The single-RS gate above is
	// what makes this a guarantee — survivors can cover at most
	// min(nodes, blocking-k) = nodes-1 nodes.
	remove := blocking - len(nodes) + 1
	targetReplicas := ptr.Deref(target.Spec.Replicas, 0)
	if int32(remove) > targetReplicas {
		return nil, fmt.Sprintf(
			"freeing a node needs %d removals but old ReplicaSet %s only holds %d desired pods — refusing",
			remove, target.Name, targetReplicas), nil
	}
	// Availability floor: kept old replicas plus the new pods that
	// the freed node(s) can admit must stay >= replicas-maxUnavailable
	// (== replicas here, maxUnavailable is 0 by the gate above).
	kept := int(targetReplicas) - remove
	newSched := min(remove, pendingBlocked)
	if kept+newSched < replicas {
		return nil, fmt.Sprintf(
			"scaling old ReplicaSet %s/%s down by %d violates the availability floor (replicas=%d, maxUnavailable=0, %d pending new pods)",
			dep.Namespace, target.Name, remove, replicas, pendingBlocked), nil
	}
	// PDB gate: every PDB selecting the old pod labels must tolerate
	// the disruption — a covering PDB that would refuse the removal
	// turns the scale-down into a silent availability cut.
	if refuse, err := u.pdbBlocksScaleDown(ctx, dep.Namespace,
		target.Spec.Template.Labels, remove); err != nil {
		return nil, "", err
	} else if refuse != "" {
		return nil, refuse, nil
	}

	return &stallPlan{
		target:         target,
		targetReplicas: targetReplicas,
		remove:         remove,
		blocking:       blocking,
		nodes:          len(nodes),
		pending:        pendingBlocked,
	}, "", nil
}

// pdbBlocksScaleDown returns a refusal reason when any PDB in ns that
// selects the old pods' labels reports fewer disruptions than the
// planned removal — nil selector and unparseable selectors fail
// CLOSED (treated as covering, same convention as
// statefulset-ondelete-roller).
func (u *helmReleaseUnlocker) pdbBlocksScaleDown(ctx context.Context,
	ns string, podLabels map[string]string, remove int) (string, error) {
	pdbs, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.PodDisruptionBudgets(u.cs, ns))
	if err != nil {
		return "", fmt.Errorf("list poddisruptionbudgets in %s (safety gate): %w", ns, err)
	}
	for i := range pdbs {
		pdb := &pdbs[i]
		sel := labels.Everything()
		if pdb.Spec.Selector != nil {
			parsed, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
			if err != nil {
				// Fail closed — an unreadable selector must not skip
				// the disruption budget check.
				parsed = labels.Everything()
			}
			sel = parsed
		}
		if !sel.Matches(labels.Set(podLabels)) {
			continue
		}
		if int(pdb.Status.DisruptionsAllowed) < remove {
			return fmt.Sprintf(
				"PDB %s/%s covers the old pods and allows %d disruptions, need %d — refusing",
				pdb.Namespace, pdb.Name, pdb.Status.DisruptionsAllowed, remove), nil
		}
	}
	return "", nil
}

// deployMaxUnavailable resolves the effective maxUnavailable for a
// RollingUpdate Deployment — nil strategy fields take the apiserver
// default ("25%", rounded down like the controller does).
func deployMaxUnavailable(dep *appsv1.Deployment) int {
	replicas := int(ptr.Deref(dep.Spec.Replicas, 1))
	maxUnavail := intstr.FromString("25%")
	if ru := dep.Spec.Strategy.RollingUpdate; ru != nil && ru.MaxUnavailable != nil {
		maxUnavail = *ru.MaxUnavailable
	}
	v, err := intstr.GetScaledValueFromIntOrPercent(&maxUnavail, replicas, false)
	if err != nil {
		return 0 // unparseable → 0 (conservative: assume the floor is full)
	}
	return v
}

// rsRevision parses the deployment.kubernetes.io/revision stamp —
// the ordering between a Deployment's ReplicaSets. Unparseable or
// absent reads as revision 0 (oldest).
func rsRevision(rs *appsv1.ReplicaSet) int64 {
	v, err := strconv.ParseInt(rs.Annotations[deployRevisionAnno], 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// podsOwnedBy returns the non-terminating pods controlled by rs —
// controller ownerReference kind+name, not UID (fake fixtures rarely
// carry matching UIDs; same convention as ownedPods in
// statefulset-ondelete-roller).
func podsOwnedBy(pods []corev1.Pod, rs *appsv1.ReplicaSet) []*corev1.Pod {
	var out []*corev1.Pod
	for i := range pods {
		p := &pods[i]
		if p.DeletionTimestamp != nil {
			continue // dying pods block nothing and stall nothing
		}
		if ref := metav1.GetControllerOf(p); ref != nil &&
			ref.Kind == "ReplicaSet" && ref.Name == rs.Name {
			out = append(out, p)
		}
	}
	return out
}

// podBlockedByAffinity reports whether the pod is stuck unscheduled
// BECAUSE of anti-affinity: PodScheduled=False whose message mentions
// affinity ("didn't satisfy existing pods anti-affinity rules",
// "didn't match pod anti-affinity rules"). Insufficient cpu, taints,
// image pulls and every other scheduling failure read false — the
// caller refuses those.
func podBlockedByAffinity(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type != corev1.PodScheduled || c.Status != corev1.ConditionFalse {
			continue
		}
		return strings.Contains(strings.ToLower(c.Message), "affinity")
	}
	return false
}

// requiredAntiAffinityMatches reports whether the OLD pod template's
// requiredDuringSchedulingIgnoredDuringExecution anti-affinity has at
// least one term whose selector matches the NEW pod labels — that is
// what rejects the surge pod on every occupied node. A nil term
// selector selects all pods (blocking by definition); preferred terms
// never count.
func requiredAntiAffinityMatches(tpl *corev1.PodTemplateSpec, newLabels map[string]string) bool {
	aff := tpl.Spec.Affinity
	if aff == nil || aff.PodAntiAffinity == nil {
		return false
	}
	for _, term := range aff.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution {
		sel := labels.Everything()
		if term.LabelSelector != nil {
			parsed, err := metav1.LabelSelectorAsSelector(term.LabelSelector)
			if err != nil {
				continue
			}
			sel = parsed
		}
		if sel.Matches(labels.Set(newLabels)) {
			return true
		}
	}
	return false
}

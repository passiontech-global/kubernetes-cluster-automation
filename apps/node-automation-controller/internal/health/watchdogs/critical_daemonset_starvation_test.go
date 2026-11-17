// critical_daemonset_starvation_test.go — coverage for the
// critical-daemonset-starvation check: the 5-minute zero-desired
// persistence window, the node-restriction false-positive guard
// (GPU/zone-scoped DaemonSets legitimately desire 0), the
// deprecated-selector signature, and the compat-label heal that
// only queues nodes actually missing the label.
package watchdogs

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

// starvedDS builds a DaemonSet with the given desired count and
// optional node scoping. generation=1 so the "status not yet
// populated" guard does not mask the fixture.
func starvedDS(ns, name string, desired int32,
	nodeSelector map[string]string) *appsv1.DaemonSet {

	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, Generation: 1,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				Spec: corev1.PodSpec{
					NodeSelector: nodeSelector,
				},
			},
		},
		Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: desired},
	}
}

// gaNode is a schedulable node carrying only GA labels — the shape
// whose deprecated twins the compat heal must add.
func gaNode(name string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"kubernetes.io/os":   "linux",
				"kubernetes.io/arch": "amd64",
			},
		},
	}
}

func TestCriticalDSZeroDesiredPersistenceAndRestriction(t *testing.T) {
	unrestricted := starvedDS("node-ops", "csi-node", 0, nil)
	restricted := starvedDS("gpu", "nvidia-ds", 0,
		map[string]string{"nvidia.com/gpu.present": "true"})
	cs := fake.NewSimpleClientset(unrestricted, restricted)
	d := probetest.NewDeps(cs, probetest.OpDyn())
	ch := &criticalDaemonSetStarvationCheck{Deps: d}
	base := time.Now()

	probetest.FreezeNow(d, base)
	if res := ch.Run(probetest.SweepCtx(ctx)); res.Pass != true {
		t.Fatalf("first sweep arms the window, must pass: %+v", res)
	}
	probetest.FreezeNow(d, base.Add(criticalDSMinAge-time.Minute))
	ch.Run(probetest.SweepCtx(ctx))
	probetest.FreezeNow(d, base.Add(criticalDSMinAge+time.Minute))
	res := ch.Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("persisted zero-desired must fail the sweep")
	}
	// Only the UNRESTRICTED ds flags — the GPU-scoped one is a
	// legitimate desired=0.
	m := probetest.FindMetric(t, "node_automation_critical_daemonset_starvation",
		map[string]string{"namespace": "node-ops", "name": "csi-node",
			"reason": "zero_desired"})
	if m == nil {
		t.Fatal("zero_desired gauge missing for unrestricted DS")
	}
	if probetest.FindMetric(t, "node_automation_critical_daemonset_starvation",
		map[string]string{"namespace": "gpu", "name": "nvidia-ds",
			"reason": "zero_desired"}) != nil {
		t.Fatal("node-restricted DS flagged zero_desired — false positive")
	}
}

func TestCriticalDSDeprecatedSelectorHealsCompatLabels(t *testing.T) {
	// DS selecting on the deprecated beta key while nodes only
	// carry the GA twin — the wedge the compat heal exists for.
	depDS := starvedDS("node-ops", "legacy-ds", 3,
		map[string]string{"beta.kubernetes.io/os": "linux"})
	// A second DS whose deprecated key every node already has —
	// must NOT burn a heal grant.
	alreadyDS := starvedDS("node-ops", "already-healed", 3,
		map[string]string{"beta.kubernetes.io/arch": "amd64"})
	n1 := gaNode("node-a")
	n1.Labels["beta.kubernetes.io/arch"] = "amd64" // arch twin present
	n2 := gaNode("node-b")
	n2.Labels["beta.kubernetes.io/arch"] = "amd64"
	cs := fake.NewSimpleClientset(depDS, alreadyDS, n1, n2)
	d := probetest.NewDeps(cs, probetest.OpDyn())
	ch := &criticalDaemonSetStarvationCheck{Deps: d}

	res := ch.Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("deprecated-selector signature must flag immediately")
	}
	// The heal must have added beta.kubernetes.io/os (from
	// kubernetes.io/os) to BOTH nodes — and nothing else.
	for _, name := range []string{"node-a", "node-b"} {
		n, err := cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get node %s: %v", name, err)
		}
		if n.Labels["beta.kubernetes.io/os"] != "linux" {
			t.Fatalf("node %s missing compat label beta.kubernetes.io/os: %v",
				name, n.Labels)
		}
		// arch twin was already present — heal must not rewrite.
		if n.Labels["beta.kubernetes.io/arch"] != "amd64" {
			t.Fatalf("node %s arch label clobbered: %v", name, n.Labels)
		}
	}
}

func TestCriticalDSNoStarvationPasses(t *testing.T) {
	healthy := starvedDS("node-ops", "fine-ds", 3, nil)
	healthy.Status.NumberReady = 3
	cs := fake.NewSimpleClientset(healthy, gaNode("node-a"))
	d := probetest.NewDeps(cs, probetest.OpDyn())
	ch := &criticalDaemonSetStarvationCheck{Deps: d}
	if res := ch.Run(probetest.SweepCtx(ctx)); !res.Pass {
		t.Fatalf("healthy DS must pass: %+v", res)
	}
}

// TestCriticalDSNilRequiredAffinityNoPanic is the regression for
// the sweep-crashing nil deref: a DaemonSet whose nodeAffinity
// carries ONLY preferredDuringScheduling terms (or an empty
// nodeAffinity: {}) leaves RequiredDuringScheduling nil — the
// restriction check must treat that as unrestricted, not panic.
func TestCriticalDSNilRequiredAffinityNoPanic(t *testing.T) {
	ds := starvedDS("node-ops", "pref-only-ds", 0, nil)
	ds.Spec.Template.Spec.Affinity = &corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			// RequiredDuringScheduling deliberately nil.
			PreferredDuringSchedulingIgnoredDuringExecution: []corev1.PreferredSchedulingTerm{{
				Weight: 1,
				Preference: corev1.NodeSelectorTerm{
					MatchExpressions: []corev1.NodeSelectorRequirement{{
						Key:      "kubernetes.io/os",
						Operator: corev1.NodeSelectorOpIn,
						Values:   []string{"linux"},
					}},
				},
			}},
		},
	}
	empty := starvedDS("node-ops", "empty-affinity-ds", 0, nil)
	empty.Spec.Template.Spec.Affinity = &corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{},
	}
	cs := fake.NewSimpleClientset(ds, empty)
	d := probetest.NewDeps(cs, probetest.OpDyn())
	ch := &criticalDaemonSetStarvationCheck{Deps: d}
	base := time.Now()

	probetest.FreezeNow(d, base)
	ch.Run(probetest.SweepCtx(ctx))
	probetest.FreezeNow(d, base.Add(criticalDSMinAge+time.Minute))
	res := ch.Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("preferred-only/empty-affinity DSes are unrestricted — persisted zero-desired must flag")
	}
	for _, name := range []string{"pref-only-ds", "empty-affinity-ds"} {
		if probetest.FindMetric(t, "node_automation_critical_daemonset_starvation",
			map[string]string{"namespace": "node-ops", "name": name,
				"reason": "zero_desired"}) == nil {
			t.Fatalf("%s missing zero_desired gauge", name)
		}
	}
}

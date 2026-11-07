// cilium_missing_endpoints.go — the cilium-missing-endpoint check:
// Running pod-networked pods with no CiliumEndpoint (or an
// unprogrammed one — identity 0/reserved:world) get their pod
// deleted so the CNI re-issues a clean endpoint; a same-node mass
// miss bounces the cilium agent instead.
package nethealth

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// ciliumMissingEndpointsCheck is the CiliumEndpoint split-brain
// watchdog.
type ciliumMissingEndpointsCheck struct {
	*probefw.Deps

	// streak counts consecutive sweeps each pod lacked a programmed
	// CEP — the 2-cycle persistence the signature requires before the
	// gauge or a delete fires (UID-keyed so a recreate re-arms).
	streak state.StreakLedger
	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1 (zero value usable; the serial sweep needs no lock).
	emitted state.GaugeLedger[string]
}

// NewCiliumMissingEndpointsCheck builds the missing-CEP check — its
// state is the streak/emitted ledgers; pod and agent-delete
// cooldowns ride the shared Deps.Heals set.
func NewCiliumMissingEndpointsCheck(d *probefw.Deps) probefw.Check {
	return &ciliumMissingEndpointsCheck{Deps: d}
}

const (
	CheckNameCiliumMissingEndpoints = "cilium-missing-endpoint"

	// cilium-missing-endpoint knobs.
	ciliumCEPPodMinAge   = 5 * time.Minute
	ciliumCEPMinStreak   = 2
	ciliumCEPHealCool    = 30 * time.Minute
	ciliumCEPNodeMinPods = 3
)

var (
	// Pods persisting without a programmed CiliumEndpoint.
	ciliumMissingCEPPodsGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_cilium_missing_cep_pods",
		Help: "1 while the pod has no CiliumEndpoint or an unprogrammed one (identity 0/world) across sweeps.",
	}, []string{"namespace", "pod", "node"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		ciliumMissingCEPPodsGauge)
}

// ciliumCEPUnprogrammed reports whether the CiliumEndpoint is present
// but useless: the security identity is unassigned or pinned to a
// reserved value (0 = unassigned, 2 = reserved:world — the Monzo-style
// split-brain where the pod gets world-classified and intra-cluster
// network policies drop its traffic), or the endpoint carries no
// addressing IP at all.
func ciliumCEPUnprogrammed(cep *unstructured.Unstructured) bool {
	id, ok := kube.NestedInt64(cep.Object, "status", "identity", "id")
	if !ok || id == 0 || id == 2 {
		return true
	}
	addrs, _ := kube.NestedSlice(cep.Object, "status", "networking", "addressing")
	if len(addrs) == 0 {
		return true
	}
	for _, a := range addrs {
		if m, ok := a.(map[string]any); ok {
			if ip, _ := kube.NestedString(m, "ipv4"); ip != "" {
				return false
			}
			if ip, _ := kube.NestedString(m, "ipv6"); ip != "" {
				return false
			}
		}
	}
	return true
}

// checkCiliumMissingEndpoints cross-references every Running
// pod-networked pod older than 5m against the CiliumEndpoint census.
// A missing or unprogrammed CEP must persist 2 sweeps before it
// counts — a fresh pod's endpoint appears within a cycle. Once
// confirmed: >=ciliumCEPNodeMinPods pods on the SAME node restart that
// node's cilium agent (the agent's informer died — restarting one
// daemon heals every workload on the node at once); fewer than that
// delete each affected pod so its replacement lands a clean CEP.
func (p *ciliumMissingEndpointsCheck) Run(ctx context.Context) probefw.Result {
	// The CEP census needs dyn — a missing client is a wiring bug,
	// not "no signal" (same posture as the scylla check).
	if r := p.RequireDyn("cilium endpoint check"); r != nil {
		return *r
	}
	log := logf.FromContext(ctx)
	now := p.Now()
	// Paged like every cluster-wide list — an unpaginated CEP list
	// forces etcd to serialize every endpoint into one response.
	ceps, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.DynamicPage(p.Dyn.Resource(kube.GVRCiliumEndpoint)))
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		// No Cilium on this cluster — still reconcile the ledgers:
		// a tuple/streak held from when Cilium existed is resolved,
		// and returning Pass early would leak the series pinned at
		// 1. (The Infra path below deliberately skips the reconcile —
		// an unevaluated sweep carries last state, per Carry.)
		var rep probefw.SweepReport
		p.streak.Prune(func(string) bool { return false })
		return rep.Result(&p.emitted, ciliumMissingCEPPodsGauge.DeleteLabelValues,
			fmt.Sprintf("pods missing a programmed CiliumEndpoint across %d sweeps: ",
				ciliumCEPMinStreak), ", ")
	case err != nil:
		return probefw.Result{Infra: fmt.Errorf("list ciliumendpoints: %w", err)}
	}
	cepByKey := map[string]*unstructured.Unstructured{}
	for i := range ceps {
		cep := &ceps[i]
		cepByKey[cep.GetNamespace()+"/"+cep.GetName()] = cep
	}
	pods, err := p.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}

	var rep probefw.SweepReport
	streakKeep := map[string]bool{}
	missingByNode := map[string]int{}
	var confirmed []*corev1.Pod
	for i := range pods {
		pod := &pods[i]
		if pod.DeletionTimestamp != nil || pod.Spec.HostNetwork ||
			pod.Spec.NodeName == "" ||
			pod.Status.Phase != corev1.PodRunning ||
			now.Sub(pod.CreationTimestamp.Time) < ciliumCEPPodMinAge {
			continue
		}
		key := pod.Namespace + "/" + pod.Name
		cep, found := cepByKey[key]
		if found && !ciliumCEPUnprogrammed(cep) {
			continue // programmed endpoint — healthy
		}
		sig := key + "/" + string(pod.UID)
		streakKeep[sig] = true
		if p.streak.Hit(sig) < ciliumCEPMinStreak {
			continue // inside the persistence window
		}
		rep.Flag(ciliumMissingCEPPodsGauge, key,
			[]string{pod.Namespace, pod.Name, pod.Spec.NodeName})
		missingByNode[pod.Spec.NodeName]++
		confirmed = append(confirmed, pod)
	}
	p.streak.Prune(func(k string) bool { return streakKeep[k] })
	rep.Close(&p.emitted, ciliumMissingCEPPodsGauge.DeleteLabelValues)

	// Heal — a node-level miss pattern means the agent lost its
	// endpoint informer; per-pod deletes there would churn workloads
	// without touching the root cause.
	agentHealed := map[string]bool{}
	for node, n := range missingByNode {
		if n < ciliumCEPNodeMinPods {
			continue
		}
		if agent := ciliumAgentPodOnNode(pods, node); agent != nil {
			p.DeletePodHeal(ctx, log, CheckNameCiliumMissingEndpoints,
				"agent/"+node, agent, ciliumCEPHealCool, now)
			agentHealed[node] = true
		}
	}
	for _, pod := range confirmed {
		if agentHealed[pod.Spec.NodeName] {
			continue // the node agent restart covers this pod
		}
		p.DeletePodHeal(ctx, log, CheckNameCiliumMissingEndpoints,
			pod.Namespace+"/"+pod.Name, pod, ciliumCEPHealCool, now)
	}
	for _, pod := range confirmed {
		rep.Find(pod.Namespace + "/" + pod.Name + "@" + pod.Spec.NodeName)
	}
	return rep.Verdict(fmt.Sprintf(
		"pods missing a programmed CiliumEndpoint across %d sweeps: ",
		ciliumCEPMinStreak), ", ")
}

// ciliumAgentPodOnNode finds the Running cilium agent pod scheduled
// on node — the k8s-app=cilium DaemonSet member.
func ciliumAgentPodOnNode(pods []corev1.Pod, node string) *corev1.Pod {
	for i := range pods {
		pod := &pods[i]
		if pod.DeletionTimestamp != nil ||
			pod.Spec.NodeName != node ||
			pod.Status.Phase != corev1.PodRunning ||
			pod.Labels["k8s-app"] != "cilium" {
			continue
		}
		return pod
	}
	return nil
}

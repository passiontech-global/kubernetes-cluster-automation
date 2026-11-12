// apiserver_node_reachability_heal.go — the remediation half of the
// apiserver-node-reachability check: resolving the Ready endpoint
// pods that back failurePolicy=Fail admission webhooks and
// evacuating the ones sitting on apiserver-dark nodes. Split from
// apiserver_node_reachability.go (the probe/persist/fence half).
package nethealth

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// webhookBackendPods resolves every Ready endpoint pod backing a
// failurePolicy=Fail admission webhook — Validating AND Mutating,
// since an unreachable injector fails pod creation just as hard.
// Returns podKey ("ns/name") → the webhook config names that route
// through it, restricted to pods sitting on darkNodes.
func (c *apiserverNodeReachabilityCheck) webhookBackendPods(
	ctx context.Context, darkNodes map[string]bool) (map[string][]string, error) {

	// Paged lists — a cluster with many webhook configs must not
	// silently truncate at the apiserver's default page size.
	vwcs, err := kube.ListAll(ctx, metav1.ListOptions{},
		kube.ValidatingWebhookConfigurations(c.Deps.CS))
	if err != nil {
		return nil, fmt.Errorf("list validatingwebhookconfigurations: %w", err)
	}
	mwcs, err := kube.ListAll(ctx, metav1.ListOptions{},
		kube.MutatingWebhookConfigurations(c.Deps.CS))
	if err != nil {
		return nil, fmt.Errorf("list mutatingwebhookconfigurations: %w", err)
	}

	// svcKey → webhook names, Fail-policy + service-backed only.
	// ValidatingWebhook and MutatingWebhook are distinct types with
	// identical admission fields — flatten both into refs first.
	type svcRef struct {
		ns, name string
	}
	type whRef struct {
		name          string
		failurePolicy *admissionv1.FailurePolicyType
		service       *admissionv1.ServiceReference
	}
	backends := map[svcRef][]string{}
	add := func(kind string, whs []whRef) {
		for i := range whs {
			w := &whs[i]
			// failurePolicy unset defaults to Fail at the apiserver —
			// only an explicit Ignore opts out of evacuation.
			if w.failurePolicy != nil && *w.failurePolicy == admissionv1.Ignore {
				continue
			}
			svc := w.service
			if svc == nil || svc.Name == "" {
				continue
			}
			ns := svc.Namespace
			if ns == "" {
				ns = "default"
			}
			ref := svcRef{ns: ns, name: svc.Name}
			backends[ref] = append(backends[ref], kind+"/"+w.name)
		}
	}
	for i := range vwcs {
		cfg := &vwcs[i]
		refs := make([]whRef, 0, len(cfg.Webhooks))
		for j := range cfg.Webhooks {
			w := &cfg.Webhooks[j]
			refs = append(refs, whRef{
				name: w.Name, failurePolicy: w.FailurePolicy,
				service: w.ClientConfig.Service})
		}
		add("vwc/"+cfg.Name, refs)
	}
	for i := range mwcs {
		cfg := &mwcs[i]
		refs := make([]whRef, 0, len(cfg.Webhooks))
		for j := range cfg.Webhooks {
			w := &cfg.Webhooks[j]
			refs = append(refs, whRef{
				name: w.Name, failurePolicy: w.FailurePolicy,
				service: w.ClientConfig.Service})
		}
		add("mwc/"+cfg.Name, refs)
	}
	if len(backends) == 0 {
		return nil, nil
	}

	// EndpointSlice → backing pods: the kubernetes.io/service-name
	// label binds a slice to its Service; ready endpoints only —
	// a not-ready endpoint is already out of the apiserver's rotation.
	slices, err := c.AllEndpointSlices(ctx)
	if err != nil {
		return nil, fmt.Errorf("list endpointslices: %w", err)
	}
	podKeys := map[string]bool{}
	svcOfPod := map[string]svcRef{}
	for i := range slices {
		sl := &slices[i]
		svcName := sl.Labels[discoveryv1.LabelServiceName]
		if svcName == "" {
			continue
		}
		ref := svcRef{ns: sl.Namespace, name: svcName}
		if _, ok := backends[ref]; !ok {
			continue
		}
		for j := range sl.Endpoints {
			ep := &sl.Endpoints[j]
			if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
				continue
			}
			tr := ep.TargetRef
			if tr == nil || tr.Kind != "Pod" || tr.Name == "" {
				continue
			}
			ns := tr.Namespace
			if ns == "" {
				ns = sl.Namespace
			}
			key := ns + "/" + tr.Name
			podKeys[key] = true
			svcOfPod[key] = ref
		}
	}
	if len(podKeys) == 0 {
		return nil, nil
	}

	podNodes, err := c.PodNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("pod→node census: %w", err)
	}
	out := map[string][]string{}
	for key := range podKeys {
		node := podNodes[key]
		if node == "" || !darkNodes[node] {
			continue
		}
		out[key] = backends[svcOfPod[key]]
	}
	return out, nil
}

// evictWebhookBackends deletes Ready backend pods sitting on
// apiserver-dark nodes so their controllers reschedule them onto
// reachable nodes. Eligibility mirrors partition-pod-evictor:
// terminal/deleting/mirror/DaemonSet pods and pods with no
// controller are never touched — a bare pod delete is data loss,
// not a heal.
func (c *apiserverNodeReachabilityCheck) evictWebhookBackends(
	ctx context.Context, rep *probefw.SweepReport,
	darkNodes map[string]bool, now time.Time, log logr.Logger) {

	backends, err := c.webhookBackendPods(ctx, darkNodes)
	if err != nil {
		rep.InfraErr(err)
		return
	}
	if len(backends) == 0 {
		return
	}
	pods, err := c.AllPods(ctx)
	if err != nil {
		rep.InfraErr(fmt.Errorf("list pods for webhook backends: %w", err))
		return
	}
	byKey := make(map[string]*corev1.Pod, len(pods))
	for i := range pods {
		p := &pods[i]
		byKey[p.Namespace+"/"+p.Name] = p
	}

	// Sorted keys before the cap: map iteration order is random, so
	// an unsorted walk would let darkHealCap pick a different subset
	// of eligible backends every sweep — a pod just past the cap
	// could starve indefinitely while its siblings churn.
	deleted := 0
	for _, key := range slices.Sorted(maps.Keys(backends)) {
		if deleted >= darkHealCap {
			break
		}
		pod := byKey[key]
		if pod == nil || !webhookBackendEvictable(pod) {
			continue
		}
		if c.DeletePodHeal(ctx, log, CheckNameApiserverNodeReachability,
			kube.PodControllerKey(pod), pod, darkHealCool, now) {
			deleted++
			rep.Find(fmt.Sprintf(
				"ACTION: deleted webhook backend %s on apiserver-dark node %s (%s)",
				key, pod.Spec.NodeName, strings.Join(backends[key], ",")))
		}
	}
}

// webhookBackendEvictable reports whether pod p is safe to delete as
// a webhook-backend heal — the partitionEvictable exclusions applied
// to this check's narrower target set.
func webhookBackendEvictable(p *corev1.Pod) bool {
	if p.Status.Phase == corev1.PodSucceeded ||
		p.Status.Phase == corev1.PodFailed ||
		p.DeletionTimestamp != nil {
		return false
	}
	if _, mirror := p.Annotations["kubernetes.io/config.mirror"]; mirror {
		return false
	}
	controller := false
	for _, o := range p.OwnerReferences {
		if o.Kind == "DaemonSet" {
			return false
		}
		if o.Controller != nil && *o.Controller {
			controller = true
		}
	}
	return controller
}

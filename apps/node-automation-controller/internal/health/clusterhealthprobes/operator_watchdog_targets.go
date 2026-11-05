// operator_watchdog_targets.go — the watched-operator table of the
// operator-workqueue-watchdog check (W5.8): the opStuckResource /
// operatorTarget wiring, the per-CRD stuck predicates (stale
// observedGeneration, absent status.conditions/phase, gateway-API
// parent/listener status), the gateway-class ownership filters that
// keep shared resource types attributed to the right controller, and
// the operatorTargets rows binding each operator's leader-election
// Lease + pod selector to its CRD signature set.
package clusterhealthprobes

import (
	"context"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	// ciliumStuckMinAge is the stuck window for the gateway-API
	// resources cilium-operator reconciles.
	ciliumStuckMinAge = 10 * time.Minute
	// operatorStuckMinAge is the default stuck window for the other
	// watched operators.
	operatorStuckMinAge = 20 * time.Minute
	// opReasonStaleGWStatus is the cilium signature: a gateway-API
	// object whose status.parents is empty/absent or whose
	// observedGeneration lags — the gateway controller never
	// attached it.
	opReasonStaleGWStatus = "stale_gateway_status"
	// ciliumGatewayController is the spec.controllerName a
	// GatewayClass carries when cilium's gateway-api controller
	// serves it — the ownership key for the gateway-API resources
	// in cilium-operator's target set.
	ciliumGatewayController = "io.cilium/gateway-controller"
	// opReasonNoConditions is the never-reconciled signature for CR
	// types that carry no observedGeneration — their controller
	// stamps status.conditions on the first reconcile pass, so an
	// absent/empty list means it never picked the object up (W7-C2).
	opReasonNoConditions = "no_status_conditions"
	// opReasonNoPhase is the same signature for CR types that report
	// a status.phase (argocd): an empty phase means the operator
	// never reconciled the object (W7-C2).
	opReasonNoPhase = "no_status_phase"
	// opReasonNoStatus is the medik8s variant: status.phase AND
	// status.conditions both absent — the operator never completed
	// a reconcile pass on either channel (W10-CP3).
	opReasonNoStatus = "no_status_at_all"
)

// ---------------------------------------------------------------------------
// operator-workqueue-watchdog (W5.8) — lease-holding zombie detector
// + auto-healer.
// ---------------------------------------------------------------------------

// opStuckResource binds a watched CRD GVR to its stall signature: the
// reason label reported on OperatorWorkqueueFrozen and the predicate
// deciding whether one object counts as unreconciled. owns optionally
// filters stuck objects down to those this operator is actually
// responsible for — required on resource types shared by several
// controllers (gateway-api objects on this cluster split between
// cilium-operator and the cloudflare-tunnel gateway controller, so a
// stuck route must not be blamed on — or healed by — the wrong
// operator). Nil means every stuck object counts.
type opStuckResource struct {
	gvr    schema.GroupVersionResource
	reason string
	stuck  func(o *unstructured.Unstructured) bool
	owns   func(ctx context.Context, p *operatorWorkqueueCheck, o *unstructured.Unstructured) bool
}

// operatorTarget is one watched operator: the leader-election Lease
// proving liveness, the pod label selector resolving the holder to a
// pod when holderIdentity parsing fails, the stuck persistence window
// and the CRD resources it is responsible for reconciling. A nil
// opStuckResource.owns means every stuck object counts.
//
// leaseNames lists every leader-election Lease id the operator may
// hold — upstream ships more than one across versions (Percona
// operators rotate their election ids, medik8s uses a fixed hash),
// so a single hardcoded name would silently disable the watch on the
// others. The first existing candidate wins.
//
// podNS overrides the namespace pods are looked up in when it differs
// from the Lease's namespace — the cert-manager chart elects leaders
// in kube-system while its pods live in cert-manager (W10-FIX2).
//
// leaseOptional marks operators that legitimately run without a
// leader-election Lease (external-secrets runs replicas:1 with
// leaderElect:false, dragonfly-operator has --leader-elect patched
// out — W10-FIX2): when no candidate Lease is found the watchdog
// falls back to a Running pod matching podSelector as the liveness
// proof — a live pod whose CRs still sit unreconciled is the same
// zombie shape the Lease renewTime proves for electing operators.
type operatorTarget struct {
	name          string
	leaseNS       string
	leaseNames    []string
	podNS         string
	podSelector   string
	leaseOptional bool
	stuckMinAge   time.Duration
	resources     []opStuckResource
}

// targetPodNS resolves the namespace operator pods live in: the
// explicit podNS override when set (lease and pods split across
// namespaces), else the Lease's own namespace.
func targetPodNS(t operatorTarget) string {
	if t.podNS != "" {
		return t.podNS
	}
	return t.leaseNS
}

// staleObservedGeneration is the canonical "controller never saw the
// last spec write" signature: status.observedGeneration lags
// metadata.generation. A missing observedGeneration reads as 0 — an
// object never touched by its controller is the strongest stuck
// signal there is (generation >= 1 for any real object).
func staleObservedGeneration(o *unstructured.Unstructured) bool {
	og, _ := shared.NestedInt64(o.Object, "status", "observedGeneration")
	return og < o.GetGeneration()
}

// fluxUnsuspendedStaleGen is staleObservedGeneration with the flux
// parking brake honored: a spec.suspend=true object is deliberately
// not reconciled — suspended work is parked, not stuck.
func fluxUnsuspendedStaleGen(o *unstructured.Unstructured) bool {
	if suspended, _ := shared.NestedBool(o.Object, "spec", "suspend"); suspended {
		return false
	}
	return staleObservedGeneration(o)
}

// helmRepoStaleGen is fluxUnsuspendedStaleGen plus the type=oci
// carve-out: since Flux v2.2 an OCI HelmRepository is a static
// reference — source-controller keeps no reconciler for it and never
// writes status, so observedGeneration stays absent forever and the
// generic signature would flag every healthy OCI repo (the actual
// OCI pull health lives on the generated HelmChart objects, which
// ARE watched by the helmcharts entry).
func helmRepoStaleGen(o *unstructured.Unstructured) bool {
	if t, _ := shared.NestedString(o.Object, "spec", "type"); t == "oci" {
		return false
	}
	return fluxUnsuspendedStaleGen(o)
}

// noStatusConditions is the "never reconciled" signature for CR
// types that lack a reliable observedGeneration (cert-manager
// Certificates, ExternalSecrets, KEDA ScaledObjects): the controller
// stamps status.conditions on its first reconcile pass, so an absent
// or empty list means it never picked the object up (W7-C2).
func noStatusConditions(o *unstructured.Unstructured) bool {
	conds, found := shared.NestedSlice(o.Object, "status", "conditions")
	return !found || len(conds) == 0
}

// emptyStatusPhase is the same never-reconciled signature for CR
// types that report a status.phase (ArgoCD): an absent/empty phase
// means the operator never touched the object (W7-C2).
func emptyStatusPhase(o *unstructured.Unstructured) bool {
	phase, found := shared.NestedString(o.Object, "status", "phase")
	return !found || phase == ""
}

// noStatusAtAll is the never-reconciled signature for CR types whose
// controllers write SPARSE status (medik8s NodeHealthCheck/
// SelfNodeRemediation): neither status.phase nor status.conditions
// means the operator never completed a reconcile pass. Either field
// alone can be legitimately absent on a healthy object — a paused
// NHC still carries phase=Paused, a finished SNR keeps its last
// phase — so only the both-absent shape proves "never reconciled".
func noStatusAtAll(o *unstructured.Unstructured) bool {
	if phase, found := shared.NestedString(o.Object, "status", "phase"); found && phase != "" {
		return false
	}
	conds, found := shared.NestedSlice(o.Object, "status", "conditions")
	return !found || len(conds) == 0
}

// perconaUnpausedStaleGen is staleObservedGeneration with the Percona
// pause brake honored: spec.pause=true (and psmdb's spec.mode=paused)
// parks reconciliation deliberately — paused clusters are parked,
// not stuck (W10-CP3).
func perconaUnpausedStaleGen(o *unstructured.Unstructured) bool {
	if paused, _ := shared.NestedBool(o.Object, "spec", "pause"); paused {
		return false
	}
	if mode, _ := shared.NestedString(o.Object, "spec", "mode"); mode == "paused" {
		return false
	}
	return staleObservedGeneration(o)
}

// condMaxObservedGeneration returns the largest observedGeneration
// carried inside a conditions list. Gateway-API resources report the
// generation their controller last processed inside each condition —
// there is no top-level status.observedGeneration on
// Gateway/HTTPRoute/GRPCRoute — so 0 means the attached controller
// has never reported a spec generation.
func condMaxObservedGeneration(conds []shared.Condition) int64 {
	var max int64
	for _, c := range conds {
		if c.ObservedGeneration > max {
			max = c.ObservedGeneration
		}
	}
	return max
}

// gatewayStatusStuck is the cilium-operator signature on the
// gateway-API route resources its gateway controller reconciles: an
// object reporting no status.parents (the controller attaches a
// parent status when it programs the route), or one whose parents'
// conditions still report only older observedGenerations — the
// controller attached once but never saw the last spec write.
func gatewayStatusStuck(o *unstructured.Unstructured) bool {
	parents, found := shared.NestedSlice(o.Object, "status", "parents")
	if !found || len(parents) == 0 {
		return true
	}
	var maxOG int64
	for _, pr := range parents {
		m, ok := pr.(map[string]any)
		if !ok {
			continue
		}
		if og := condMaxObservedGeneration(
			shared.Conditions(m, "conditions")); og > maxOG {
			maxOG = og
		}
	}
	return maxOG < o.GetGeneration()
}

// gatewayObjectStuck is the same signature for the Gateway kind
// itself: Gateways carry status.listeners, not status.parents — the
// route predicate would flag every healthy Gateway forever. A
// programmed Gateway reports one status.listeners entry per
// spec.listeners entry; a spec with listeners but an empty/absent
// status.listeners means the controller never programmed it.
// Generation lag is judged from the conditions' observedGeneration
// (top-level status.conditions plus per-listener conditions) —
// Gateway status has no top-level observedGeneration field.
func gatewayObjectStuck(o *unstructured.Unstructured) bool {
	spec, found := shared.NestedSlice(o.Object, "spec", "listeners")
	if !found || len(spec) == 0 {
		return false
	}
	status, found := shared.NestedSlice(o.Object, "status", "listeners")
	if !found || len(status) == 0 {
		return true
	}
	var maxOG int64
	maxOG = condMaxObservedGeneration(
		shared.Conditions(o.Object, "status", "conditions"))
	for _, l := range status {
		m, ok := l.(map[string]any)
		if !ok {
			continue
		}
		if og := condMaxObservedGeneration(
			shared.Conditions(m, "conditions")); og > maxOG {
			maxOG = og
		}
	}
	return maxOG < o.GetGeneration()
}

// gatewayClassStuck is the signature for the GatewayClass kind
// itself: the class carries no top-level status.observedGeneration —
// the serving controller reports the last reconciled generation only
// inside status.conditions[type=Accepted].observedGeneration. No
// conditions, or none of them an Accepted entry, means the class was
// never picked up; an Accepted observedGeneration lagging
// metadata.generation means the last spec write was never seen. The
// Accepted status value (True/False) is irrelevant — a fresh
// rejection still proves the controller read the object.
func gatewayClassStuck(o *unstructured.Unstructured) bool {
	conds := shared.Conditions(o.Object, "status", "conditions")
	if len(conds) == 0 {
		return true
	}
	c, ok := shared.FindCondition(conds, "Accepted")
	if !ok {
		return true
	}
	return c.ObservedGeneration < o.GetGeneration()
}

// gatewayClassController resolves a GatewayClass name to its
// spec.controllerName, caching the class set for a minute so a
// stuck-object sweep doesn't LIST per object. ok=false means the
// class set is unavailable or the class is unknown — callers treat
// that as "cannot disprove ownership" and keep the object.
func (p *operatorWorkqueueCheck) gatewayClassController(ctx context.Context, class string) (string, bool) {
	p.mu.Lock()
	cached, at := p.gwClassCtlr, p.gwClassAt
	p.mu.Unlock()
	if cached == nil || p.now().Sub(at) > time.Minute {
		list, err := p.dyn.Resource(shared.GVRGatewayClass).
			List(ctx, metav1.ListOptions{})
		if err != nil {
			return "", false
		}
		m := map[string]string{}
		for i := range list.Items {
			ctlr, _ := shared.NestedString(
				list.Items[i].Object, "spec", "controllerName")
			m[list.Items[i].GetName()] = ctlr
		}
		p.mu.Lock()
		p.gwClassCtlr, p.gwClassAt = m, p.now()
		p.mu.Unlock()
		cached = m
	}
	ctlr, ok := cached[class]
	return ctlr, ok
}

// ciliumOwnsGatewayObject is the ownership filter for the Gateways
// resource: only a Gateway whose class is served by cilium's gateway
// controller belongs in cilium-operator's stuck set. Unresolvable
// class data keeps the object — a Gateway whose class cannot be
// attributed is still worth flagging under the cluster's gateway-API
// watcher.
func ciliumOwnsGatewayObject(ctx context.Context, p *operatorWorkqueueCheck,
	o *unstructured.Unstructured) bool {
	class, _ := shared.NestedString(o.Object, "spec", "gatewayClassName")
	ctlr, ok := p.gatewayClassController(ctx, class)
	if !ok {
		return true
	}
	return ctlr == ciliumGatewayController
}

// ciliumOwnsGatewayClass attributes a GatewayClass to cilium
// directly — spec.controllerName sits on the object itself, so no
// lookup is needed. An absent controllerName keeps the object (a
// malformed class cannot disprove ownership, same rule as the other
// gateway-API filters); a PROVEN foreign controller drops it.
func ciliumOwnsGatewayClass(_ context.Context, _ *operatorWorkqueueCheck,
	o *unstructured.Unstructured) bool {
	ctlr, _ := shared.NestedString(o.Object, "spec", "controllerName")
	return ctlr == "" || ctlr == ciliumGatewayController
}

// ciliumOwnsRouteParent is the same filter for the route kinds: it
// resolves each spec.parentRefs[] entry to its Gateway and reports
// whether any parent's class is cilium's. Objects with no Gateway
// parents, or parents that fail to resolve, stay in the stuck set —
// an unattributable route is still a gateway-API-plane problem —
// while a route provably owned by another gateway controller is
// that controller's problem, not cilium-operator's.
func ciliumOwnsRouteParent(ctx context.Context, p *operatorWorkqueueCheck,
	o *unstructured.Unstructured) bool {
	refs, found := shared.NestedSlice(o.Object, "spec", "parentRefs")
	if !found || len(refs) == 0 {
		return true
	}
	resolved := false
	for _, ref := range refs {
		m, ok := ref.(map[string]any)
		if !ok {
			continue
		}
		if k, _ := shared.NestedString(m, "kind"); k != "" && k != "Gateway" {
			continue
		}
		if g, _ := shared.NestedString(m, "group"); g != "" && g != "gateway.networking.k8s.io" {
			continue
		}
		name, _ := shared.NestedString(m, "name")
		if name == "" {
			continue
		}
		ns, _ := shared.NestedString(m, "namespace")
		if ns == "" {
			ns = o.GetNamespace()
		}
		gw, err := p.dyn.Resource(shared.GVRGateway).Namespace(ns).
			Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			continue
		}
		class, _ := shared.NestedString(gw.Object, "spec", "gatewayClassName")
		ctlr, ok := p.gatewayClassController(ctx, class)
		if !ok {
			continue
		}
		resolved = true
		if ctlr == ciliumGatewayController {
			return true
		}
	}
	return !resolved
}

var operatorTargets = []operatorTarget{
	{
		name:        "cilium-operator",
		leaseNS:     "kube-system",
		leaseNames:  []string{"cilium-operator-resource-lock"},
		podSelector: "io.cilium/app=operator",
		stuckMinAge: ciliumStuckMinAge,
		resources: []opStuckResource{
			// GatewayClass has no top-level status.observedGeneration
			// — the serving controller stamps the reconciled
			// generation inside conditions[type=Accepted] only.
			{gvr: shared.GVRGatewayClass, reason: opReasonStaleGWStatus,
				stuck: gatewayClassStuck, owns: ciliumOwnsGatewayClass},
			{gvr: shared.GVRGateway, reason: opReasonStaleGWStatus,
				stuck: gatewayObjectStuck, owns: ciliumOwnsGatewayObject},
			{gvr: shared.GVRHTTPRoute, reason: opReasonStaleGWStatus,
				stuck: gatewayStatusStuck, owns: ciliumOwnsRouteParent},
			{gvr: shared.GVRGRPCRoute, reason: opReasonStaleGWStatus,
				stuck: gatewayStatusStuck, owns: ciliumOwnsRouteParent},
		},
	},
	{
		name:        "scylla-operator",
		leaseNS:     "scylla-operator",
		leaseNames:  []string{"scylla-operator-lock"},
		podSelector: "app.kubernetes.io/name=scylla-operator",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr:    shared.GVRScyllaCluster,
			reason: kcmReasonStaleGen, stuck: staleObservedGeneration,
		}},
	},
	{
		name:          "dragonfly-operator",
		leaseNS:       dragonflyOperatorNS,
		leaseNames:    []string{"7898635c.dragonflydb.io"},
		podSelector:   "control-plane=controller-manager",
		leaseOptional: true,
		stuckMinAge:   operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr:    shared.GVRDragonfly,
			reason: kcmReasonStaleGen, stuck: staleObservedGeneration,
		}},
	},
	{
		name:        "helm-controller",
		leaseNS:     "flux-system",
		leaseNames:  []string{"helm-controller-leader-election"},
		podSelector: "app=helm-controller",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr:    shared.GVRHelmReleaseV2,
			reason: kcmReasonStaleGen, stuck: fluxUnsuspendedStaleGen,
		}},
	},
	{
		name:        "kustomize-controller",
		leaseNS:     "flux-system",
		leaseNames:  []string{"kustomize-controller-leader-election"},
		podSelector: "app=kustomize-controller",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr:    shared.GVRFluxKustomization,
			reason: kcmReasonStaleGen, stuck: fluxUnsuspendedStaleGen,
		}},
	},
	// W7-C2 — the ten additional leader-electing operators: every one
	// a controller-runtime leader whose zombie-leader gray failure
	// would wedge a whole slice of the stack (gitops sources, cert
	// issuance, secret sync, autoscaling, stateful operands).
	{
		name:        "source-controller",
		leaseNS:     "flux-system",
		leaseNames:  []string{"source-controller-leader-election"},
		podSelector: "app=source-controller",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{
			{gvr: shared.GVRFluxGitRepository,
				reason: kcmReasonStaleGen, stuck: fluxUnsuspendedStaleGen},
			{gvr: shared.GVRFluxHelmRepository,
				reason: kcmReasonStaleGen, stuck: helmRepoStaleGen},
			{gvr: shared.GVRFluxHelmChart,
				reason: kcmReasonStaleGen, stuck: fluxUnsuspendedStaleGen},
			{gvr: shared.GVRFluxOCIRepository,
				reason: kcmReasonStaleGen, stuck: fluxUnsuspendedStaleGen},
			{gvr: shared.GVRFluxBucket,
				reason: kcmReasonStaleGen, stuck: fluxUnsuspendedStaleGen},
		},
	},
	// notification-controller is deliberately absent: its v1beta3
	// Alert/Provider/Receiver are static objects — the API version
	// dropped their reconcilers, so no controller ever writes
	// status.observedGeneration or conditions on them and every
	// stuck signature flags healthy objects forever (the
	// passiontech-k0s-nonprod false-positive incident 2026-11-04).
	// Liveness stays covered by the pod/lease watches elsewhere.
	{
		name: "cert-manager",
		// The cert-manager helm chart elects leaders in kube-system
		// (global.leaderElection.namespace default) — the lease does
		// NOT live in the release namespace.
		leaseNS:    "kube-system",
		leaseNames: []string{"cert-manager-controller"},
		// The chart elects in kube-system but runs its pods in the
		// release namespace — pod lookups must not scan kube-system
		// (W10-FIX2).
		podNS:       "cert-manager",
		podSelector: "app.kubernetes.io/name=cert-manager",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{
			{gvr: shared.GVRCertificate,
				reason: opReasonNoConditions, stuck: noStatusConditions},
			// BUG-C5 — the same GVR additionally watched for
			// observedGeneration lag: a Certificate the controller
			// DID once reconcile can still be skipped by every
			// later spec write.
			{gvr: shared.GVRCertificate,
				reason: kcmReasonStaleGen, stuck: staleObservedGeneration},
		},
	},
	{
		name:    "external-secrets",
		leaseNS: "external-secrets",
		// Helm-default lease id — the deployment runs leaderElect:
		// false today (single replica), so the leaseOptional pod
		// fallback carries the liveness proof until HA is switched
		// on. externalsecret-operator-leader-election is the
		// OLM-installed name, not the helm chart's.
		leaseNames:    []string{"external-secrets-controller"},
		podSelector:   "app.kubernetes.io/name=external-secrets",
		leaseOptional: true,
		stuckMinAge:   operatorStuckMinAge,
		resources: []opStuckResource{
			{gvr: shared.GVRExternalSecretV1,
				reason: opReasonNoConditions, stuck: noStatusConditions},
			{gvr: shared.GVRExternalSecretV1,
				reason: kcmReasonStaleGen, stuck: staleObservedGeneration},
			{gvr: shared.GVRExternalSecretV1Beta1,
				reason: opReasonNoConditions, stuck: noStatusConditions},
			{gvr: shared.GVRExternalSecretV1Beta1,
				reason: kcmReasonStaleGen, stuck: staleObservedGeneration},
		},
	},
	{
		name:        "rabbitmq-cluster-operator",
		leaseNS:     "operators",
		leaseNames:  []string{"9c433e27.rabbitmq.com"},
		podSelector: "app.kubernetes.io/name=rabbitmq-cluster-operator",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr:    shared.GVRRabbitMQCluster,
			reason: kcmReasonStaleGen, stuck: staleObservedGeneration,
		}},
	},
	{
		name:        "keda-operator",
		leaseNS:     "operators",
		leaseNames:  []string{"operator.keda.sh"},
		podSelector: "app=keda-operator",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{
			{gvr: shared.GVRKedaScaledObject,
				reason: opReasonNoConditions, stuck: noStatusConditions},
			{gvr: shared.GVRKedaScaledObject,
				reason: kcmReasonStaleGen, stuck: staleObservedGeneration},
		},
	},
	{
		name: "argocd-operator",
		// The OLM Subscription sits in argocd-operator-system (see
		// infrastructure/base/operators/argocd-operator.yaml) — OLM
		// places the CSV deployment AND the leader-election lease
		// there, and the manager pods carry the kubebuilder
		// control-plane label, not name=argocd-operator.
		leaseNS:     "argocd-operator-system",
		leaseNames:  []string{"b23f6029.argoproj.io"},
		podSelector: "control-plane=controller-manager",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{
			{gvr: shared.GVRArgoCD,
				reason: opReasonNoPhase, stuck: emptyStatusPhase},
			{gvr: shared.GVRArgoCD,
				reason: kcmReasonStaleGen, stuck: staleObservedGeneration},
		},
	},
	{
		name:        "kargo-controller",
		leaseNS:     "kargo",
		leaseNames:  []string{"kargo-controller"},
		podSelector: "app.kubernetes.io/name=kargo,app.kubernetes.io/component=controller",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{
			{gvr: shared.GVRKargoStage,
				reason: kcmReasonStaleGen, stuck: staleObservedGeneration},
			{gvr: shared.GVRKargoWarehouse,
				reason: kcmReasonStaleGen, stuck: staleObservedGeneration},
		},
	},
	{
		name:        "everest-operator",
		leaseNS:     "everest-system",
		leaseNames:  []string{"a8916322.percona.com"},
		podSelector: "control-plane=controller-manager",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr:    shared.GVREverestDatabaseCluster,
			reason: kcmReasonStaleGen, stuck: staleObservedGeneration,
		}},
	},
	{
		name:        "shipwright-build-controller",
		leaseNS:     "shipwright-build",
		leaseNames:  []string{"shipwright-build-controller"},
		podSelector: "app.kubernetes.io/name=shipwright-build-controller",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr:    shared.GVRShipwrightBuild,
			reason: kcmReasonStaleGen, stuck: staleObservedGeneration,
		}},
	},

	// ------------------------------------------------------------------
	// W10-CP3 — the remaining operators whose stuck queues still gate
	// the self-healing path. Lease ids, namespaces, pod selectors and
	// CRD anchors were verified against the cluster's Flux manifests
	// and upstream kubebuilder scaffolds (medik8s election ids
	// e1f13584/547f6cb6.medik8s.io, fluent 45c4fdd2.fluent.io,
	// shipwright 01a9b2d1.shipwright.io); where upstream can
	// legitimately run without a Lease (single replica or
	// leader-elect patched out) leaseOptional lets the Running-pod
	// fallback carry the liveness proof.
	// ------------------------------------------------------------------
	{
		// flux notification-controller: the v1beta3
		// Alert/Provider/Receiver objects are STATIC user config —
		// the controller reconciles no status into them, so there
		// is no CR signature to watch (the watchdog entry exists so
		// the Lease liveness signal is still covered).
		name:        "notification-controller",
		leaseNS:     "flux-system",
		leaseNames:  []string{"notification-controller-leader-election"},
		podSelector: "app=notification-controller",
		stuckMinAge: operatorStuckMinAge,
	},
	{
		name:        "node-healthcheck-operator",
		leaseNS:     "operators",
		leaseNames:  []string{"e1f13584.medik8s.io"},
		podSelector: "app.kubernetes.io/name=node-healthcheck-operator",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr:    shared.GVRNodeHealthCheck,
			reason: opReasonNoStatus, stuck: noStatusAtAll,
		}},
	},
	{
		name:        "self-node-remediation-operator",
		leaseNS:     "operators",
		leaseNames:  []string{"547f6cb6.medik8s.io"},
		podSelector: "control-plane=controller-manager,self-node-remediation-operator",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr:    shared.GVRSelfNodeRemediation,
			reason: opReasonNoStatus, stuck: noStatusAtAll,
		}},
	},
	{
		// Percona DB operators are installed by the everest
		// dbNamespace (openeverest values dbNamespace.
		// namespaceOverride: everest) — NOT everest-system, which
		// only runs the everest server + DatabaseCluster CRs.
		// Each ships multiple election-id generations across
		// releases, so leaseNames carries every candidate and
		// leaseOptional lets the pod fallback cover a total id
		// rotation (W10-CP3).
		name:          "percona-xtradb-cluster-operator",
		leaseNS:       "everest",
		leaseNames:    []string{"90888d0c.percona.com", "percona-xtradb-cluster-operator-lock"},
		podSelector:   "app.kubernetes.io/name=percona-xtradb-cluster-operator",
		leaseOptional: true,
		stuckMinAge:   operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr:    shared.GVRPerconaXtraDBCluster,
			reason: kcmReasonStaleGen, stuck: perconaUnpausedStaleGen,
		}},
	},
	{
		name:          "percona-postgresql-operator",
		leaseNS:       "everest",
		leaseNames:    []string{"pgo-controller-lease", "percona-postgresql-operator-lock"},
		podSelector:   "app.kubernetes.io/name=percona-postgresql-operator",
		leaseOptional: true,
		stuckMinAge:   operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr:    shared.GVRPerconaPGCluster,
			reason: kcmReasonStaleGen, stuck: perconaUnpausedStaleGen,
		}},
	},
	{
		name:          "percona-server-mongodb-operator",
		leaseNS:       "everest",
		leaseNames:    []string{"087f5a08.percona.com", "percona-server-mongodb-operator-lock"},
		podSelector:   "app.kubernetes.io/name=percona-server-mongodb-operator",
		leaseOptional: true,
		stuckMinAge:   operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr:    shared.GVRPerconaServerMongoDB,
			reason: kcmReasonStaleGen, stuck: perconaUnpausedStaleGen,
		}},
	},
	{
		// fluent-operator (fluent-system): every fluentbit.fluent.io
		// CRD ships an EMPTY status struct — there is no status
		// channel to fingerprint, so the entry exists purely for
		// lease/pod liveness parity with the other operators.
		name:          "fluent-operator",
		leaseNS:       "fluent-system",
		leaseNames:    []string{"fluent-operator-leader-election", "45c4fdd2.fluent.io"},
		podSelector:   "app.kubernetes.io/name=fluent-operator",
		leaseOptional: true,
		stuckMinAge:   operatorStuckMinAge,
	},
	{
		name:          "tekton-pipelines-controller",
		leaseNS:       "tekton-pipelines",
		leaseNames:    []string{"tekton-pipelines-controller.tkn-leader-election", "tekton-pipelines-controller.pipelinerun.00-of-01"},
		podSelector:   "app.kubernetes.io/component=controller,app.kubernetes.io/part-of=tekton-pipelines",
		leaseOptional: true,
		stuckMinAge:   operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr:    shared.GVRTektonPipelineRun,
			reason: opReasonNoConditions, stuck: noStatusConditions,
		}},
	},
	{
		name:          "shipwright-operator",
		leaseNS:       "operators",
		leaseNames:    []string{"01a9b2d1.shipwright.io"},
		podSelector:   "app=shipwright-operator,control-plane=controller-manager",
		leaseOptional: true,
		stuckMinAge:   operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr:    shared.GVRShipwrightOperatorBuild,
			reason: opReasonNoConditions, stuck: noStatusConditions,
		}},
	},
}

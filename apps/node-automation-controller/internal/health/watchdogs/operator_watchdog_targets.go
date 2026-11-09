// operator_watchdog_targets.go — the watched-operator table of the
// operator-workqueue-watchdog check (operator-workqueue-watchdog): the opStuckResource /
// operatorTarget wiring and the operatorTargets rows binding each
// operator's leader-election Lease + pod selector to its CRD
// signature set. The generic per-CRD stuck predicates live in
// operator_stuck_signatures.go; the gateway-API stuck signatures
// and ownership filters live in gateway_targets.go.
package watchdogs

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
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
	// absent/empty list means it never picked the object up (operator-watchdog-targets).
	opReasonNoConditions = "no_status_conditions"
	// opReasonNoPhase is the same signature for CR types that report
	// a status.phase (argocd): an empty phase means the operator
	// never reconciled the object (operator-watchdog-targets).
	opReasonNoPhase = "no_status_phase"
	// opReasonNoStatus is the medik8s variant: status.phase AND
	// status.conditions both absent — the operator never completed
	// a reconcile pass on either channel (operator-workqueue-watchdog).
	opReasonNoStatus = "no_status_at_all"
)

// ---------------------------------------------------------------------------
// operator-workqueue-watchdog (operator-workqueue-watchdog) — lease-holding zombie detector
// + auto-healer.
// ---------------------------------------------------------------------------

// opStuckResource binds a watched CRD GVR to its stall signature: the
// reason label reported on operatorWorkqueueFrozenGauge and the predicate
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
// in kube-system while its pods live in cert-manager (operator-watchdog-leases).
//
// leaseOptional marks operators that legitimately run without a
// leader-election Lease (external-secrets runs replicas:1 with
// leaderElect:false, dragonfly-operator has --leader-elect patched
// out — operator-watchdog-leases): when no candidate Lease is found the watchdog
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
			{gvr: kube.GVRGatewayClass, reason: opReasonStaleGWStatus,
				stuck: gatewayClassStuck, owns: ciliumOwnsGatewayClass},
			{gvr: kube.GVRGateway, reason: opReasonStaleGWStatus,
				stuck: gatewayObjectStuck, owns: ciliumOwnsGatewayObject},
			{gvr: kube.GVRHTTPRoute, reason: opReasonStaleGWStatus,
				stuck: gatewayStatusStuck, owns: ciliumOwnsRouteParent},
			{gvr: kube.GVRGRPCRoute, reason: opReasonStaleGWStatus,
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
			gvr:    kube.GVRScyllaCluster,
			reason: kcmReasonStaleGen, stuck: staleObservedGeneration,
		}},
	},
	{
		name:          "dragonfly-operator",
		leaseNS:       kube.DragonflyOperatorNS,
		leaseNames:    []string{"7898635c.dragonflydb.io"},
		podSelector:   "control-plane=controller-manager",
		leaseOptional: true,
		stuckMinAge:   operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr:    kube.GVRDragonfly,
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
			gvr:    kube.GVRHelmReleaseV2,
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
			gvr:    kube.GVRFluxKustomization,
			reason: kcmReasonStaleGen, stuck: fluxUnsuspendedStaleGen,
		}},
	},
	// operator-watchdog-targets — the ten additional leader-electing operators: every one
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
			{gvr: kube.GVRFluxGitRepository,
				reason: kcmReasonStaleGen, stuck: fluxUnsuspendedStaleGen},
			{gvr: kube.GVRFluxHelmRepository,
				reason: kcmReasonStaleGen, stuck: helmRepoStaleGen},
			{gvr: kube.GVRFluxHelmChart,
				reason: kcmReasonStaleGen, stuck: fluxUnsuspendedStaleGen},
			{gvr: kube.GVRFluxOCIRepository,
				reason: kcmReasonStaleGen, stuck: fluxUnsuspendedStaleGen},
			{gvr: kube.GVRFluxBucket,
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
		// (operator-watchdog-leases).
		podNS:       "cert-manager",
		podSelector: "app.kubernetes.io/name=cert-manager",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{
			{gvr: kube.GVRCertificate,
				reason: opReasonNoConditions, stuck: noStatusConditions},
			// BUG-C5 — the same GVR additionally watched for
			// observedGeneration lag: a Certificate the controller
			// DID once reconcile can still be skipped by every
			// later spec write.
			{gvr: kube.GVRCertificate,
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
			{gvr: kube.GVRExternalSecretV1,
				reason: opReasonNoConditions, stuck: noStatusConditions},
			{gvr: kube.GVRExternalSecretV1,
				reason: kcmReasonStaleGen, stuck: staleObservedGeneration},
			{gvr: kube.GVRExternalSecretV1Beta1,
				reason: opReasonNoConditions, stuck: noStatusConditions},
			{gvr: kube.GVRExternalSecretV1Beta1,
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
			gvr:    kube.GVRRabbitMQCluster,
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
			{gvr: kube.GVRKedaScaledObject,
				reason: opReasonNoConditions, stuck: noStatusConditions},
			{gvr: kube.GVRKedaScaledObject,
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
			{gvr: kube.GVRArgoCD,
				reason: opReasonNoPhase, stuck: emptyStatusPhase},
			{gvr: kube.GVRArgoCD,
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
			{gvr: kube.GVRKargoStage,
				reason: kcmReasonStaleGen, stuck: staleObservedGeneration},
			{gvr: kube.GVRKargoWarehouse,
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
			gvr:    kube.GVREverestDatabaseCluster,
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
			gvr:    kube.GVRShipwrightBuild,
			reason: kcmReasonStaleGen, stuck: staleObservedGeneration,
		}},
	},

	// ------------------------------------------------------------------
	// operator-workqueue-watchdog — the remaining operators whose stuck queues still gate
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
			gvr:    kube.GVRNodeHealthCheck,
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
			gvr:    kube.GVRSelfNodeRemediation,
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
		// rotation (operator-workqueue-watchdog).
		name:          "percona-xtradb-cluster-operator",
		leaseNS:       "everest",
		leaseNames:    []string{"90888d0c.percona.com", "percona-xtradb-cluster-operator-lock"},
		podSelector:   "app.kubernetes.io/name=percona-xtradb-cluster-operator",
		leaseOptional: true,
		stuckMinAge:   operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr:    kube.GVRPerconaXtraDBCluster,
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
			gvr:    kube.GVRPerconaPGCluster,
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
			gvr:    kube.GVRPerconaServerMongoDB,
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
			gvr:    kube.GVRTektonPipelineRun,
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
			gvr:    kube.GVRShipwrightOperatorBuild,
			reason: opReasonNoConditions, stuck: noStatusConditions,
		}},
	},
	{
		// rollout-scale-flap — argo-rollouts: the Rollouts controller reconciles
		// argoproj.io/v1alpha1 Rollouts (the cluster runs the official
		// chart in the argo-rollouts namespace — infrastructure/base/
		// helm/helm-releases/argo-rollouts). A stalled observedGeneration
		// is the same wedged-queue signature the other typed operators
		// carry: the analysis-template gate wedged, the canary stuck
		// mid-promotion, or the controller crashed-looping on one CR.
		name:        "argo-rollouts-controller",
		leaseNS:     "argo-rollouts",
		leaseNames:  []string{"argo-rollouts-controller", "rollouts-controller-leader-election"},
		podSelector: "app.kubernetes.io/name=argo-rollouts",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr:    kube.GVRArgoRollout,
			reason: kcmReasonStaleGen, stuck: staleObservedGeneration,
		}},
	},
	{
		// rollout-scale-flap — cloudflare-tunnel-gateway-controller (lexfrei chart,
		// cloudflare-tunnel-system ns — infrastructure/base/helm/
		// helm-releases/cloudflare-tunnel-gateway-controller). The
		// controller owns NO CRD of its own: it reconciles Gateway API
		// objects whose traffic rides its GatewayClass, so the stuck
		// set is the gateway/route kinds filtered to its class by the
		// cftOwns* filters below. The chart may or may not leader-elect
		// depending on replica count — leaseOptional lets a live pod
		// prove liveness when no Lease exists (dragonfly-operator's
		// operator-watchdog-leases posture).
		name:          "cloudflare-tunnel-gateway-controller",
		leaseNS:       "cloudflare-tunnel-system",
		leaseNames:    []string{"cloudflare-tunnel-gateway-controller"},
		podSelector:   "app.kubernetes.io/name=cloudflare-tunnel-gateway-controller",
		leaseOptional: true,
		stuckMinAge:   operatorStuckMinAge,
		resources: []opStuckResource{
			{gvr: kube.GVRGateway, reason: opReasonStaleGWStatus,
				stuck: gatewayObjectStuck, owns: cftOwnsGatewayObject},
			{gvr: kube.GVRHTTPRoute, reason: opReasonStaleGWStatus,
				stuck: gatewayStatusStuck, owns: cftOwnsRouteParent},
			{gvr: kube.GVRGRPCRoute, reason: opReasonStaleGWStatus,
				stuck: gatewayStatusStuck, owns: cftOwnsRouteParent},
		},
	},
	{
		// cloudnative-pg (W20): the CNPG instance operator in
		// cnpg-system — Cluster CRs whose status.observedGeneration
		// lags while the manager lease renews are the same
		// wedged-queue signature the other typed operators carry.
		name:          "cloudnative-pg",
		leaseNS:       "cnpg-system",
		leaseNames:    []string{"cnpg-controller-manager", "cloudnative-pg"},
		podSelector:   "app.kubernetes.io/name=cloudnative-pg",
		leaseOptional: true,
		stuckMinAge:   operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr:    kube.GVRCNPGCluster,
			reason: kcmReasonStaleGen, stuck: staleObservedGeneration,
		}},
	},
	{
		// velero (W20): the backup controller in velero — a Backup
		// whose status.phase never lands means the controller never
		// picked the object up (the in-flight backup audit owns the
		// stuck-InProgress class; this row owns never-reconciled).
		name:          "velero",
		leaseNS:       "velero",
		leaseNames:    []string{"velero", "velero-leader-election"},
		podSelector:   "app.kubernetes.io/name=velero",
		leaseOptional: true,
		stuckMinAge:   operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr:    kube.GVRVeleroBackup,
			reason: opReasonNoPhase, stuck: emptyStatusPhase,
		}},
	},
	{
		// fence-agents-remediation (W20): the FAR operator in
		// operators — medik8s election ids are per-operator hashes
		// (e1f13584/547f6cb6.medik8s.io for NHC/SNR) and FAR's is not
		// pinned here, so the leaseOptional Running-pod fallback is
		// the liveness proof; the CR signature is the same sparse-
		// status medik8s variant noStatusAtAll covers.
		name:          "fence-agents-remediation-operator",
		leaseNS:       "operators",
		podSelector:   "app.kubernetes.io/name=fence-agents-remediation-operator",
		leaseOptional: true,
		stuckMinAge:   operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr:    kube.GVRFenceAgentsRemediation,
			reason: opReasonNoStatus, stuck: noStatusAtAll,
		}},
	},
	{
		// liqo-controller-manager (W20): the Liqo control plane in
		// liqo — ForeignCluster CRs whose status.conditions never
		// land mean the peering controller never reconciled them.
		name:          "liqo-controller-manager",
		leaseNS:       "liqo",
		leaseNames:    []string{"liqo-controller-manager"},
		podSelector:   "app.kubernetes.io/name=liqo-controller-manager",
		leaseOptional: true,
		stuckMinAge:   operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr:    kube.GVRLiqoForeignCluster,
			reason: opReasonNoConditions, stuck: noStatusConditions,
		}},
	},
}

// cftGatewayClassName is the GatewayClass the cloudflare-tunnel
// gateway-controller serves — infrastructure/base/gateway-api/
// gateways/cloudflare-tunnel pins it in Git. Ownership keys on the
// class NAME, not the controller's spec.controllerName string: that
// string is chart-version dependent, the class name is not.
const cftGatewayClassName = "cloudflare-tunnel"

// cftOwnsGatewayObject keeps a Gateway in the cloudflare-tunnel
// stuck set when its spec.gatewayClassName names the cloudflare-tunnel
// class. Unresolvable/absent class names KEEP the object — an
// unattributable stuck Gateway is still a gateway-API-plane problem
// (the same fail-open posture ciliumOwnsGatewayObject documents);
// only a PROVEN foreign class drops it.
func cftOwnsGatewayObject(_ context.Context, _ *operatorWorkqueueCheck,
	o *unstructured.Unstructured) bool {
	class, _ := kube.NestedString(o.Object, "spec", "gatewayClassName")
	return class == "" || class == cftGatewayClassName
}

// cftOwnsRouteParent keeps a route in the stuck set when any
// spec.parentRefs[] Gateway resolves to the cloudflare-tunnel class —
// the ciliumOwnsRouteParent shape with the class-name key. Routes
// with no Gateway parents or unresolvable parents stay in the set;
// a route provably riding another controller's Gateway is that
// controller's problem.
func cftOwnsRouteParent(ctx context.Context, p *operatorWorkqueueCheck,
	o *unstructured.Unstructured) bool {
	refs, found := kube.NestedSlice(o.Object, "spec", "parentRefs")
	if !found || len(refs) == 0 {
		return true
	}
	resolved := false
	for _, ref := range refs {
		m, ok := ref.(map[string]any)
		if !ok {
			continue
		}
		if k, _ := kube.NestedString(m, "kind"); k != "" && k != "Gateway" {
			continue
		}
		if g, _ := kube.NestedString(m, "group"); g != "" && g != "gateway.networking.k8s.io" {
			continue
		}
		name, _ := kube.NestedString(m, "name")
		if name == "" {
			continue
		}
		ns, _ := kube.NestedString(m, "namespace")
		if ns == "" {
			ns = o.GetNamespace()
		}
		gw, ok := lookupGateway(ctx, p, ns, name)
		if !ok {
			continue
		}
		class, _ := kube.NestedString(gw.Object, "spec", "gatewayClassName")
		resolved = true
		if class == cftGatewayClassName {
			return true
		}
	}
	return !resolved
}

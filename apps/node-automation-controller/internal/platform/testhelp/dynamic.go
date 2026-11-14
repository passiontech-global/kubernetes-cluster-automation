// dynamic.go — the dynamic-client fake with a REAL scheme. NewFakeDyn
// hands dynamicfake an empty runtime.Scheme plus a hand-built
// GVR->ListKind map, so a test that needs to List a CRD the module
// reads must spell out the list-kind mapping itself. NewDynamicClient
// bakes the whole table in once: every GVK the module code reaches
// through dyn.Resource(gvr) is registered, object kind AND
// <Kind>List, so the fake's GVR->list-kind guessing covers all of
// them and seeding unstructured objects just works. Living at the
// platform leaf means platform's own tests (kube maintenance,
// heal) reach the same table domain tests get via testutil.
package testhelp

import (
	"fmt"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
)

// dynCRDGVKs enumerates every CRD GroupVersionKind the module code
// Lists through the dynamic client — the GVR literals under
// internal/<domain>/ plus the served-version variants the same kind
// appears under (HelmRelease v2 AND v2beta2, the external-secrets
// trio under v1 AND v1beta1). The list-kind map the fake builds is inverted from
// these via meta.UnsafeGuessKindToResource, so every Kind below MUST
// pluralize to the resource string the module's GVR literal uses —
// the survey that produced this table checked each one (e.g.
// GatewayClass -> "gatewayclasses" via the trailing-"s" -> +"es"
// rule, Dragonfly -> "dragonflies" via trailing-"y" -> "ies").
//
// Deliberately absent: GVRs discovered at RUNTIME
// (namespace-terminating-wedged builds GVRs from API discovery for
// arbitrary CRs, and tests seed example.com/v1 "foos") — no static
// table can cover those; those call sites keep NewFakeDyn's
// explicit map. Built-in types (Plan is NOT one — it is the k0s
// autopilot CRD; apiservices, leases, pods, ...) come from
// clientgoscheme inside DynScheme instead.
var dynCRDGVKs = []schema.GroupVersionKind{
	// cert-manager (certdriftauditor, certmanagerreaper,
	// clusterhealthprobes' Certificate signature watches).
	{Group: "cert-manager.io", Version: "v1", Kind: "Certificate"},
	{Group: "cert-manager.io", Version: "v1", Kind: "CertificateRequest"},
	{Group: "acme.cert-manager.io", Version: "v1", Kind: "Order"},
	{Group: "acme.cert-manager.io", Version: "v1", Kind: "Challenge"},

	// cilium (ciliumidentityauditor, clusterhealthprobes' endpoint/
	// node scans).
	{Group: "cilium.io", Version: "v2", Kind: "CiliumIdentity"},
	{Group: "cilium.io", Version: "v2", Kind: "CiliumEndpoint"},
	{Group: "cilium.io", Version: "v2", Kind: "CiliumNode"},
	{Group: "cilium.io", Version: "v2alpha1", Kind: "CiliumEndpointSlice"},

	// external-secrets — v1 and v1beta1 are BOTH served and both
	// listed (externalsecretnudge tries each in order).
	{Group: "external-secrets.io", Version: "v1", Kind: "ExternalSecret"},
	{Group: "external-secrets.io", Version: "v1", Kind: "SecretStore"},
	{Group: "external-secrets.io", Version: "v1", Kind: "ClusterSecretStore"},
	{Group: "external-secrets.io", Version: "v1beta1", Kind: "ExternalSecret"},
	{Group: "external-secrets.io", Version: "v1beta1", Kind: "SecretStore"},
	{Group: "external-secrets.io", Version: "v1beta1", Kind: "ClusterSecretStore"},

	// fluxcd helm/kustomize/source/notification toolkits
	// (helmreleaseunlocker, clusterhealthprobes' operator scans).
	{Group: "helm.toolkit.fluxcd.io", Version: "v2", Kind: "HelmRelease"},
	{Group: "helm.toolkit.fluxcd.io", Version: "v2beta2", Kind: "HelmRelease"},
	{Group: "kustomize.toolkit.fluxcd.io", Version: "v1", Kind: "Kustomization"},
	{Group: "source.toolkit.fluxcd.io", Version: "v1", Kind: "GitRepository"},
	{Group: "source.toolkit.fluxcd.io", Version: "v1", Kind: "HelmRepository"},
	{Group: "source.toolkit.fluxcd.io", Version: "v1", Kind: "HelmChart"},
	{Group: "source.toolkit.fluxcd.io", Version: "v1", Kind: "OCIRepository"},
	{Group: "source.toolkit.fluxcd.io", Version: "v1", Kind: "Bucket"},
	{Group: "notification.toolkit.fluxcd.io", Version: "v1beta3", Kind: "Alert"},
	{Group: "notification.toolkit.fluxcd.io", Version: "v1beta3", Kind: "Provider"},
	{Group: "notification.toolkit.fluxcd.io", Version: "v1beta3", Kind: "Receiver"},

	// velero + percona everest (velerobackupauditor).
	{Group: "velero.io", Version: "v1", Kind: "Schedule"},
	{Group: "velero.io", Version: "v1", Kind: "Backup"},
	{Group: "velero.io", Version: "v1", Kind: "BackupStorageLocation"},
	{Group: "velero.io", Version: "v1", Kind: "PodVolumeBackup"},
	// PodVolumeRestore — velero-inflight-audit's velero-restore-wedge-audit restore-side
	// wedge scan; "podvolumerestores" pluralizes via trailing-"e" +"s".
	{Group: "velero.io", Version: "v1", Kind: "PodVolumeRestore"},
	// BackupRepository — velero-backup-auditor's backup-health repo scan;
	// BackupRepository -> "backuprepositories" pluralizes correctly
	// via the trailing-"y" -> "ies" rule.
	{Group: "velero.io", Version: "v1", Kind: "BackupRepository"},
	{Group: "everest.percona.com", Version: "v1alpha1", Kind: "DatabaseCluster"},
	{Group: "everest.percona.com", Version: "v1alpha1", Kind: "DatabaseClusterBackup"},

	// argocd (argocd_app_stuck, operator scans).
	{Group: "argoproj.io", Version: "v1alpha1", Kind: "Application"},
	{Group: "argoproj.io", Version: "v1beta1", Kind: "ArgoCD"},

	// olm (clusterhealthprobes' subscription-health check + the
	// installplan-auto-approver InstallPlan auto-approver — InstallPlan ->
	// "installplans" pluralizes via the trailing-"n" -> +"s" rule).
	{Group: "operators.coreos.com", Version: "v1alpha1", Kind: "ClusterServiceVersion"},
	{Group: "operators.coreos.com", Version: "v1alpha1", Kind: "Subscription"},
	{Group: "operators.coreos.com", Version: "v1alpha1", Kind: "InstallPlan"},

	// percona operator clusters (clusterhealthprobes) + the postgres
	// WAL guard's CNPG scan.
	{Group: "pxc.percona.com", Version: "v1", Kind: "PerconaXtraDBCluster"},
	{Group: "pgv2.percona.com", Version: "v2", Kind: "PerconaPGCluster"},
	{Group: "psmdb.percona.com", Version: "v1", Kind: "PerconaServerMongoDB"},
	{Group: "postgresql.cnpg.io", Version: "v1", Kind: "Cluster"},
	// cnpg-backup-audit — CNPG backup audit (velerobackupauditor/cnpg_audit.go):
	// ScheduledBackup -> "scheduledbackups" pluralizes correctly via
	// the trailing-"y" -> "ies" rule.
	{Group: "postgresql.cnpg.io", Version: "v1", Kind: "ScheduledBackup"},
	{Group: "postgresql.cnpg.io", Version: "v1", Kind: "Backup"},
	// cnpg-backup-audit — velero data-mover transfers (velerobackupauditor
	// in-flight audit).
	{Group: "velero.io", Version: "v2alpha1", Kind: "DataUpload"},
	{Group: "velero.io", Version: "v2alpha1", Kind: "DataDownload"},

	// trivy-operator reports + policy-reporter (clusterhealthprobes'
	// api-object-sprawl-report-gc census/GC).
	{Group: "aquasecurity.github.io", Version: "v1alpha1", Kind: "VulnerabilityReport"},
	{Group: "aquasecurity.github.io", Version: "v1alpha1", Kind: "ConfigAuditReport"},
	{Group: "aquasecurity.github.io", Version: "v1alpha1", Kind: "ExposedSecretReport"},
	{Group: "aquasecurity.github.io", Version: "v1alpha1", Kind: "EphemeralReport"},
	{Group: "wgpolicyk8s.io", Version: "v1alpha2", Kind: "PolicyReport"},

	// liqo multi-cluster networking (clusterhealthprobes'
	// liqo-tunnel-health peer scan).
	{Group: "networking.liqo.io", Version: "v1beta1", Kind: "Connection"},
	{Group: "networking.liqo.io", Version: "v1beta1", Kind: "GatewayClient"},
	{Group: "networking.liqo.io", Version: "v1beta1", Kind: "GatewayServer"},
	// liqo foreign-cluster CR — operator-watchdog's liqo target
	// signature scan (core.liqo.io, not networking.liqo.io).
	{Group: "core.liqo.io", Version: "v1beta1", Kind: "ForeignCluster"},

	// medik8s self-node-remediation family (deadnodesweeper,
	// clusterhealthprobes' nodehealthchecks scan).
	{Group: "remediation.medik8s.io", Version: "v1alpha1", Kind: "NodeHealthCheck"},
	{Group: "self-node-remediation.medik8s.io", Version: "v1alpha1", Kind: "SelfNodeRemediation"},
	{Group: "fence-agents-remediation.medik8s.io", Version: "v1alpha1", Kind: "FenceAgentsRemediation"},
	{Group: "nodemaintenance.medik8s.io", Version: "v1beta1", Kind: "NodeMaintenance"},

	// tekton + shipwright (failedjobsjanitor buildruns,
	// clusterhealthprobes' builds/shipwrightbuilds scans). The
	// ShipwrightBuild CRD is served ONLY under operator.shipwright.io
	// — the OLM operator API (shipwrightbuilds.operator.shipwright.io);
	// shipwright.io itself serves the v1beta1 Build/BuildRun APIs and
	// has no v1alpha1 shipwrightbuilds resource.
	{Group: "tekton.dev", Version: "v1", Kind: "PipelineRun"},
	{Group: "tekton.dev", Version: "v1", Kind: "TaskRun"},
	{Group: "shipwright.io", Version: "v1beta1", Kind: "Build"},
	{Group: "shipwright.io", Version: "v1beta1", Kind: "BuildRun"},
	{Group: "operator.shipwright.io", Version: "v1alpha1", Kind: "ShipwrightBuild"},

	// the remaining watched operators (clusterhealthprobes) + the
	// health-check scans (kargo promotion health, argo analysisrun zombie
	// guard, percona quorum).
	{Group: "rabbitmq.com", Version: "v1beta1", Kind: "RabbitmqCluster"},
	{Group: "keda.sh", Version: "v1alpha1", Kind: "ScaledObject"},
	{Group: "kargo.akuity.io", Version: "v1alpha1", Kind: "Stage"},
	{Group: "kargo.akuity.io", Version: "v1alpha1", Kind: "Warehouse"},
	{Group: "kargo.akuity.io", Version: "v1alpha1", Kind: "Promotion"},
	{Group: "argoproj.io", Version: "v1alpha1", Kind: "AnalysisRun"},
	// argo-rollout-gates: gateway downscaler verdicts, keda zero-rescue and flux
	// workload readiness also census the Rollout GVR.
	{Group: "argoproj.io", Version: "v1alpha1", Kind: "Rollout"},
	// rollout-scale-flap: api-object-sprawl-report-gc also GCs completed Rollouts
	// Experiments — the sweep fake must serve their List kinds.
	{Group: "argoproj.io", Version: "v1alpha1", Kind: "Experiment"},
	{Group: "scylla.scylladb.com", Version: "v1", Kind: "ScyllaCluster"},
	{Group: "dragonflydb.io", Version: "v1alpha1", Kind: "Dragonfly"},

	// k0s autopilot Plan — the maintenance-mutex signal every
	// sweep module's dyn client reads (kube.AutopilotPlanGVR).
	{Group: "autopilot.k0sproject.io", Version: "v1beta2", Kind: "Plan"},

	// gateway-api (clusterhealthprobes' cilium gateway signature) +
	// the reference-grant census gateway-route-health lists under
	// both served versions.
	{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "GatewayClass"},
	{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "Gateway"},
	{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "HTTPRoute"},
	{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "GRPCRoute"},
	{Group: "gateway.networking.k8s.io", Version: "v1beta1", Kind: "ReferenceGrant"},
	{Group: "gateway.networking.k8s.io", Version: "v1alpha2", Kind: "ReferenceGrant"},
}

// buildDynScheme assembles the scheme NewDynamicClient and DynScheme
// share: the client-go built-ins plus every CRD kind in dynCRDGVKs.
func buildDynScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	// client-go built-ins: typed seed objects (a *coordinationv1.Lease,
	// say) convert to unstructured through ObjectKinds, and built-in
	// List GVKs (PodList, EndpointSliceList, APIServiceList, ...) give
	// the fake's GVR->list-kind map entries for free.
	if err := clientgoscheme.AddToScheme(s); err != nil {
		panic(err)
	}
	for _, gvk := range dynCRDGVKs {
		// Both the object kind and its <Kind>List counterpart are
		// registered: the fake's tracker builds list results via
		// scheme.New(<Kind>List), and its GVR->list-kind map is
		// inverted from registered List GVKs — registering only the
		// object kind would leave List() panicking on "you must
		// register resource to list kind".
		s.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})
		s.AddKnownTypeWithName(
			gvk.GroupVersion().WithKind(gvk.Kind+"List"),
			&unstructured.UnstructuredList{})
	}
	return s
}

// dynSchemeOnce caches the shared scheme: NewSimpleDynamicClient only
// READS the scheme it is handed (it copies every known GVK into its
// own unstructured scheme and converts seed objects through it), so
// one instance is safe for every NewDynamicClient call.
var dynSchemeOnce = sync.OnceValue(buildDynScheme)

// dynCRDListGVKs are the apiextensions kinds the CRD-inclusive fake
// registers ON TOP of dynCRDGVKs — deliberately kept out of the
// shared table (see CRDGVR: baking them in would widen the default
// fake for every test that must NOT see CRDs and silence the
// panic-on-unregistered-List guard those tests rely on).
var dynCRDListGVKs = []schema.GroupVersionKind{
	{Group: "apiextensions.k8s.io", Version: "v1",
		Kind: "CustomResourceDefinition"},
}

// dynSchemeWithCRDsOnce caches the CRD-inclusive scheme — the same
// table plus the apiextensions kinds, for fakes whose checks
// genuinely List CRDs every sweep (api-object-sprawl-report-gc's
// kine large-object census reads them via AllUnstructured).
var dynSchemeWithCRDsOnce = sync.OnceValue(func() *runtime.Scheme {
	s := buildDynScheme()
	for _, gvk := range dynCRDListGVKs {
		s.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})
		s.AddKnownTypeWithName(
			gvk.GroupVersion().WithKind(gvk.Kind+"List"),
			&unstructured.UnstructuredList{})
	}
	return s
})

// DynScheme returns a FRESH scheme carrying the client-go built-ins
// plus every CRD GVK in dynCRDGVKs (object and <Kind>List kinds, all
// as unstructured). Use it when a test needs the same type coverage
// outside the dynamic fake — e.g. a controller-runtime fake client
// built with fake.NewClientBuilder().WithScheme(testutil.DynScheme()).
// Fresh-per-call because callers may register additional types.
func DynScheme() *runtime.Scheme {
	return buildDynScheme()
}

// dynListKindOverrides repairs the resources
// meta.UnsafeGuessKindToResource cannot derive. The fake builds its
// GVR->list-kind map by pluralizing each registered <Kind>List, which
// guesses "gatewaies" for Gateway — the gateway-api CRD's real
// resource is "gateways". Custom entries merge over the guessed map,
// so the wrong guess can stay (harmless) alongside the right one.
var dynListKindOverrides = map[schema.GroupVersionResource]string{
	{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}: "GatewayList",
}

// NewDynamicClient returns a dynamic fake that can List every CRD
// GVK the modules read — the drop-in for the per-test-file
// map[schema.GroupVersionResource]string literals NewFakeDyn still
// requires. Seed it with *unstructured.Unstructured objects carrying
// apiVersion/kind (the shape every module test builder produces); typed
// objects work too — the client-go scheme converts them. For GVRs
// outside the dynCRDGVKs table (runtime-discovered resources), keep
// using NewFakeDyn, optionally merged with DynListKinds().
func NewDynamicClient(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return newDynamicClient(dynSchemeOnce(), objs...)
}

// NewDynamicClientWithCRDs is NewDynamicClient plus the apiextensions
// CustomResourceDefinition kinds — the fake the full health sweep
// needs now that api-object-sprawl-report-gc's kine large-object
// census Lists CRDs every cycle. Tests asserting CRD-absence keep
// using NewDynamicClient/NewFakeDyn: the unregistered-List panic
// stays their guard.
func NewDynamicClientWithCRDs(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return newDynamicClient(dynSchemeWithCRDsOnce(), objs...)
}

func newDynamicClient(scheme *runtime.Scheme,
	objs ...runtime.Object) *dynamicfake.FakeDynamicClient {

	// The body mirrors dynamicfake.NewSimpleDynamicClient — the
	// all-unstructured scheme copy and the typed-seed conversion —
	// because the overrides need NewSimpleDynamicClientWithCustomListKinds
	// and that entry point performs NEITHER step itself.
	unstructuredScheme := runtime.NewScheme()
	for gvk := range scheme.AllKnownTypes() {
		if strings.HasSuffix(gvk.Kind, "List") {
			unstructuredScheme.AddKnownTypeWithName(gvk, &unstructured.UnstructuredList{})
			continue
		}
		unstructuredScheme.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})
	}

	converted := make([]runtime.Object, 0, len(objs))
	for _, obj := range objs {
		converted = append(converted, dynSeedToUnstructured(scheme, obj))
	}
	for _, obj := range converted {
		gvk := obj.GetObjectKind().GroupVersionKind()
		if !unstructuredScheme.Recognizes(gvk) {
			unstructuredScheme.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})
		}
		gvk.Kind += "List"
		if !unstructuredScheme.Recognizes(gvk) {
			unstructuredScheme.AddKnownTypeWithName(gvk, &unstructured.UnstructuredList{})
		}
	}

	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		unstructuredScheme, dynListKindOverrides, converted...)
}

// dynSeedToUnstructured is client-go's convertToUnstructured: a typed
// seed converts through the scheme (resolving the GVK when TypeMeta
// is empty, the shape k8s test fixtures usually carry); an
// *unstructured.Unstructured seed round-trips unchanged. Panics like
// NewSimpleDynamicClient do — a seed the scheme cannot place is a
// test-authoring bug, not a runtime condition.
func dynSeedToUnstructured(scheme *runtime.Scheme, obj runtime.Object) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	var err error
	u.Object, err = runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		panic(fmt.Errorf("failed to convert to unstructured: %w", err))
	}
	if gvk := u.GroupVersionKind(); gvk.Group == "" || gvk.Kind == "" {
		gvks, _, err := scheme.ObjectKinds(obj)
		if err != nil {
			panic(fmt.Errorf("failed to convert to unstructured - unable to get GVK %w", err))
		}
		apiv, k := gvks[0].ToAPIVersionAndKind()
		u.SetAPIVersion(apiv)
		u.SetKind(k)
	}
	return u
}

// NewFakeDyn builds a dynamic fake client with explicit GVR->ListKind
// mappings (required for List on unregistered CRDs).
func NewFakeDyn(kinds map[schema.GroupVersionResource]string,
	objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(), kinds, objs...)
}

// DynListKinds returns the GVR->ListKind map covering every CRD
// NewDynamicClient knows, computed with the same
// meta.UnsafeGuessKindToResource inversion the fake applies. Merge it
// into a custom map for NewFakeDyn when a test needs BOTH the known
// CRDs and ad-hoc GVRs:
//
//	kinds := maps.Clone(testutil.DynListKinds())
//	kinds[myGVR] = "FooList"
//	dyn := testutil.NewFakeDyn(kinds, objs...)
func DynListKinds() map[schema.GroupVersionResource]string {
	m := make(map[schema.GroupVersionResource]string, len(dynCRDGVKs))
	for _, gvk := range dynCRDGVKs {
		gvr, _ := meta.UnsafeGuessKindToResource(gvk)
		m[gvr] = gvk.Kind + "List"
	}
	// The guessed map inherits the guesser's blind spots — apply the
	// same overrides NewDynamicClient passes to the fake.
	for gvr, listKind := range dynListKindOverrides {
		m[gvr] = listKind
	}
	return m
}

// CRDGVR is the apiextensions CustomResourceDefinition GVR — the one
// CRD kind deliberately absent from dynCRDGVKs because baking it into
// the shared table would widen the default fake for every test that
// must NOT see CRDs (and would silence the panic-on-unregistered-List
// guard those tests rely on). Tests that genuinely List CRDs opt in
// via NewDynWithCRDs instead.
var CRDGVR = schema.GroupVersionResource{
	Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}

// NewDynWithCRDs is an alias-style forwarder to NewDynamicClientWithCRDs
// kept for existing callers.
func NewDynWithCRDs(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return NewDynamicClientWithCRDs(objs...)
}

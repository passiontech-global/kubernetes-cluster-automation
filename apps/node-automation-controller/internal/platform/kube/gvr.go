// gvr.go — the named schema.GroupVersionResource registry for every
// CRD/operator API the modules read through the dynamic client.
// Before this file each module carried its own copy of the literal
// (cert-manager.io/v1 certificates alone was declared in three
// packages); centralizing them keeps group/version/resource typos
// impossible to diverge and gives adopters one place to look up the
// GVR a check scans. Values are verbatim from the call sites — do
// NOT "fix" a version here without checking every consumer: several
// modules deliberately probe multiple served versions of the same
// resource (HelmRelease v2+v2beta2, ExternalSecret v1+v1beta1).
//
// Domain groups mirror the operator each CRD belongs to; the
// clusterhealthprobes operator-watchdog table is the largest
// consumer.
package kube

import "k8s.io/apimachinery/pkg/runtime/schema"

var (
	// ---------------------------------------------------------------
	// Kubernetes aggregated API (apiservice-guard).
	// ---------------------------------------------------------------
	GVRAPIService = schema.GroupVersionResource{
		Group: "apiregistration.k8s.io", Version: "v1", Resource: "apiservices"}

	// ---------------------------------------------------------------
	// FluxCD (helmrelease-unlocker, cluster-health-probes).
	// HelmReleases ship two served versions — modules probe BOTH and
	// use the first that lists (helmReleaseGVRs /
	// helmReleaseRetryGVRs were identical literals).
	// ---------------------------------------------------------------
	GVRHelmReleaseV2 = schema.GroupVersionResource{
		Group: "helm.toolkit.fluxcd.io", Version: "v2", Resource: "helmreleases"}
	GVRHelmReleaseV2Beta2 = schema.GroupVersionResource{
		Group: "helm.toolkit.fluxcd.io", Version: "v2beta2", Resource: "helmreleases"}
	// HelmReleaseGVRs is the probe order: current v2 first, then the
	// previous storage version.
	HelmReleaseGVRs = []schema.GroupVersionResource{
		GVRHelmReleaseV2, GVRHelmReleaseV2Beta2}
	GVRFluxKustomization = schema.GroupVersionResource{
		Group: "kustomize.toolkit.fluxcd.io", Version: "v1", Resource: "kustomizations"}
	// Flux source kinds (source.toolkit.fluxcd.io/v1) — the objects
	// a stale-artifact reconcile nudge lands on; helmrelease-unlocker
	// maps sourceRef kinds onto these.
	GVRFluxHelmChart      = schema.GroupVersionResource{Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "helmcharts"}
	GVRFluxGitRepository  = schema.GroupVersionResource{Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "gitrepositories"}
	GVRFluxHelmRepository = schema.GroupVersionResource{Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "helmrepositories"}
	GVRFluxOCIRepository  = schema.GroupVersionResource{Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "ocirepositories"}
	GVRFluxBucket         = schema.GroupVersionResource{Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "buckets"}

	// ---------------------------------------------------------------
	// cert-manager + ACME (certmanager-reaper, cert-drift-auditor,
	// cluster-health-probes).
	// ---------------------------------------------------------------
	GVRCertificate = schema.GroupVersionResource{
		Group: "cert-manager.io", Version: "v1", Resource: "certificates"}
	GVRCertificateRequest = schema.GroupVersionResource{
		Group: "cert-manager.io", Version: "v1", Resource: "certificaterequests"}
	GVRACMEOrder = schema.GroupVersionResource{
		Group: "acme.cert-manager.io", Version: "v1", Resource: "orders"}
	GVRACMEChallenge = schema.GroupVersionResource{
		Group: "acme.cert-manager.io", Version: "v1", Resource: "challenges"}

	// ---------------------------------------------------------------
	// External Secrets Operator — every resource ships v1 AND
	// v1beta1; modules probe both (externalsecret-nudge's
	// clusterSecretStoreGVRs/secretStoreGVRs/externalSecretGVRs and
	// the cluster-health-probes watchdog rows).
	// ---------------------------------------------------------------
	GVRExternalSecretV1 = schema.GroupVersionResource{
		Group: "external-secrets.io", Version: "v1", Resource: "externalsecrets"}
	GVRExternalSecretV1Beta1 = schema.GroupVersionResource{
		Group: "external-secrets.io", Version: "v1beta1", Resource: "externalsecrets"}
	ExternalSecretGVRs = []schema.GroupVersionResource{
		GVRExternalSecretV1, GVRExternalSecretV1Beta1}
	GVRSecretStoreV1 = schema.GroupVersionResource{
		Group: "external-secrets.io", Version: "v1", Resource: "secretstores"}
	GVRSecretStoreV1Beta1 = schema.GroupVersionResource{
		Group: "external-secrets.io", Version: "v1beta1", Resource: "secretstores"}
	SecretStoreGVRs = []schema.GroupVersionResource{
		GVRSecretStoreV1, GVRSecretStoreV1Beta1}
	GVRClusterSecretStoreV1 = schema.GroupVersionResource{
		Group: "external-secrets.io", Version: "v1", Resource: "clustersecretstores"}
	GVRClusterSecretStoreV1Beta1 = schema.GroupVersionResource{
		Group: "external-secrets.io", Version: "v1beta1", Resource: "clustersecretstores"}
	ClusterSecretStoreGVRs = []schema.GroupVersionResource{
		GVRClusterSecretStoreV1, GVRClusterSecretStoreV1Beta1}

	// ---------------------------------------------------------------
	// Cilium (cilium-identity-auditor). CiliumEndpointSlice is the
	// v2alpha1 CES-enabled replacement — the agent stops writing
	// CiliumEndpoints entirely on CES clusters.
	// ---------------------------------------------------------------
	GVRCiliumIdentity = schema.GroupVersionResource{
		Group: "cilium.io", Version: "v2", Resource: "ciliumidentities"}
	GVRCiliumEndpoint = schema.GroupVersionResource{
		Group: "cilium.io", Version: "v2", Resource: "ciliumendpoints"}
	GVRCiliumEndpointSlice = schema.GroupVersionResource{
		Group: "cilium.io", Version: "v2alpha1", Resource: "ciliumendpointslices"}

	// ---------------------------------------------------------------
	// Velero (velero-backup-auditor).
	// ---------------------------------------------------------------
	GVVeleroSchedule = schema.GroupVersionResource{
		Group: "velero.io", Version: "v1", Resource: "schedules"}
	GVVeleroBackup = schema.GroupVersionResource{
		Group: "velero.io", Version: "v1", Resource: "backups"}
	GVVeleroBackupStorageLocation = schema.GroupVersionResource{
		Group: "velero.io", Version: "v1", Resource: "backupstoragelocations"}
	GVVeleroPodVolumeBackup = schema.GroupVersionResource{
		Group: "velero.io", Version: "v1", Resource: "podvolumebackups"}
	// GVVeleroBackupRepository is the restic/kopia BackupRepository —
	// velero-backup-auditor's W13-ST2 repo health/maintenance scan.
	GVVeleroBackupRepository = schema.GroupVersionResource{
		Group: "velero.io", Version: "v1", Resource: "backuprepositories"}

	// ---------------------------------------------------------------
	// Percona Everest operator (velero-backup-auditor W9-ST3) and the
	// three Percona database operators (cluster-health-probes W10-ST5
	// quorum check + W10-CP3 watchdog rows).
	// ---------------------------------------------------------------
	GVREverestDatabaseCluster = schema.GroupVersionResource{
		Group: "everest.percona.com", Version: "v1alpha1", Resource: "databaseclusters"}
	GVREverestDatabaseClusterBackup = schema.GroupVersionResource{
		Group: "everest.percona.com", Version: "v1alpha1", Resource: "databaseclusterbackups"}
	GVRPerconaXtraDBCluster = schema.GroupVersionResource{
		Group: "pxc.percona.com", Version: "v1", Resource: "perconaxtradbclusters"}
	GVRPerconaPGCluster = schema.GroupVersionResource{
		Group: "pgv2.percona.com", Version: "v2", Resource: "perconapgclusters"}
	GVRPerconaServerMongoDB = schema.GroupVersionResource{
		Group: "psmdb.percona.com", Version: "v1", Resource: "perconaservermongodbs"}
	// PerconaClusterGVRs is the quorum check's sweep set — a cluster
	// without a given operator simply has no objects.
	PerconaClusterGVRs = []schema.GroupVersionResource{
		GVRPerconaXtraDBCluster, GVRPerconaPGCluster, GVRPerconaServerMongoDB}

	// ---------------------------------------------------------------
	// medik8s operators (dead-node-sweeper, cluster-health-probes
	// watchdog rows).
	// ---------------------------------------------------------------
	GVRNodeHealthCheck = schema.GroupVersionResource{
		Group: "remediation.medik8s.io", Version: "v1alpha1", Resource: "nodehealthchecks"}
	GVRSelfNodeRemediation = schema.GroupVersionResource{
		Group: "self-node-remediation.medik8s.io", Version: "v1alpha1", Resource: "selfnoderemediations"}
	GVRFenceAgentsRemediation = schema.GroupVersionResource{
		Group: "fence-agents-remediation.medik8s.io", Version: "v1alpha1", Resource: "fenceagentsremediations"}

	// ---------------------------------------------------------------
	// k0s autopilot (kube.MaintenanceActive, concourse-workdir-
	// janitor, descheduler-storm-gate). Declared here so every
	// consumer shares one literal; AutopilotPlanGVR is the original
	// exported name kept for API stability.
	// ---------------------------------------------------------------
	// AutopilotPlanGVR is the k0s autopilot Plan resource — a Plan in a
	// non-terminal state means a cluster upgrade is in flight.
	AutopilotPlanGVR = schema.GroupVersionResource{
		Group:    "autopilot.k0sproject.io",
		Version:  "v1beta2",
		Resource: "plans",
	}

	// ---------------------------------------------------------------
	// StateFul / data-platform operators (cluster-health-probes).
	// ---------------------------------------------------------------
	GVRScyllaCluster = schema.GroupVersionResource{
		Group: "scylla.scylladb.com", Version: "v1", Resource: "scyllaclusters"}
	GVRDragonfly = schema.GroupVersionResource{
		Group: "dragonflydb.io", Version: "v1alpha1", Resource: "dragonflies"}
	GVRRabbitMQCluster = schema.GroupVersionResource{
		Group: "rabbitmq.com", Version: "v1beta1", Resource: "rabbitmqclusters"}

	// ---------------------------------------------------------------
	// GitOps / delivery operators (cluster-health-probes watchdog
	// rows; argocd_app_stuck reads Applications).
	// ---------------------------------------------------------------
	// GVRArgoCD is the argoproj.io/v1beta1 ArgoCD cluster CR (the
	// operator watchdog's target); GVRArgoCDApplication is the
	// argoproj.io/v1alpha1 Application CR the stuck-app auditor reads
	// — different resource, different version, do not merge.
	GVRArgoCD = schema.GroupVersionResource{
		Group: "argoproj.io", Version: "v1beta1", Resource: "argocds"}
	GVRArgoCDApplication = schema.GroupVersionResource{
		Group: "argoproj.io", Version: "v1alpha1", Resource: "applications"}
	GVRKargoStage = schema.GroupVersionResource{
		Group: "kargo.akuity.io", Version: "v1alpha1", Resource: "stages"}
	GVRKargoWarehouse = schema.GroupVersionResource{
		Group: "kargo.akuity.io", Version: "v1alpha1", Resource: "warehouses"}
	GVRKargoPromotion = schema.GroupVersionResource{
		Group: "kargo.akuity.io", Version: "v1alpha1", Resource: "promotions"}
	// GVRArgoAnalysisRun is the argoproj.io/v1alpha1 AnalysisRun the
	// kargo-promotion-health zombie guard scans (Rollouts analysis).
	GVRArgoAnalysisRun = schema.GroupVersionResource{
		Group: "argoproj.io", Version: "v1alpha1", Resource: "analysisruns"}

	// ---------------------------------------------------------------
	// Shipwright (failed-jobs-janitor BuildRuns; cluster-health-probes
	// watchdog rows for Builds and the operator's ShipwrightBuild CRD).
	// ---------------------------------------------------------------
	GVRShipwrightBuild = schema.GroupVersionResource{
		Group: "shipwright.io", Version: "v1beta1", Resource: "builds"}
	GVRShipwrightBuildRun = schema.GroupVersionResource{
		Group: "shipwright.io", Version: "v1beta1", Resource: "buildruns"}
	GVRShipwrightOperatorBuild = schema.GroupVersionResource{
		Group: "operator.shipwright.io", Version: "v1alpha1", Resource: "shipwrightbuilds"}

	// ---------------------------------------------------------------
	// Tekton + KEDA + OLM (cluster-health-probes watchdog rows).
	// ---------------------------------------------------------------
	GVRTektonPipelineRun = schema.GroupVersionResource{
		Group: "tekton.dev", Version: "v1", Resource: "pipelineruns"}
	GVRTektonTaskRun = schema.GroupVersionResource{
		Group: "tekton.dev", Version: "v1", Resource: "taskruns"}
	GVRKedaScaledObject = schema.GroupVersionResource{
		Group: "keda.sh", Version: "v1alpha1", Resource: "scaledobjects"}
	GVROLMClusterServiceVersion = schema.GroupVersionResource{
		Group: "operators.coreos.com", Version: "v1alpha1", Resource: "clusterserviceversions"}
	GVROLMSubscription = schema.GroupVersionResource{
		Group: "operators.coreos.com", Version: "v1alpha1", Resource: "subscriptions"}

	// ---------------------------------------------------------------
	// Gateway API (cluster-health-probes cilium-operator signature —
	// the gwv1(resource) helper built these inline).
	// ---------------------------------------------------------------
	GVRGatewayClass = schema.GroupVersionResource{
		Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gatewayclasses"}
	GVRGateway = schema.GroupVersionResource{
		Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}
	GVRHTTPRoute = schema.GroupVersionResource{
		Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"}
	GVRGRPCRoute = schema.GroupVersionResource{
		Group: "gateway.networking.k8s.io", Version: "v1", Resource: "grpcroutes"}

	// ---------------------------------------------------------------
	// Trivy operator report CRDs + Policy Reporter (api-object-sprawl-
	// report-gc). The aquasecurity reports and PolicyReports pile up
	// per ReplicaSet/Pod churn — the GC deletes ones whose owner is
	// gone.
	// ---------------------------------------------------------------
	GVRVulnerabilityReport = schema.GroupVersionResource{
		Group: "aquasecurity.github.io", Version: "v1alpha1", Resource: "vulnerabilityreports"}
	GVRConfigAuditReport = schema.GroupVersionResource{
		Group: "aquasecurity.github.io", Version: "v1alpha1", Resource: "configauditreports"}
	GVRExposedSecretReport = schema.GroupVersionResource{
		Group: "aquasecurity.github.io", Version: "v1alpha1", Resource: "exposedsecretreports"}
	GVREphemeralReport = schema.GroupVersionResource{
		Group: "aquasecurity.github.io", Version: "v1alpha1", Resource: "ephemeralreports"}
	GVRPolicyReport = schema.GroupVersionResource{
		Group: "wgpolicyk8s.io", Version: "v1alpha2", Resource: "policyreports"}

	// ---------------------------------------------------------------
	// Liqo multi-cluster networking (liqo-tunnel-health) + CiliumNode
	// (cilium-missing-endpoint node census).
	// ---------------------------------------------------------------
	GVRLiqoConnection = schema.GroupVersionResource{
		Group: "networking.liqo.io", Version: "v1beta1", Resource: "connections"}
	GVRLiqoGatewayClient = schema.GroupVersionResource{
		Group: "networking.liqo.io", Version: "v1beta1", Resource: "gatewayclients"}
	GVRLiqoGatewayServer = schema.GroupVersionResource{
		Group: "networking.liqo.io", Version: "v1beta1", Resource: "gatewayservers"}
	GVRCiliumNode = schema.GroupVersionResource{
		Group: "cilium.io", Version: "v2", Resource: "ciliumnodes"}

	// ---------------------------------------------------------------
	// CloudNativePG (postgres-wal-archive-guard — complements the
	// Percona/Everest GVRs above).
	// ---------------------------------------------------------------
	GVRCNPGCluster = schema.GroupVersionResource{
		Group: "postgresql.cnpg.io", Version: "v1", Resource: "clusters"}
)

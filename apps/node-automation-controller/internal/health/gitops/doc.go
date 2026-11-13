// Package gitops holds the GitOps control-plane checks riding the
// cluster-health sweep: argocd-app-stuck,
// flux-helmrelease-retries, kargo-promotion-health, the flux-stuck
// flux-kustomization-health domino unblocker, the pullsecret-audit
// workload-scale-flapping + imagepull-secret-auditor hygiene checks,
// keda-scaledobject-guard and the OLM subscription health behind
// gitops/olm. Each reports on the shared kuberhealthy_check series
// under its own check name.
package gitops

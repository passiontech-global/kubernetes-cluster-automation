// Package gitops holds the GitOps control-plane checks riding the
// cluster-health sweep: argocd-app-stuck,
// flux-helmrelease-retries, kargo-promotion-health, the W13-GO1
// flux-kustomization-health domino unblocker, and the W13-SC1
// workload-scale-flapping + imagepull-secret-auditor hygiene checks.
// Each reports on the shared kuberhealthy_check series under its own
// check name.
package gitops

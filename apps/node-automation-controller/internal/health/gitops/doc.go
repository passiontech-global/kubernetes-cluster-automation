// Package gitops holds the GitOps control-plane checks riding the
// cluster-health sweep: argocd-app-stuck,
// flux-helmrelease-retries and kargo-promotion-health. Each reports
// on the shared kuberhealthy_check series under its own check name.
package gitops

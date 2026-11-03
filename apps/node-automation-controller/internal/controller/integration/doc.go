// Package integration groups the modules that unstick third-party
// controllers via their CRDs (dynamic client): HelmRelease
// pending-operation unlocks plus failed helm-hook Job reaping
// (helmrelease_unlocker), ExternalSecret backoff nudges
// (externalsecret_nudge), wedged cert-manager ACME Order reaping
// (certmanager_reaper), leaked CiliumIdentity auditing with two-pass
// safe GC (cilium_identity_auditor), and webhook caBundle / TLS-secret
// expiry drift auditing (cert_drift_auditor).
package integration

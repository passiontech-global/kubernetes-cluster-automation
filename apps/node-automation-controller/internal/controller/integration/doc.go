// Package integration groups the modules that unstick third-party
// controllers via their CRDs (dynamic client): HelmRelease
// pending-operation unlocks (helmrelease_unlocker), ExternalSecret
// backoff nudges (externalsecret_nudge), wedged cert-manager ACME
// Order reaping (certmanager_reaper) and leaked CiliumIdentity
// auditing (cilium_identity_auditor).
package integration

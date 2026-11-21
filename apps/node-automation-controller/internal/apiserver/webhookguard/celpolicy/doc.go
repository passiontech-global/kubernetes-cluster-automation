// Package celpolicy implements the CEL Admission Policy Guard for
// ValidatingAdmissionPolicy / ValidatingAdmissionPolicyBinding and
// MutatingAdmissionPolicy / MutatingAdmissionPolicyBinding (admissionregistration/v1).
//
// It audits fail-closed CEL policies for critical self-healing namespace
// exposure (patching a kubernetes.io/metadata.name NotIn exclusion behind
// heal.FluxPatchGate + heal.AllowedV when CEL_POLICY_CRITICAL_NS_ENFORCE_ENABLED
// is enabled) and protects the cluster against self-deadlock by circuit-breaking
// policies with sustained missing paramRef or CEL evaluation error storms to
// failurePolicy=Ignore (auto-restoring to Fail after 2 consecutive clean sweeps).
// Every API list/get gracefully skips on 403 Forbidden and 404/NoMatch.
package celpolicy

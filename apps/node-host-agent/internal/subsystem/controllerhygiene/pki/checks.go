// checks.go — the pki-domain check constructors. The parent
// controllerhygiene package wires the checks into its ordered
// dispatch table (check.go) — order there is load-bearing.
package pki

import "github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"

// NewDrift returns the pki-cert-drift on-disk-vs-served PKI cert drift check.
func NewDrift(d *cdeps.Deps) *DriftCheck { return &DriftCheck{d: d} }

// NewKubeCert returns the kubeconfig-cert-expiry embedded kubeconfig client-cert
// expiry check — it rides the apiserver freeze check's ungated
// slot, not its own table row.
func NewKubeCert(d *cdeps.Deps) *KubeCertCheck { return &KubeCertCheck{d: d} }

// checks.go — the pods-domain check constructors (pod-teardown,
// konnectivity, dns-resolv). The parent workerhygiene package wires
// them into its ordered dispatch list.
package pods

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// NewPodTeardown returns the 36-pod-teardown check.
func NewPodTeardown(d *wdeps.Deps) *PodTeardownCheck {
	return &PodTeardownCheck{d: d}
}

// NewKonn returns the 30-konnectivity stale-identifier guard.
func NewKonn(d *wdeps.Deps) *KonnCheck { return &KonnCheck{d: d} }

// NewDNSResolv returns the 33-dns-resolv-drift guard.
func NewDNSResolv(d *wdeps.Deps) *DNSResolvCheck {
	return &DNSResolvCheck{d: d}
}

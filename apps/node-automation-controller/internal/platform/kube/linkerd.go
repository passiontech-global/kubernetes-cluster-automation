// linkerd.go — the linkerd identifiers more than one domain tree
// keys on, homed on the leaf so internal/apiserver/* can share them
// without importing internal/health/* (depguard keeps domain trees
// self-contained). Ops contract — the values are byte-stable.
package kube

import corev1 "k8s.io/api/core/v1"

const (
	// LinkerdProxyContainer is the sidecar container name linkerd
	// injection adds — a pod carrying it in containers OR
	// initContainers counts as meshed. Read by the unmeshed-pod
	// auditor (apiserver/webhookguard), the linkerd nethealth
	// checks, and the zombie-sidecar reaper.
	LinkerdProxyContainer = "linkerd-proxy"
	// LinkerdInjectKey is the namespace/pod injection opt-in
	// label+annotation key ("linkerd.io/inject") — enabled opts in,
	// disabled opts out.
	LinkerdInjectKey = "linkerd.io/inject"
	// LinkerdInjectorWebhook is the injector's full sub-webhook name
	// inside the MutatingWebhookConfiguration — matched exactly so a
	// similarly-named webhook (e.g. "acme-linkerd-proxy-injector.example.com")
	// can never impersonate the health signal.
	LinkerdInjectorWebhook = "linkerd-proxy-injector.linkerd.io"
)

// PodIsMeshed reports whether the pod spec carries the linkerd-proxy
// in containers OR initContainers. Linkerd >=1.12 native sidecars
// inject the proxy as an init container (the kernel keeps it running
// after the container's PID 1 exits), so a Containers-only scan —
// what PodSpecHasContainer does — misses every natively injected pod.
// Mesh-membership checks (nethealth linkerd guards, unmeshed
// auditors) must use this; PodSpecHasContainer stays for
// patch-eligibility checks that need a real container entry.
func PodIsMeshed(ps *corev1.PodSpec) bool {
	for i := range ps.Containers {
		if ps.Containers[i].Name == LinkerdProxyContainer {
			return true
		}
	}
	for i := range ps.InitContainers {
		if ps.InitContainers[i].Name == LinkerdProxyContainer {
			return true
		}
	}
	return false
}

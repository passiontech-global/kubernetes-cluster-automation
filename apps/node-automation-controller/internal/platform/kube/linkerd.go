// linkerd.go — the linkerd identifiers more than one domain tree
// keys on, homed on the leaf so internal/apiserver/* can share them
// without importing internal/health/* (depguard keeps domain trees
// self-contained). Ops contract — the values are byte-stable.
package kube

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

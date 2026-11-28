// live_socket_targets.go — TLS endpoint target discovery and mounted Secret
// attribution for Check 5 (live_socket_audit.go): collects referenced TLS
// Services (MWC/VWC, CRD conversion webhooks, APIService), resolves Ready
// endpoints and TLS ports, and matches served X.509 identities against mounted
// kubernetes.io/tls Secrets.
package certdriftauditor

import (
	"context"
	"crypto/x509"
	"net"
	"strings"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// certIPStrings renders IP SANs into the same textual form the served
// certificate's ip.String() match uses. Both TLS-Secret census paths
// (Check B's reused list and the standalone fallback list) must fill
// ipNames or an IP-only served cert can never find its Secret.
func certIPStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// servesName reports whether this Secret's certificate was issued for
// the probe's SNI name (or the bare Service name). Used to pick the
// Secret that actually serves a port when a Pod mounts several.
func (m tlsSecretMeta) servesName(svcName, serverName string) bool {
	for _, n := range append([]string{m.commonName}, m.dnsNames...) {
		if n == "" {
			continue
		}
		if n == serverName || n == svcName || n == svcName+"." || strings.HasPrefix(n, svcName+".") {
			return true
		}
	}
	return false
}

// collectReferencedTLSServices returns "namespace/name" → the port the
// reference pins (0 = unspecified, fall back to the Service's TLS port).
// Only the in-cluster clientConfig surfaces this operator can actually
// READ are used: MWC/VWC, CRD conversion and APIService. Ingress and
// HTTPRoute were deliberately dropped — NAC has no RBAC on ingresses
// (a guaranteed 403 that tore down the whole 15m audit) and dialing a
// proxy/L7 backend's Service port does not prove the origin's cert.
func (a *certDriftAuditor) collectReferencedTLSServices(ctx context.Context) (map[string]int32, error) {
	refs := map[string]int32{}
	opts := metav1.ListOptions{Limit: kube.DefaultListPageSize}
	log := logf.FromContext(ctx)

	mwcs, vwcs, ok := a.cachedWebhookConfigs()
	if ok {
		addWebhookRefs(refs, mwcs, vwcs)
	} else {
		var err error
		mwcs, err = kube.ListAll(ctx, opts, kube.MutatingWebhookConfigurations(a.cs))
		if err != nil {
			if apierrors.IsForbidden(err) {
				log.Info("skip mutatingwebhookconfigurations: RBAC forbidden", "err", err)
			} else {
				return nil, err
			}
		} else {
			for i := range mwcs {
				addMutatingWebhookRefs(refs, mwcs[i].Webhooks)
			}
		}
		vwcs, err = kube.ListAll(ctx, opts, kube.ValidatingWebhookConfigurations(a.cs))
		if err != nil {
			if apierrors.IsForbidden(err) {
				log.Info("skip validatingwebhookconfigurations: RBAC forbidden", "err", err)
			} else {
				return nil, err
			}
		} else {
			for i := range vwcs {
				addValidatingWebhookRefs(refs, vwcs[i].Webhooks)
			}
		}
	}

	// CRD conversion refs ride the same census as Check A (informer
	// cache first, dynamic fallback). The cache is only warm when run()
	// called auditWebhookCABundles first; standalone unit tests fall
	// back to listCachedCRDs or dynamic ListEach.
	if a.crdRefsCached() {
		for key, port := range a.cachedCRDRefs() {
			ns, name, ok := strings.Cut(key, "/")
			if !ok {
				continue
			}
			putRef(refs, ns, name, port)
		}
	} else if crds, ok := a.listCachedCRDs(ctx); ok {
		for i := range crds {
			collectTypedCRDConversionService(&crds[i], refs)
		}
	} else if a.dyn != nil {
		listErr := kube.ListEach(ctx, opts,
			kube.DynamicPage(a.dyn.Resource(kube.GVRCustomResourceDefinition)),
			func(page []unstructured.Unstructured) error {
				for i := range page {
					collectCRDConversionService(&page[i], refs)
				}
				return nil
			})
		if listErr != nil && !kube.IsCRDAbsent(listErr) && !apierrors.IsForbidden(listErr) {
			return nil, listErr
		}
	}
	if a.dyn != nil {
		// APIService objects are tiny — reading them here is cheap.
		listErr := kube.ListEach(ctx, opts,
			kube.DynamicPage(a.dyn.Resource(kube.GVRAPIService)),
			func(page []unstructured.Unstructured) error {
				for i := range page {
					collectAPIServiceRef(&page[i], refs)
				}
				return nil
			})
		if listErr != nil && !kube.IsCRDAbsent(listErr) && !apierrors.IsForbidden(listErr) {
			return nil, listErr
		}
	}
	return refs, nil
}

func putRef(refs map[string]int32, ns, name string, port int32) {
	if ns == "" || name == "" {
		return
	}
	key := ns + "/" + name
	if prev, exists := refs[key]; !exists || (prev == 0 && port > 0) {
		refs[key] = port
	}
}

func addWebhookRefs(refs map[string]int32,
	mwcs []admissionv1.MutatingWebhookConfiguration,
	vwcs []admissionv1.ValidatingWebhookConfiguration) {
	for i := range mwcs {
		addMutatingWebhookRefs(refs, mwcs[i].Webhooks)
	}
	for i := range vwcs {
		addValidatingWebhookRefs(refs, vwcs[i].Webhooks)
	}
}

func addMutatingWebhookRefs(refs map[string]int32, ws []admissionv1.MutatingWebhook) {
	for i := range ws {
		addWebhookServiceRef(refs, ws[i].ClientConfig.Service)
	}
}

func addValidatingWebhookRefs(refs map[string]int32, ws []admissionv1.ValidatingWebhook) {
	for i := range ws {
		addWebhookServiceRef(refs, ws[i].ClientConfig.Service)
	}
}

func addWebhookServiceRef(refs map[string]int32, svc *admissionv1.ServiceReference) {
	if svc == nil {
		return
	}
	var port int32
	if svc.Port != nil {
		port = *svc.Port
	}
	putRef(refs, svc.Namespace, svc.Name, port)
}

func collectCRDConversionService(u *unstructured.Unstructured, refs map[string]int32) {
	strategy, _ := kube.NestedString(u.Object, "spec", "conversion", "strategy")
	if strategy != "Webhook" {
		return
	}
	ns, _ := kube.NestedString(u.Object, "spec", "conversion", "webhook", "clientConfig", "service", "namespace")
	name, _ := kube.NestedString(u.Object, "spec", "conversion", "webhook", "clientConfig", "service", "name")
	port, _ := nestedInt32(u.Object, "spec", "conversion", "webhook", "clientConfig", "service", "port")
	putRef(refs, ns, name, port)
}

func collectAPIServiceRef(u *unstructured.Unstructured, refs map[string]int32) {
	ns, _ := kube.NestedString(u.Object, "spec", "service", "namespace")
	name, _ := kube.NestedString(u.Object, "spec", "service", "name")
	port, _ := nestedInt32(u.Object, "spec", "service", "port")
	putRef(refs, ns, name, port)
}

func nestedInt32(obj map[string]any, fields ...string) (int32, bool) {
	v, found, err := unstructured.NestedInt64(obj, fields...)
	if err != nil || !found {
		return 0, false
	}
	return int32(v), true
}

type endpointAddr struct {
	ip      string
	podName string
}

func buildReadyEndpointsMap(slices []discoveryv1.EndpointSlice) map[string][]endpointAddr {
	out := map[string][]endpointAddr{}
	for i := range slices {
		es := &slices[i]
		svcName := es.Labels[discoveryv1.LabelServiceName]
		if svcName == "" {
			continue
		}
		key := es.Namespace + "/" + svcName
		for j := range es.Endpoints {
			ep := &es.Endpoints[j]
			if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
				continue
			}
			if len(ep.Addresses) == 0 {
				continue
			}
			podName := ""
			if ep.TargetRef != nil && ep.TargetRef.Kind == "Pod" {
				podName = ep.TargetRef.Name
			}
			out[key] = append(out[key], endpointAddr{ip: ep.Addresses[0], podName: podName})
		}
	}
	return out
}

func buildProbeTarget(svc *corev1.Service, knownTLSSvcs map[string]int32,
	secrets map[secretMetricKey]tlsSecretMeta, podsByNSName map[string]*corev1.Pod,
	podsByNS map[string][]*corev1.Pod, epBySvc map[string][]endpointAddr) (liveProbeTarget, bool) {

	if svc.Spec.Type == corev1.ServiceTypeExternalName || len(svc.Spec.Ports) == 0 {
		return liveProbeTarget{}, false
	}
	svcKey := svc.Namespace + "/" + svc.Name
	pinnedPort, isKnownRef := knownTLSSvcs[svcKey]

	var matchedPod *corev1.Pod
	var ip string
	for _, ep := range epBySvc[svcKey] {
		if ep.podName == "" {
			continue
		}
		p := podsByNSName[svc.Namespace+"/"+ep.podName]
		if p != nil && p.DeletionTimestamp == nil && p.Status.Phase == corev1.PodRunning && kube.PodReadyCond(p) {
			matchedPod = p
			ip = ep.ip
			break
		}
	}
	if matchedPod == nil && len(svc.Spec.Selector) > 0 {
		for _, p := range podsByNS[svc.Namespace] {
			if p.Status.PodIP != "" && selectorMatches(svc.Spec.Selector, p.Labels) {
				matchedPod = p
				ip = p.Status.PodIP
				break
			}
		}
	}
	if matchedPod == nil || ip == "" {
		return liveProbeTarget{}, false
	}

	mounted := mountedTLSSecrets(matchedPod, secrets)
	if len(mounted) == 0 {
		return liveProbeTarget{}, false
	}

	port, isTLSPort := resolveServiceTLSPort(svc, matchedPod)
	// A ServiceReference.Port is a SERVICE port; the probe dials the
	// endpoint (pod IP), so it must be translated through targetPort.
	if pinnedPort > 0 {
		if translated, ok := resolvePinnedServicePort(svc, matchedPod, pinnedPort); ok {
			port, isTLSPort = translated, true
		}
	}
	if !isKnownRef && !isTLSPort {
		return liveProbeTarget{}, false
	}
	if port <= 0 {
		port = svc.Spec.Ports[0].Port
		if svc.Spec.Ports[0].TargetPort.Type == intstr.Int && svc.Spec.Ports[0].TargetPort.IntVal > 0 {
			port = svc.Spec.Ports[0].TargetPort.IntVal
		}
	}
	serverName := svc.Name + "." + svc.Namespace + ".svc"
	// pickServingSecret reports only a real SAN/CN match. The blind
	// mounted[0] fallback is confined to known TLS references: for a
	// TLS-port-only Service we cannot prove a mounted Secret serves the
	// port, so the audit loop re-resolves it from the served certificate.
	secret, nameMatched := pickServingSecret(mounted, svc.Name, serverName)
	if isKnownRef && !nameMatched {
		secret = mounted[0]
	}
	if secret.dnsName != "" {
		serverName = secret.dnsName
	}
	return liveProbeTarget{
		svc:        *svc,
		pod:        matchedPod,
		ip:         ip,
		port:       port,
		serverName: serverName,
		isKnownRef: isKnownRef,
		secret:     secret,
		secrets:    mounted,
	}, true
}

func selectorMatches(sel, labels map[string]string) bool {
	for k, v := range sel {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// resolvePinnedServicePort translates a ServiceReference.Service.Port
// (the Service-side port) into the container port the endpoint listens
// on. Without this the audit dials podIP:<servicePort> and reports a
// false TLS drift for every webhook whose targetPort differs.
func resolvePinnedServicePort(svc *corev1.Service, pod *corev1.Pod, port int32) (int32, bool) {
	for i := range svc.Spec.Ports {
		if svc.Spec.Ports[i].Port == port {
			return resolveContainerPort(&svc.Spec.Ports[i], pod), true
		}
	}
	return 0, false
}

// podTLSSecretNames lists every Secret source referenced by the Pod's
// volumes (direct or projected). Volumes are shared by the app and init
// containers; the explicit InitContainers pass also resolves a TLS
// Secret an init sidecar mounts by name, so a cert staged before the main
// container starts is never missed by the live-socket census.
func podTLSSecretNames(pod *corev1.Pod) []string {
	var out []string
	secretByVolume := map[string]string{}
	addSecret := func(name string) {
		if name != "" {
			out = append(out, name)
		}
	}
	for i := range pod.Spec.Volumes {
		v := &pod.Spec.Volumes[i]
		if v.Secret != nil {
			addSecret(v.Secret.SecretName)
			secretByVolume[v.Name] = v.Secret.SecretName
		}
		if v.Projected != nil {
			for j := range v.Projected.Sources {
				if src := v.Projected.Sources[j].Secret; src != nil {
					addSecret(src.Name)
					secretByVolume[v.Name] = src.Name
				}
			}
		}
	}
	for i := range pod.Spec.InitContainers {
		for j := range pod.Spec.InitContainers[i].VolumeMounts {
			if name, ok := secretByVolume[pod.Spec.InitContainers[i].VolumeMounts[j].Name]; ok {
				addSecret(name)
			}
		}
	}
	return out
}

// mountedTLSSecrets is the multi-Secret successor to
// firstMountedTLSSecret: it returns every TLS Secret mounted (directly
// or via a projected volume) into the Pod, not just the first one.
func mountedTLSSecrets(pod *corev1.Pod, secrets map[secretMetricKey]tlsSecretMeta) []tlsSecretMeta {
	var out []tlsSecretMeta
	seen := map[string]bool{}
	for _, name := range podTLSSecretNames(pod) {
		if seen[name] {
			continue
		}
		if meta, ok := secrets[secretMetricKey{pod.Namespace, name}]; ok {
			seen[name] = true
			out = append(out, meta)
		}
	}
	return out
}

func podMountsTLSSecret(pod *corev1.Pod, secrets map[secretMetricKey]tlsSecretMeta) bool {
	for _, name := range podTLSSecretNames(pod) {
		if _, ok := secrets[secretMetricKey{pod.Namespace, name}]; ok {
			return true
		}
	}
	return false
}

// pickServingSecret selects the mounted Secret whose Subject/SAN names
// the Service. It never guesses: a Pod that mounts only a client mTLS
// Secret for an unrelated upstream must not be assumed to serve it.
// The bool distinguishes a real match from "no Secret named this port".
func pickServingSecret(mounted []tlsSecretMeta, svcName, serverName string) (tlsSecretMeta, bool) {
	for _, m := range mounted {
		if m.servesName(svcName, serverName) {
			return m, true
		}
	}
	return tlsSecretMeta{}, false
}

// matchServedSecret identifies the mounted Secret that actually serves a
// port by comparing the certificate presented on the socket with each
// mounted Secret's Subject CN / DNS+IP SANs. A name match with a different
// serial means the Secret rotated but the Pod still serves the old cert —
// genuine drift. When no mounted Secret bears the served identity, a
// TLS-port-only Service is skipped rather than restarted on a guess.
func matchServedSecret(mounted []tlsSecretMeta, served *x509.Certificate) (tlsSecretMeta, bool) {
	if served == nil {
		return tlsSecretMeta{}, false
	}
	names := make(map[string]bool, len(served.DNSNames)+len(served.IPAddresses)+1)
	if served.Subject.CommonName != "" {
		names[served.Subject.CommonName] = true
	}
	for _, n := range served.DNSNames {
		names[n] = true
	}
	for _, ip := range served.IPAddresses {
		names[ip.String()] = true
	}
	for _, m := range mounted {
		// An empty CN is NOT an identity — without the guard, a served
		// cert with an empty SAN/CN set would match every mounted Secret
		// that has no CN and restart the wrong workload.
		if m.commonName != "" && names[m.commonName] {
			return m, true
		}
		for _, n := range m.dnsNames {
			if names[n] {
				return m, true
			}
		}
		for _, ip := range m.ipNames {
			if names[ip] {
				return m, true
			}
		}
	}
	return tlsSecretMeta{}, false
}

func anyMountedSecretServesSerial(mounted []tlsSecretMeta, serialHex string) bool {
	for _, m := range mounted {
		if m.serialHex == serialHex {
			return true
		}
	}
	return false
}

func resolveServiceTLSPort(svc *corev1.Service, pod *corev1.Pod) (int32, bool) {
	for i := range svc.Spec.Ports {
		sp := &svc.Spec.Ports[i]
		name := strings.ToLower(sp.Name)
		namedTLS := name == "https" || name == "tls" || name == "webhook"
		numTLS := sp.Port == 443 || sp.Port == 8443 || sp.Port == 9443 ||
			(sp.TargetPort.Type == intstr.Int && (sp.TargetPort.IntVal == 443 || sp.TargetPort.IntVal == 8443 || sp.TargetPort.IntVal == 9443))
		if namedTLS || numTLS {
			return resolveContainerPort(sp, pod), true
		}
	}
	return resolveContainerPort(&svc.Spec.Ports[0], pod), false
}

func resolveContainerPort(sp *corev1.ServicePort, pod *corev1.Pod) int32 {
	if sp.TargetPort.Type == intstr.Int && sp.TargetPort.IntVal > 0 {
		return sp.TargetPort.IntVal
	}
	if sp.TargetPort.Type == intstr.String && sp.TargetPort.StrVal != "" {
		for i := range pod.Spec.Containers {
			if port := namedContainerPort(pod.Spec.Containers[i].Ports, sp.TargetPort.StrVal); port > 0 {
				return port
			}
		}
		// Native sidecars (restartPolicy: Always on an initContainer)
		// live for the whole pod and may own the named targetPort —
		// e.g. a service-mesh proxy terminating the Service traffic.
		for i := range pod.Spec.InitContainers {
			ic := &pod.Spec.InitContainers[i]
			if ic.RestartPolicy == nil || *ic.RestartPolicy != corev1.ContainerRestartPolicyAlways {
				continue
			}
			if port := namedContainerPort(ic.Ports, sp.TargetPort.StrVal); port > 0 {
				return port
			}
		}
	}
	return sp.Port
}

func namedContainerPort(ports []corev1.ContainerPort, name string) int32 {
	for i := range ports {
		if ports[i].Name == name {
			return ports[i].ContainerPort
		}
	}
	return 0
}

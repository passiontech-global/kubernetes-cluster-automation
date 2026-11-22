// live_socket_audit.go — Live-Socket vs Secret X.509 Certificate Drift
// Healer (#5): probes Ready Service endpoints for 4 TLS service classes
// (Webhook/CRD conversion Services, APIService Services, TLS Ingress/Gateway
// Services, and Services whose Ready Pods mount a kubernetes.io/tls Secret on
// ports 443/8443/9443 or named https/tls/webhook), compares the served X.509
// serial against the mounted Secret's tls.crt across >=2 consecutive scans,
// exports node_automation_tls_live_socket_drift + Warning Event, and performs
// guarded rollout restarts when the served cert is expired or <7d from expiry
// while the Secret holds a newer cert.
package certdriftauditor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

const (
	liveProbeTimeout         = 3 * time.Second
	liveProbeWorkers         = 4
	liveDriftConfirmScans    = 2
	liveSecretStableMinAge   = 30 * time.Second
	liveDriftEventCooldown   = time.Hour
	liveDriftRolloutCooldown = 2 * time.Hour
	liveDriftExpiryThreshold = 7 * 24 * time.Hour
)

type liveCertProber func(ctx context.Context, addr, serverName string) (*x509.Certificate, error)

type liveDriftMetricKey struct{ namespace, service, secret string }

type tlsSecretMeta struct {
	name         string
	serialHex    string
	notAfter     time.Time
	creationTime time.Time
	// dnsName is kept for the probe's SNI (first SAN); dnsNames holds the
	// full set so the port-serving Secret can be picked by SAN/CN match
	// instead of "whichever Secret happens to be mounted first".
	dnsName    string
	dnsNames   []string
	ipNames    []string
	commonName string
}

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

type liveProbeTarget struct {
	svc        corev1.Service
	pod        *corev1.Pod
	ip         string
	port       int32
	serverName string
	// isKnownRef proves an in-cluster TLS reference (webhook/CRD
	// conversion/APIService) pins this Service. Only then may the audit
	// assume a mounted Secret serves the port without a Subject/SAN match
	// to the served certificate — a TLS-port-only hit must not fall back to
	// mounted[0] (a Pod may mount a client mTLS Secret for an unrelated
	// upstream and would be restarted every 2h).
	isKnownRef bool
	// secret is the SAN/CN-matched Secret serving this port (metric label
	// + expiry comparison). secrets is every TLS Secret mounted into the
	// Pod: a socket serial matching ANY of them means the workload is
	// already serving a mounted cert, so no drift/rollout is warranted.
	secret     tlsSecretMeta
	secrets    []tlsSecretMeta
	servedCert *x509.Certificate
	probeErr   error
}

var liveDriftSystemNamespaces = map[string]bool{
	"kube-system":      true,
	"kube-public":      true,
	"kube-node-lease":  true,
	"flux-system":      true,
	"node-ops":         true,
	"cert-manager":     true,
	"linkerd":          true,
	"linkerd-cni":      true,
	"external-secrets": true,
	// Operators/platform tenants whose TLS workloads are shared
	// infrastructure: an automatic rollout there has a wide blast
	// radius, so drift is still reported but the restart is skipped.
	"k0s-system":        true,
	"gatekeeper-system": true,
	"metallb-system":    true,
	"tigera-operator":   true,
}

var liveDriftDBQuorumLabels = []string{
	"cnpg.io/cluster",
	"postgres-operator.crunchydata.com/cluster",
	"pgv2.percona.com/cluster",
	"everest.percona.com/cluster",
	"scylla.scylladb.com/cluster",
	"apps.rabbitmq.com/cluster",
	// Legacy/parallel operator labels seen on stateful DB workloads.
	"postgresql.cnpg.io/cluster",
	"operator.crunchydata.com/cluster",
	// Keep parity with the watchdogs' DB-quorum label sets — restarting a
	// member of one of these clusters can breach quorum.
	"pxc.percona.com/cluster",
	"psmdb.percona.com/cluster",
	"dragonflydb.io/cluster",
	"nats_cluster",
}

func defaultLiveCertProber(ctx context.Context, addr, serverName string) (*x509.Certificate, error) {
	// NetDialer.Timeout bounds the TCP connect only — a server that
	// accepts the socket and then stalls the TLS handshake would hold
	// this goroutine (and a probe worker slot) forever. Bound the
	// whole handshake, not just the connect.
	pctx, cancel := context.WithTimeout(ctx, liveProbeTimeout)
	defer cancel()
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: liveProbeTimeout},
		Config: &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true, // serial comparison only — endpoint IP may lack SAN
		},
	}
	conn, err := d.DialContext(pctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return nil, errors.New("non-tls connection")
	}
	cs := tc.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return nil, errors.New("no peer certificates presented")
	}
	return cs.PeerCertificates[0], nil
}

func (a *certDriftAuditor) auditLiveSockets(ctx context.Context) error {
	a.seenLiveDrift.Begin()
	log := logf.FromContext(ctx)
	now := a.now.Now()
	seenStreaks := map[string]bool{}
	prune := func() {
		a.liveDriftStreak.Prune(func(k string) bool { return seenStreaks[k] })
		a.seenLiveDrift.Prune(metrics.TLSLiveSocketDrift.DeleteLabelValues)
	}

	var err error
	secrets := a.cachedTLSSecretMeta()
	// The census flag, not an empty map, decides whether Check B already
	// ran this sweep: a cluster with no TLS Secrets is a valid (empty)
	// census and must not trigger a second full Secret list every 15m.
	if !a.liveRunSecretSet {
		secrets, err = a.collectTLSSecretMeta(ctx)
		if err != nil {
			return fmt.Errorf("live socket audit secrets: %w", err)
		}
	}
	if len(secrets) == 0 {
		prune()
		return nil
	}

	knownTLSSvcs, err := a.collectReferencedTLSServices(ctx)
	if err != nil {
		return fmt.Errorf("live socket audit references: %w", err)
	}

	// Stream the pod census page-by-page and retain only Ready pods that
	// mount a TLS Secret. A cluster-wide ListAll here used to pull every
	// Pod body (with all container/env/detail) into the operator's heap
	// every 15m — the filtered map is the only thing the target builder
	// needs.
	podsByNSName := map[string]*corev1.Pod{}
	podsByNS := map[string][]*corev1.Pod{}
	err = kube.ListEach(ctx, metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.Pods(a.cs, metav1.NamespaceAll), func(page []corev1.Pod) error {
			for i := range page {
				// &page[i] would pin the whole ~500-Pod page (with every
				// container/env payload) for the rest of the sweep. Keep a
				// lean copy of just the Pod we retain and drop ManagedFields
				// — the bulky field this audit never reads — so each page is
				// collectable as soon as the callback returns.
				cp := page[i]
				cp.ManagedFields = nil
				p := &cp
				if p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning ||
					!kube.PodReadyCond(p) || !podMountsTLSSecret(p, secrets) {
					continue
				}
				podsByNSName[p.Namespace+"/"+p.Name] = p
				podsByNS[p.Namespace] = append(podsByNS[p.Namespace], p)
			}
			return nil
		})
	if err != nil {
		return fmt.Errorf("live socket audit pods: %w", err)
	}

	slices, err := kube.ListAll(ctx, metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.EndpointSlices(a.cs, metav1.NamespaceAll))
	if err != nil {
		return fmt.Errorf("live socket audit endpointslices: %w", err)
	}
	epBySvc := buildReadyEndpointsMap(slices)

	svcs, err := kube.ListAll(ctx, metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.Services(a.cs, metav1.NamespaceAll))
	if err != nil {
		return fmt.Errorf("live socket audit services: %w", err)
	}

	var targets []liveProbeTarget
	for i := range svcs {
		svc := &svcs[i]
		if target, ok := buildProbeTarget(svc, knownTLSSvcs, secrets, podsByNSName, podsByNS, epBySvc); ok {
			targets = append(targets, target)
		}
	}
	if len(targets) == 0 {
		prune()
		return nil
	}

	prober := a.prober
	if prober == nil {
		prober = defaultLiveCertProber
	}
	runProbePool(ctx, prober, targets)
	if err := ctx.Err(); err != nil {
		return err
	}

	rolledWorkloads := map[string]bool{}
	for i := range targets {
		t := &targets[i]
		if t.probeErr != nil || t.servedCert == nil || t.servedCert.SerialNumber == nil {
			continue
		}
		servedSerial := t.servedCert.SerialNumber.Text(16)
		// A Pod may mount several TLS Secrets (webhook + metrics +
		// management). The socket serving one of them is in sync even
		// when it is not the SAN-matched Secret for this port — paging
		// a restart on the SAN match alone would bounce a healthy pod
		// every 2h. Only an unknown serial is drift.
		if anyMountedSecretServesSerial(t.secrets, servedSerial) {
			continue
		}
		// The socket serves a serial no mounted Secret holds. Identify the
		// port's Secret from the served certificate's Subject/SAN rather
		// than a blind mounted[0]: a same-name cert with a new serial is
		// real drift (Secret rotated, Pod still serves the old one).
		if servedSecret, ok := matchServedSecret(t.secrets, t.servedCert); ok {
			t.secret = servedSecret
		} else if !t.isKnownRef {
			// A TLS-port-only Service with no mounted Secret bearing the
			// served identity gives no proof a mounted Secret serves this
			// port — e.g. the Pod mounts a client mTLS Secret for an
			// unrelated upstream. Never page/restart it on a guess.
			continue
		}
		if !t.secret.creationTime.IsZero() && now.Sub(t.secret.creationTime) < liveSecretStableMinAge {
			continue
		}
		streakKey := t.svc.Namespace + "/" + t.svc.Name + "/" + t.secret.name
		seenStreaks[streakKey] = true
		if a.liveDriftStreak.Hit(streakKey) < liveDriftConfirmScans {
			continue
		}
		mk := liveDriftMetricKey{namespace: t.svc.Namespace, service: t.svc.Name, secret: t.secret.name}
		a.seenLiveDrift.Set(metrics.TLSLiveSocketDrift, 1, mk, t.svc.Namespace, t.svc.Name, t.secret.name)
		a.emitLiveDriftEvent(ctx, t, servedSerial, now)

		if a.disableLiveRollout {
			continue
		}
		remaining := t.servedCert.NotAfter.Sub(now)
		if remaining >= liveDriftExpiryThreshold || !t.secret.notAfter.After(t.servedCert.NotAfter) {
			continue
		}
		a.maybeRolloutWorkload(ctx, log, t, rolledWorkloads, now)
	}
	prune()
	return nil
}

func (a *certDriftAuditor) collectTLSSecretMeta(ctx context.Context) (map[secretMetricKey]tlsSecretMeta, error) {
	out := map[secretMetricKey]tlsSecretMeta{}
	err := kube.ListEach(ctx, metav1.ListOptions{
		FieldSelector: "type=kubernetes.io/tls",
		Limit:         kube.DefaultListPageSize,
	}, kube.Secrets(a.cs, metav1.NamespaceAll), func(items []corev1.Secret) error {
		for i := range items {
			s := &items[i]
			if s.Type != corev1.SecretTypeTLS {
				continue
			}
			block, _ := pem.Decode(s.Data["tls.crt"])
			if block == nil {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil || cert.SerialNumber == nil {
				continue
			}
			dnsName := ""
			if len(cert.DNSNames) > 0 {
				dnsName = cert.DNSNames[0]
			}
			out[secretMetricKey{s.Namespace, s.Name}] = tlsSecretMeta{
				name:         s.Name,
				serialHex:    cert.SerialNumber.Text(16),
				notAfter:     cert.NotAfter,
				creationTime: s.CreationTimestamp.Time,
				dnsName:      dnsName,
				dnsNames:     append([]string(nil), cert.DNSNames...),
				ipNames:      certIPStrings(cert.IPAddresses),
				commonName:   cert.Subject.CommonName,
			}
		}
		return nil
	})
	if err == nil {
		a.liveRunSecretMeta = out
		a.liveRunSecretSet = true
	}
	return out, err
}

// cachedTLSSecretMeta returns the TLS-Secret census Check B built this
// sweep. run() orders auditTLSSecrets before auditLiveSockets, so the
// live-socket audit reuses it instead of listing all TLS Secrets a
// second time. Unit tests that drive auditLiveSockets directly see an
// empty cache and fall back to their own list.
func (a *certDriftAuditor) cachedTLSSecretMeta() map[secretMetricKey]tlsSecretMeta {
	if !a.liveRunSecretSet {
		return nil
	}
	return a.liveRunSecretMeta
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

func runProbePool(ctx context.Context, prober liveCertProber, targets []liveProbeTarget) {
	var next atomic.Int64
	workers := min(liveProbeWorkers, len(targets))
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for {
				idx := int(next.Add(1) - 1)
				if idx >= len(targets) {
					return
				}
				t := &targets[idx]
				addr := net.JoinHostPort(t.ip, strconv.Itoa(int(t.port)))
				t.servedCert, t.probeErr = prober(ctx, addr, t.serverName)
			}
		}()
	}
	wg.Wait()
}

func (a *certDriftAuditor) emitLiveDriftEvent(ctx context.Context, t *liveProbeTarget, servedSerial string, now time.Time) {
	key := t.svc.Namespace + "/" + t.svc.Name + "/" + t.secret.name
	if a.liveDriftEventSent.CooledDown(key, liveDriftEventCooldown, now) {
		return
	}
	note := fmt.Sprintf(
		"Service %s/%s serves TLS cert serial=%s (expires %s) which differs from Secret %s/%s serial=%s (expires %s)",
		t.svc.Namespace, t.svc.Name, servedSerial, t.servedCert.NotAfter.Format(time.RFC3339),
		t.svc.Namespace, t.secret.name, t.secret.serialHex, t.secret.notAfter.Format(time.RFC3339))
	if err := kube.EmitWarningEvent(ctx, a.cs, kube.WarningEvent{
		Namespace: t.svc.Namespace,
		Name:      fmt.Sprintf("%s.live-tls-drift.%d", t.svc.Name, now.Unix()),
		Reason:    "TLSLiveSocketDrift",
		Note:      note,
		Regarding: corev1.ObjectReference{
			Kind:       "Service",
			APIVersion: "v1",
			Namespace:  t.svc.Namespace,
			Name:       t.svc.Name,
			UID:        t.svc.UID,
		},
		ReportingInstance: a.queue,
		Now:               now,
	}); err == nil {
		a.liveDriftEventSent.Stamp(key, now)
	}
}

func (a *certDriftAuditor) maybeRolloutWorkload(ctx context.Context, log interface {
	Info(string, ...any)
	Error(error, string, ...any)
}, t *liveProbeTarget, rolled map[string]bool, now time.Time) {
	ns := t.svc.Namespace
	if liveDriftSystemNamespaces[ns] {
		return
	}
	kind, name, ok := a.resolveOwnerWorkload(ctx, t.pod)
	if !ok {
		return
	}
	wKey := ns + "/" + kind + "/" + name
	if rolled[wKey] {
		return
	}

	var obj metav1.Object
	var tplLabels map[string]string
	var fluxKind string
	var patchFn func(context.Context, []byte) error

	switch kind {
	case "Deployment":
		dep, err := a.cs.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			metrics.IncError(a.queue)
			return
		}
		if kube.EffectiveAnnos(ctx, dep)[kube.AnnoCertDriftReloadOptOut] == "true" {
			return
		}
		obj = dep
		tplLabels = dep.Spec.Template.Labels
		fluxKind = "deployment"
		patchFn = func(c context.Context, data []byte) error {
			_, err := a.cs.AppsV1().Deployments(ns).Patch(c, name, types.StrategicMergePatchType, data, metav1.PatchOptions{})
			return err
		}
	case "DaemonSet":
		ds, err := a.cs.AppsV1().DaemonSets(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			metrics.IncError(a.queue)
			return
		}
		if kube.EffectiveAnnos(ctx, ds)[kube.AnnoCertDriftReloadOptOut] == "true" {
			return
		}
		obj = ds
		tplLabels = ds.Spec.Template.Labels
		fluxKind = "daemonset"
		patchFn = func(c context.Context, data []byte) error {
			_, err := a.cs.AppsV1().DaemonSets(ns).Patch(c, name, types.StrategicMergePatchType, data, metav1.PatchOptions{})
			return err
		}
	case "StatefulSet":
		sts, err := a.cs.AppsV1().StatefulSets(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			metrics.IncError(a.queue)
			return
		}
		if kube.EffectiveAnnos(ctx, sts)[kube.AnnoCertDriftReloadOptIn] != "true" {
			return
		}
		obj = sts
		tplLabels = sts.Spec.Template.Labels
		fluxKind = "statefulset"
		patchFn = func(c context.Context, data []byte) error {
			_, err := a.cs.AppsV1().StatefulSets(ns).Patch(c, name, types.StrategicMergePatchType, data, metav1.PatchOptions{})
			return err
		}
	default:
		return
	}

	for _, lk := range liveDriftDBQuorumLabels {
		if tplLabels[lk] != "" {
			return
		}
	}

	lgr := logf.FromContext(ctx)
	proceed, unverifiable := heal.AllowedVPersisted(ctx, lgr, a.verdict, a.cs, a.dyn,
		&a.liveDriftRolloutHeals, obj, kube.AnnoLastCertDriftRollout, wKey,
		liveDriftRolloutCooldown, now)
	if !proceed {
		if unverifiable {
			metrics.IncError(a.queue)
		}
		return
	}
	if !heal.FluxPatchGate(fluxKind, obj, "live-socket-audit:"+wKey, now) {
		heal.RefundGrant(now)
		return
	}
	if !kube.TryReserveWorkloadKey(ctx, wKey) {
		heal.RefundGrant(now)
		return
	}
	if err := patchFn(ctx, kube.RestartTemplatePatch(now)); err != nil {
		kube.ReleaseWorkloadKey(ctx, wKey)
		if apierrors.IsNotFound(err) {
			heal.RefundGrant(now)
			log.Info("skip tls live-socket drift rollout: workload vanished mid-patch — grant refunded",
				"workload", wKey, "secret", t.secret.name)
			return
		}
		metrics.IncError(a.queue)
		log.Error(err, "tls live-socket drift rollout failed", "workload", wKey, "secret", t.secret.name)
		return
	}
	rolled[wKey] = true
	a.liveDriftRolloutHeals.Stamp(wKey, now)
	log.Info("ACTION: restarted workload due to stale live TLS certificate near expiry",
		"workload", wKey, "service", t.svc.Namespace+"/"+t.svc.Name, "secret", t.secret.name)
	if err := heal.StampPersisted(ctx, obj, patchFn, kube.AnnoLastCertDriftRollout,
		&a.liveDriftRolloutHeals, wKey, now); err != nil {
		metrics.IncError(a.queue)
		log.Error(err, "tls live-socket drift persisted cooldown stamp failed", "workload", wKey)
	}
}

func (a *certDriftAuditor) resolveOwnerWorkload(ctx context.Context, pod *corev1.Pod) (kind, name string, ok bool) {
	for i := range pod.OwnerReferences {
		ref := &pod.OwnerReferences[i]
		if ref.Controller == nil || !*ref.Controller {
			continue
		}
		switch ref.Kind {
		case "DaemonSet", "StatefulSet":
			return ref.Kind, ref.Name, true
		case "ReplicaSet":
			rs, err := a.cs.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
			if err != nil {
				return "", "", false
			}
			for j := range rs.OwnerReferences {
				r := &rs.OwnerReferences[j]
				if r.Controller != nil && *r.Controller && r.Kind == "Deployment" {
					return "Deployment", r.Name, true
				}
			}
		}
	}
	return "", "", false
}

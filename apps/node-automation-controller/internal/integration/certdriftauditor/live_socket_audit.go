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

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
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
	dnsName      string
}

type liveProbeTarget struct {
	svc        corev1.Service
	pod        *corev1.Pod
	ip         string
	port       int32
	serverName string
	secret     tlsSecretMeta
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
}

var liveDriftDBQuorumLabels = []string{
	"cnpg.io/cluster",
	"postgres-operator.crunchydata.com/cluster",
	"pgv2.percona.com/cluster",
	"everest.percona.com/cluster",
	"scylla.scylladb.com/cluster",
	"apps.rabbitmq.com/cluster",
}

func defaultLiveCertProber(ctx context.Context, addr, serverName string) (*x509.Certificate, error) {
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: liveProbeTimeout},
		Config: &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true, // serial comparison only — endpoint IP may lack SAN
		},
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
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
	defer func() {
		a.liveDriftStreak.Prune(func(k string) bool { return seenStreaks[k] })
		a.seenLiveDrift.Prune(metrics.TLSLiveSocketDrift.DeleteLabelValues)
	}()

	secrets, err := a.collectTLSSecretMeta(ctx)
	if err != nil {
		return fmt.Errorf("live socket audit secrets: %w", err)
	}
	if len(secrets) == 0 {
		return nil
	}

	knownTLSSvcs, err := a.collectReferencedTLSServices(ctx)
	if err != nil {
		return fmt.Errorf("live socket audit references: %w", err)
	}

	pods, err := kube.ListAll(ctx, metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.Pods(a.cs, metav1.NamespaceAll))
	if err != nil {
		return fmt.Errorf("live socket audit pods: %w", err)
	}
	podsByNSName := make(map[string]*corev1.Pod, len(pods))
	podsByNS := map[string][]*corev1.Pod{}
	for i := range pods {
		p := &pods[i]
		podsByNSName[p.Namespace+"/"+p.Name] = p
		if p.DeletionTimestamp == nil && p.Status.Phase == corev1.PodRunning && kube.PodReadyCond(p) {
			podsByNS[p.Namespace] = append(podsByNS[p.Namespace], p)
		}
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
		return nil
	}

	prober := a.prober
	if prober == nil {
		prober = defaultLiveCertProber
	}
	runProbePool(ctx, prober, targets)

	rolledWorkloads := map[string]bool{}
	for i := range targets {
		t := &targets[i]
		if t.probeErr != nil || t.servedCert == nil || t.servedCert.SerialNumber == nil {
			continue
		}
		servedSerial := t.servedCert.SerialNumber.Text(16)
		if servedSerial == t.secret.serialHex {
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
			}
		}
		return nil
	})
	return out, err
}

func (a *certDriftAuditor) collectReferencedTLSServices(ctx context.Context) (map[string]bool, error) {
	refs := map[string]bool{}
	opts := metav1.ListOptions{Limit: kube.DefaultListPageSize}

	mwcs, err := kube.ListAll(ctx, opts, kube.MutatingWebhookConfigurations(a.cs))
	if err != nil {
		return nil, err
	}
	for i := range mwcs {
		for j := range mwcs[i].Webhooks {
			if svc := mwcs[i].Webhooks[j].ClientConfig.Service; svc != nil && svc.Namespace != "" && svc.Name != "" {
				refs[svc.Namespace+"/"+svc.Name] = true
			}
		}
	}

	vwcs, err := kube.ListAll(ctx, opts, kube.ValidatingWebhookConfigurations(a.cs))
	if err != nil {
		return nil, err
	}
	for i := range vwcs {
		for j := range vwcs[i].Webhooks {
			if svc := vwcs[i].Webhooks[j].ClientConfig.Service; svc != nil && svc.Namespace != "" && svc.Name != "" {
				refs[svc.Namespace+"/"+svc.Name] = true
			}
		}
	}

	ings, err := kube.ListAll(ctx, opts, func(c context.Context, lo metav1.ListOptions) ([]networkingv1.Ingress, string, error) {
		l, listErr := a.cs.NetworkingV1().Ingresses(metav1.NamespaceAll).List(c, lo)
		if listErr != nil {
			return nil, "", listErr
		}
		return l.Items, l.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	for i := range ings {
		collectIngressTLSServices(&ings[i], refs)
	}

	if a.dyn != nil {
		for _, src := range []struct {
			collect func(*unstructured.Unstructured, map[string]bool)
			fn      kube.PageFunc[unstructured.Unstructured]
		}{
			{
				collect: collectCRDConversionService,
				fn:      kube.DynamicPage(a.dyn.Resource(kube.GVRCustomResourceDefinition)),
			},
			{
				collect: collectAPIServiceRef,
				fn:      kube.DynamicPage(a.dyn.Resource(kube.GVRAPIService)),
			},
			{
				collect: collectHTTPRouteServices,
				fn:      kube.DynamicPage(a.dyn.Resource(kube.GVRHTTPRoute)),
			},
		} {
			listErr := kube.ListEach(ctx, opts, src.fn, func(page []unstructured.Unstructured) error {
				for i := range page {
					src.collect(&page[i], refs)
				}
				return nil
			})
			if listErr != nil && !kube.IsCRDAbsent(listErr) {
				return nil, listErr
			}
		}
	}
	return refs, nil
}

func collectIngressTLSServices(ing *networkingv1.Ingress, refs map[string]bool) {
	if len(ing.Spec.TLS) == 0 {
		return
	}
	if ing.Spec.DefaultBackend != nil && ing.Spec.DefaultBackend.Service != nil {
		if name := ing.Spec.DefaultBackend.Service.Name; name != "" {
			refs[ing.Namespace+"/"+name] = true
		}
	}
	for i := range ing.Spec.Rules {
		http := ing.Spec.Rules[i].HTTP
		if http == nil {
			continue
		}
		for j := range http.Paths {
			if http.Paths[j].Backend.Service != nil && http.Paths[j].Backend.Service.Name != "" {
				refs[ing.Namespace+"/"+http.Paths[j].Backend.Service.Name] = true
			}
		}
	}
}

func collectCRDConversionService(u *unstructured.Unstructured, refs map[string]bool) {
	strategy, _ := kube.NestedString(u.Object, "spec", "conversion", "strategy")
	if strategy != "Webhook" {
		return
	}
	ns, _ := kube.NestedString(u.Object, "spec", "conversion", "webhook", "clientConfig", "service", "namespace")
	name, _ := kube.NestedString(u.Object, "spec", "conversion", "webhook", "clientConfig", "service", "name")
	if ns != "" && name != "" {
		refs[ns+"/"+name] = true
	}
}

func collectAPIServiceRef(u *unstructured.Unstructured, refs map[string]bool) {
	ns, _ := kube.NestedString(u.Object, "spec", "service", "namespace")
	name, _ := kube.NestedString(u.Object, "spec", "service", "name")
	if ns != "" && name != "" {
		refs[ns+"/"+name] = true
	}
}

func collectHTTPRouteServices(u *unstructured.Unstructured, refs map[string]bool) {
	rules, found, _ := unstructured.NestedSlice(u.Object, "spec", "rules")
	if !found {
		return
	}
	defaultNS := u.GetNamespace()
	for _, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		brefs, _ := rm["backendRefs"].([]any)
		for _, b := range brefs {
			bm, ok := b.(map[string]any)
			if !ok {
				continue
			}
			kind, _ := bm["kind"].(string)
			if kind != "" && kind != "Service" {
				continue
			}
			name, _ := bm["name"].(string)
			if name == "" {
				continue
			}
			ns, _ := bm["namespace"].(string)
			if ns == "" {
				ns = defaultNS
			}
			if ns != "" {
				refs[ns+"/"+name] = true
			}
		}
	}
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

func buildProbeTarget(svc *corev1.Service, knownTLSSvcs map[string]bool,
	secrets map[secretMetricKey]tlsSecretMeta, podsByNSName map[string]*corev1.Pod,
	podsByNS map[string][]*corev1.Pod, epBySvc map[string][]endpointAddr) (liveProbeTarget, bool) {

	if svc.Spec.Type == corev1.ServiceTypeExternalName || len(svc.Spec.Ports) == 0 {
		return liveProbeTarget{}, false
	}
	svcKey := svc.Namespace + "/" + svc.Name
	isKnownRef := knownTLSSvcs[svcKey]

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

	secret, hasSecret := firstMountedTLSSecret(matchedPod, secrets)
	if !hasSecret {
		return liveProbeTarget{}, false
	}

	port, isTLSPort := resolveServiceTLSPort(svc, matchedPod)
	if !isKnownRef && !isTLSPort {
		return liveProbeTarget{}, false
	}
	if port <= 0 {
		port = svc.Spec.Ports[0].Port
		if svc.Spec.Ports[0].TargetPort.Type == intstr.Int && svc.Spec.Ports[0].TargetPort.IntVal > 0 {
			port = svc.Spec.Ports[0].TargetPort.IntVal
		}
	}
	serverName := secret.dnsName
	if serverName == "" {
		serverName = svc.Name + "." + svc.Namespace + ".svc"
	}
	return liveProbeTarget{
		svc:        *svc,
		pod:        matchedPod,
		ip:         ip,
		port:       port,
		serverName: serverName,
		secret:     secret,
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

func firstMountedTLSSecret(pod *corev1.Pod, secrets map[secretMetricKey]tlsSecretMeta) (tlsSecretMeta, bool) {
	for i := range pod.Spec.Volumes {
		v := &pod.Spec.Volumes[i]
		if v.Secret != nil {
			if meta, ok := secrets[secretMetricKey{pod.Namespace, v.Secret.SecretName}]; ok {
				return meta, true
			}
		}
		if v.Projected != nil {
			for j := range v.Projected.Sources {
				src := &v.Projected.Sources[j]
				if src.Secret != nil {
					if meta, ok := secrets[secretMetricKey{pod.Namespace, src.Secret.Name}]; ok {
						return meta, true
					}
				}
			}
		}
	}
	return tlsSecretMeta{}, false
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
			for j := range pod.Spec.Containers[i].Ports {
				if pod.Spec.Containers[i].Ports[j].Name == sp.TargetPort.StrVal {
					return pod.Spec.Containers[i].Ports[j].ContainerPort
				}
			}
		}
	}
	return sp.Port
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
		if dep.Annotations[kube.AnnoCertDriftReloadOptOut] == "true" {
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
		if ds.Annotations[kube.AnnoCertDriftReloadOptOut] == "true" {
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
		if sts.Annotations[kube.AnnoCertDriftReloadOptIn] != "true" {
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
	if !kube.TryReserveWorkloadKey(ctx, wKey) ||
		!heal.FluxPatchGate(fluxKind, obj, ns+"/"+name, now) {
		heal.RefundGrant(now)
		return
	}
	if err := patchFn(ctx, kube.RestartTemplatePatch(now)); err != nil {
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

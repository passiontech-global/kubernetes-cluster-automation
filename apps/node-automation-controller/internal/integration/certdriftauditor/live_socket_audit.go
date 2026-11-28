// live_socket_audit.go — Live-Socket vs Secret X.509 Certificate Drift
// Healer (#5): probes Ready Service endpoints for 4 TLS service classes
// (Webhook/CRD conversion Services, APIService Services, TLS Ingress/Gateway
// Services, and Services whose Ready Pods mount a kubernetes.io/tls Secret on
// ports 443/8443/9443 or named https/tls/webhook), compares the served X.509
// serial against the mounted Secret's tls.crt across >=2 consecutive scans,
// exports node_automation_tls_live_socket_drift + Warning Event, and performs
// guarded rollout restarts when the served cert is expired or <7d from expiry
// while the Secret holds a newer cert.
//
// Companion files: live_socket_targets.go (TLS service/endpoint/Secret
// attribution) and live_socket_rollout.go (guarded workload restart).
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
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
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

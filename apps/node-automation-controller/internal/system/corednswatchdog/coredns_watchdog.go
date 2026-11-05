// coredns-stale-watchdog — port of hooks/40-coredns-stale-watchdog.sh.
//
// Detects the CoreDNS "stale watch" failure (incident 2026-09-25):
// after a long konnectivity->apiserver outage the pod SA token expires
// before renewal, the kubernetes-plugin informer dies with
// `Failed to watch: ... Unauthorized` while the process keeps serving
// a FROZEN cache — records created/changed after that return NODATA.
// Per-replica detection in 3 layers (detection writes nothing to the
// apiserver):
//
//  1. log fast-path: grep the informer/reflector death signature in
//     the last 10m of logs — instant catch, no false positives.
//  2. active freshness query: pick a Service <10m old with a ready
//     EndpointSlice (its delta certainly crossed a healthy watch) and
//     resolve <svc>.<ns>.svc.cluster.local directly against each pod's
//     podIP. Two consecutive failed runs (streak) = stale. If NO pod
//     answers at all the layer aborts without bumping streaks — the
//     probe path itself is broken, not the fleet.
//  3. metrics :9153: coredns_panics_total > 0 = plugin panic.
//
// Recovery deletes only the stale pods by name; falls back to a full
// rollout restart when the entire fleet is stale. 30m cooldown via an
// annotation on the Deployment object (does NOT trigger a rollout),
// plus storm-gate (NotReady nodes) and rollout-in-progress skips.
package corednswatchdog

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

const (
	corednsNS          = "kube-system"
	corednsPodSelector = "k8s-app=kube-dns"
	corednsLogSinceS   = 600 // layer-1 log window / layer-2 max service age
	corednsCooldownS   = 1800
	corednsStreakMax   = 2 // consecutive flagged runs before action
	corednsTSAnno      = "node-ops.passiontech.dev/last-coredns-restart"
	corednsMaxLogBytes = 256 * 1024
)

// corednsLogRE is the dead-informer signature — the exact bash
// alternation. Healthy pods only log a few INFO lines at boot.
var corednsLogRE = regexp.MustCompile(
	`Failed to watch|failed to watch|Failed to list|failed to list|Unauthorized|reflector`)

type coreDNSWatchdog struct {
	cs   kubernetes.Interface
	http *http.Client
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue string
	mu    sync.Mutex
	// streak replaces the bash /tmp/coredns-streak-* files: pod ->
	// consecutive layer-2 failures. Resets on operator restart,
	// biasing conservative like the old tmpfs files did.
	streak map[string]int
	// Probe seams: the real implementations are the logHit/dnsProbe/
	// panics methods below — fields so tests can stub log-stream,
	// UDP:53 and :9153 access that the fake clientset cannot reach.
	logHitFn func(ctx context.Context, pod string) string
	// dnsFn resolves fqdn through one coredns pod and returns the
	// A-record IPs it answered — the W8-NM5 fallback verifies them
	// against the live EndpointSlice/ClusterIP instead of accepting
	// any answer as "fresh". nil → dnsProbe.
	dnsFn    func(ctx context.Context, podIP, fqdn string) ([]string, error)
	panicsFn func(ctx context.Context, podIP string) (float64, bool)
}

func Setup(d shared.Deps) error {
	w := &coreDNSWatchdog{
		cs:     d.CS,
		http:   &http.Client{Timeout: 5 * time.Second},
		queue:  d.Name,
		streak: map[string]int{},
	}
	w.logHitFn = w.logHit
	w.dnsFn = w.dnsProbe
	w.panicsFn = w.panics
	return shared.AddPeriodic(d.Mgr, w.queue, time.Minute, w.run)
}

func (w *coreDNSWatchdog) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	w.mu.Lock()
	defer w.mu.Unlock()

	podList, err := w.cs.CoreV1().Pods(corednsNS).List(ctx,
		metav1.ListOptions{LabelSelector: corednsPodSelector})
	if err != nil {
		// Inconclusive — the next minute's run re-evaluates; returning
		// nil avoids an error/retry hot loop on API flaps.
		log.Info("ABORT: cannot list coredns pods (API flap) — inconclusive", "error", err)
		return nil
	}
	podIP := map[string]string{}
	for _, p := range podList.Items {
		podIP[p.Name] = p.Status.PodIP
	}
	// Only name->IP feeds the layers below — release the full PodList
	// before the log streams, EndpointSlice lists and DNS probes run.
	podList = nil
	// Prune streaks of pods that vanished (recreates change names).
	for name := range w.streak {
		if _, ok := podIP[name]; !ok {
			delete(w.streak, name)
		}
	}
	stale := map[string]bool{}

	// ===== Layer 1: log fast-path =====
	for name := range podIP {
		if hit := w.logHitFn(ctx, name); hit != "" {
			stale[name] = true
			w.streak[name] = corednsStreakMax
			log.Info("log: STALE — informer death signature", "pod", name, "match", hit)
		}
	}

	// ===== Layer 2: active freshness query =====
	fqdn, wantIPs := w.probeFQDN(ctx)
	if fqdn == "" {
		log.Info("dns: skip layer 2 — no service <10m old and no usable endpointslice (inconclusive)")
	} else {
		log.Info("dns: probing each coredns pod", "fqdn", fqdn, "wantIPs", len(wantIPs))
		answered := 0
		var failed []string
		for name, ip := range podIP {
			if stale[name] {
				continue
			}
			if ip == "" {
				log.Info("dns: no podIP — skipping layer 2", "pod", name)
				continue
			}
			if ips, err := w.dnsFn(ctx, ip, fqdn); err == nil && dnsAnswerFresh(ips, wantIPs) {
				answered++
				delete(w.streak, name)
				log.Info("dns: fresh", "pod", name, "answers", len(ips))
			} else {
				failed = append(failed, name)
			}
		}
		if answered == 0 && len(failed) > 0 {
			// Every probe failed — our path to podIPs is likely broken
			// (CNI partition, netpol). Do NOT bump streaks: flagging
			// the whole fleet would restart healthy coredns while the
			// probe path itself is severed.
			log.Info("dns: ABORT layer 2 — no pod answered, probe path to podIP likely broken (inconclusive)")
		} else {
			for _, name := range failed {
				s := w.streak[name] + 1
				w.streak[name] = s
				if s >= corednsStreakMax {
					stale[name] = true
					log.Info("dns: STALE — cannot resolve probe fqdn",
						"pod", name, "fqdn", fqdn, "streak", s)
				} else {
					log.Info("dns: suspect — cannot resolve probe fqdn",
						"pod", name, "fqdn", fqdn, "streak", s, "max", corednsStreakMax)
				}
			}
		}
	}

	// ===== Layer 3: metrics :9153 per pod =====
	for name, ip := range podIP {
		if ip == "" || stale[name] {
			continue
		}
		panics, ok := w.panicsFn(ctx, ip)
		if !ok {
			log.Info("metrics: UNKNOWN — cannot fetch :9153/metrics", "pod", name)
			continue
		}
		if panics > 0 {
			stale[name] = true
			w.streak[name] = corednsStreakMax
			log.Info("metrics: STALE — coredns_panics_total>0", "pod", name, "panics", panics)
		}
	}

	if len(stale) == 0 {
		log.Info("sweep done: coredns fresh", "replicas", len(podIP))
		return nil
	}
	suspects := make([]string, 0, len(stale))
	for name := range stale {
		suspects = append(suspects, name)
	}
	sort.Strings(suspects)
	log.Info("STALE coredns replicas — dead watch or panic",
		"stale", len(suspects), "total", len(podIP), "pods", suspects)
	return w.recover(ctx, suspects, len(podIP))
}

// recover applies cooldown/storm-gate/rollout gates, then either
// rollout-restarts the Deployment (whole fleet stale) or deletes only
// the stale pods, and stamps the cooldown annotation. Hard API
// failures are returned so the wrapper counts them.
func (w *coreDNSWatchdog) recover(ctx context.Context, suspects []string, nPods int) error {
	log := logf.FromContext(ctx)
	deploy, err := w.cs.AppsV1().Deployments(corednsNS).Get(ctx, "coredns", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get deployment %s/coredns: %w", corednsNS, err)
	}
	// Cooldown lives on Deployment metadata — patching it does not
	// roll the pods (unlike a pod-template annotation).
	if last, ok := deploy.Annotations[corednsTSAnno]; ok {
		if ts, err := strconv.ParseInt(last, 10, 64); err == nil {
			if ago := time.Now().Unix() - ts; ago < corednsCooldownS {
				metrics.IncError(w.queue)
				log.Info("SKIP recovery: inside cooldown",
					"pods", suspects, "agoS", ago, "cooldownS", corednsCooldownS)
				return nil
			}
		}
	}
	// Storm-gate: never evict while nodes are NotReady — eviction
	// only slows recovery during a cluster storm.
	notReady, err := shared.CountNotReadyNodes(ctx, w.cs)
	if err != nil {
		return fmt.Errorf("count not-ready nodes (storm gate): %w", err)
	}
	if notReady > 0 {
		metrics.IncError(w.queue)
		log.Info("SKIP recovery: nodes NotReady — cluster storm",
			"pods", suspects, "notReady", notReady)
		return nil
	}
	// Fleet not fully ready = a rollout is already recreating pods.
	if deploy.Status.ReadyReplicas < deploy.Status.Replicas {
		metrics.IncError(w.queue)
		log.Info("SKIP recovery: coredns not fully ready",
			"pods", suspects,
			"ready", deploy.Status.ReadyReplicas, "replicas", deploy.Status.Replicas)
		return nil
	}

	if nPods == 0 || len(suspects) >= nPods {
		// Whole fleet stale (or empty pod list) — restart the
		// Deployment once; a short outage beats stale answers.
		log.Info("ACTION: rollout restart deploy/coredns",
			"suspects", len(suspects), "total", nPods)
		patch, err := json.Marshal(map[string]any{
			"spec": map[string]any{
				"template": map[string]any{
					"metadata": map[string]any{
						"annotations": map[string]string{
							"kubectl.kubernetes.io/restartedAt": time.Now().UTC().Format(time.RFC3339),
						},
					},
				},
			},
		})
		if err != nil {
			return err
		}
		if _, err := w.cs.AppsV1().Deployments(corednsNS).Patch(ctx, "coredns",
			types.StrategicMergePatchType, patch, metav1.PatchOptions{}); err != nil {
			return fmt.Errorf("rollout-restart patch deployment %s/coredns: %w", corednsNS, err)
		}
	} else {
		// Delete only the stale pods — healthy replicas keep serving.
		log.Info("ACTION: delete stale pods", "pods", suspects)
		for _, name := range suspects {
			if err := w.cs.CoreV1().Pods(corednsNS).Delete(ctx, name,
				metav1.DeleteOptions{}); err != nil {
				return fmt.Errorf("delete stale pod %s/%s: %w", corednsNS, name, err)
			}
		}
	}
	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]string{
				corednsTSAnno: strconv.FormatInt(time.Now().Unix(), 10),
			},
		},
	})
	if err != nil {
		return err
	}
	_, err = w.cs.AppsV1().Deployments(corednsNS).Patch(ctx, "coredns",
		types.MergePatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("stamp cooldown annotation on deployment %s/coredns: %w", corednsNS, err)
	}
	log.Info("sweep done: stale coredns recovery issued", "pods", suspects)
	return nil
}

// logHit returns the first last-10m log line matching the informer
// death signature ("" = clean/unreadable). Bounded to 8s / 256KiB.
// A stream/read failure is inconclusive, not clean — logged so a
// broken pod-log path (RBAC, API flap) cannot silently disable
// layer 1 while layers 2/3 keep reporting "fresh".
func (w *coreDNSWatchdog) logHit(ctx context.Context, pod string) string {
	log := logf.FromContext(ctx)
	lctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	since := int64(corednsLogSinceS)
	stream, err := w.cs.CoreV1().Pods(corednsNS).GetLogs(pod,
		&corev1.PodLogOptions{SinceSeconds: &since}).Stream(lctx)
	if err != nil {
		log.Info("log: cannot stream pod logs — layer 1 inconclusive", "pod", pod, "error", err)
		return ""
	}
	defer func() { _ = stream.Close() }()
	data, err := io.ReadAll(io.LimitReader(stream, corednsMaxLogBytes))
	if err != nil {
		log.Info("log: cannot read pod log stream — layer 1 inconclusive", "pod", pod, "error", err)
		return ""
	}
	for rest := string(data); rest != ""; {
		line, after, _ := strings.Cut(rest, "\n")
		rest = after
		if corednsLogRE.MatchString(line) {
			return line
		}
	}
	return ""
}

// probeFQDN picks the layer-2 probe target: the newest Service <10m
// old having an EndpointSlice with a ready endpoint — its delta
// certainly crossed a healthy watch — returning its
// <name>.<ns>.svc.cluster.local FQDN plus nil wantIPs (any answer
// proves freshness).
//
// W8-NM5 fallback: on a quiet cluster no Service is <10m old, so the
// old code skipped layer 2 entirely — exactly the steady-state where a
// frozen watch rots longest. The fallback picks the most-recently-
// CHANGED EndpointSlice (highest resourceVersion) that still carries a
// ready endpoint and resolves its owning Service: the want set is the
// Service's clusterIPs, or — for a headless service — the ready
// endpoint pod IPs. A pod answering with anything else is serving a
// frozen cache. Returns ("", nil) when nothing qualifies.
func (w *coreDNSWatchdog) probeFQDN(ctx context.Context) (string, map[string]bool) {
	log := logf.FromContext(ctx)
	// Page the cluster-wide Service list — an unbounded List forces
	// etcd to serialize every Service into one response; 500-per-page
	// keeps each request cheap at fleet scale.
	svcItems, err := shared.ListAll(ctx, metav1.ListOptions{Limit: 500},
		shared.Services(w.cs, metav1.NamespaceAll))
	if err != nil {
		log.Info("dns: cannot list services — layer 2 inconclusive", "error", err)
		return "", nil
	}
	sort.Slice(svcItems, func(i, j int) bool {
		return svcItems[i].CreationTimestamp.
			After(svcItems[j].CreationTimestamp.Time)
	})
	type svcCand struct {
		ns, name string
		created  time.Time
	}
	n := len(svcItems)
	if n > 8 { // bash: top-8 newest BEFORE the age filter
		n = 8
	}
	cands := make([]svcCand, 0, n)
	for i := 0; i < n; i++ {
		s := &svcItems[i]
		cands = append(cands, svcCand{
			ns:      s.Namespace,
			name:    s.Name,
			created: s.CreationTimestamp.Time,
		})
	}
	for _, svc := range cands {
		if time.Since(svc.created) >= corednsLogSinceS*time.Second {
			continue
		}
		eps, err := w.cs.DiscoveryV1().EndpointSlices(svc.ns).List(ctx,
			metav1.ListOptions{LabelSelector: "kubernetes.io/service-name=" + svc.name})
		if err != nil {
			log.Info("dns: cannot list endpointslices — skipping probe candidate",
				"service", svc.ns+"/"+svc.name, "error", err)
			continue
		}
		for _, es := range eps.Items {
			for _, ep := range es.Endpoints {
				// bash: conditions.ready == true — nil does NOT count.
				if ep.Conditions.Ready != nil && *ep.Conditions.Ready {
					return svc.name + "." + svc.ns + ".svc.cluster.local", nil
				}
			}
		}
	}
	svcItems = nil
	return w.probeFQDNFromSlices(ctx)
}

// probeFQDNFromSlices is the W8-NM5 fallback target: the
// most-recently-changed EndpointSlice (highest resourceVersion —
// slice objects carry no change timestamp, so the apiserver's RV is
// the recency proxy) with at least one ready endpoint. The answer set
// comes from the slice's Service: clusterIPs for a normal service,
// the ready endpoint pod IPs for a headless one.
func (w *coreDNSWatchdog) probeFQDNFromSlices(ctx context.Context) (string, map[string]bool) {
	log := logf.FromContext(ctx)
	var best *discoveryv1.EndpointSlice
	var bestRV int64
	err := shared.ListEach(ctx, metav1.ListOptions{Limit: 500},
		shared.EndpointSlices(w.cs, metav1.NamespaceAll),
		func(items []discoveryv1.EndpointSlice) error {
			for i := range items {
				es := &items[i]
				if es.Labels[discoveryv1.LabelServiceName] == "" {
					continue
				}
				ready := false
				for _, ep := range es.Endpoints {
					if ep.Conditions.Ready != nil && *ep.Conditions.Ready {
						ready = true
						break
					}
				}
				if !ready {
					continue
				}
				rv, err := strconv.ParseInt(es.ResourceVersion, 10, 64)
				if err != nil || rv <= bestRV {
					continue
				}
				best, bestRV = es, rv
			}
			return nil
		})
	if err != nil {
		log.Info("dns: cannot list endpointslices — fallback inconclusive", "error", err)
		return "", nil
	}
	if best == nil {
		return "", nil
	}
	ns, svcName := best.Namespace, best.Labels[discoveryv1.LabelServiceName]
	svc, err := w.cs.CoreV1().Services(ns).Get(ctx, svcName, metav1.GetOptions{})
	if err != nil {
		log.Info("dns: fallback slice's service unresolvable — inconclusive",
			"service", ns+"/"+svcName, "error", err)
		return "", nil
	}
	want := map[string]bool{}
	if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != corev1.ClusterIPNone {
		want[svc.Spec.ClusterIP] = true
		for _, ip := range svc.Spec.ClusterIPs {
			want[ip] = true
		}
	} else {
		// Headless: the A record IS the endpoint set.
		for _, ep := range best.Endpoints {
			if ep.Conditions.Ready == nil || !*ep.Conditions.Ready {
				continue
			}
			for _, a := range ep.Addresses {
				want[a] = true
			}
		}
	}
	if len(want) == 0 {
		return "", nil
	}
	return svcName + "." + ns + ".svc.cluster.local", want
}

// dnsAnswerFresh reports whether a coredns pod's answer proves its
// watch is alive: at least one A record, and — when the caller knows
// the expected answer set — every returned IP inside it. A stale
// replica either resolves NODATA (no records) or answers with IPs the
// EndpointSlice no longer carries.
func dnsAnswerFresh(ips []string, want map[string]bool) bool {
	if len(ips) == 0 {
		return false
	}
	if want == nil {
		return true
	}
	for _, ip := range ips {
		if !want[ip] {
			return false
		}
	}
	return true
}

// dnsProbe resolves fqdn directly through one coredns pod (UDP :53),
// equivalent to `nslookup <fqdn> <podIP>` — returning the A-record
// addresses it answered so the caller can diff them against the live
// endpoint set.
func (w *coreDNSWatchdog) dnsProbe(ctx context.Context, podIP, fqdn string) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", net.JoinHostPort(podIP, "53"))
		},
	}
	// Bound the whole lookup (dial timeout alone does not cover the
	// resolver's read/retries) — nslookup's default is ~5s.
	pctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	return r.LookupHost(pctx, fqdn)
}

// panics sums coredns_panics_total across label variants on the pod's
// :9153/metrics. ok=false = curl -sf equivalent (UNKNOWN).
func (w *coreDNSWatchdog) panics(ctx context.Context, podIP string) (float64, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://"+net.JoinHostPort(podIP, "9153")+"/metrics", nil)
	if err != nil {
		return 0, false
	}
	resp, err := w.http.Do(req)
	if err != nil {
		return 0, false
	}
	defer func() {
		// Drain before Close — an unread body makes the connection
		// unreusable, which silently defeats keep-alive on the
		// shared transport (same pattern as the apiserver endpoint
		// guard). Bounded to the same 4MiB as the scan so a
		// pathological body cannot pin the sweep either.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024*1024))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return 0, false
	}
	// Stream line-by-line instead of ReadAll+Split: the body can be
	// megabytes and only the panic counter matters, so materializing
	// it (4MiB []byte -> string -> thousands of substrings) every
	// minute per pod was pure heap churn. The 4MiB cap stays via
	// LimitReader.
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 4*1024*1024))
	// Metric lines are short, but one absurdly long line must not
	// silently truncate the scan (ErrTooLong reads as a failed
	// scrape below, which is the honest verdict anyway).
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var sum float64
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "coredns_panics_total") {
			continue
		}
		f := strings.Fields(line)
		if v, err := strconv.ParseFloat(f[len(f)-1], 64); err == nil {
			sum += v
		}
	}
	if err := sc.Err(); err != nil {
		return 0, false // same UNKNOWN verdict as a failed ReadAll
	}
	return sum, true
}

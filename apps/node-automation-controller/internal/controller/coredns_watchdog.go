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
package controller

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

const (
	corednsQueue       = "coredns-stale-watchdog"
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
	mu   sync.Mutex
	// streak replaces the bash /tmp/coredns-streak-* files: pod ->
	// consecutive layer-2 failures. Resets on operator restart,
	// biasing conservative like the old tmpfs files did.
	streak map[string]int
	// Probe seams: the real implementations are the logHit/dnsProbe/
	// panics methods below — fields so tests can stub log-stream,
	// UDP:53 and :9153 access that the fake clientset cannot reach.
	logHitFn func(ctx context.Context, pod string) string
	dnsFn    func(ctx context.Context, podIP, fqdn string) bool
	panicsFn func(ctx context.Context, podIP string) (float64, bool)
}

func SetupCoreDNSWatchdog(mgr ctrl.Manager, cs kubernetes.Interface) error {
	w := &coreDNSWatchdog{
		cs:     cs,
		http:   &http.Client{Timeout: 5 * time.Second},
		streak: map[string]int{},
	}
	w.logHitFn = w.logHit
	w.dnsFn = w.dnsProbe
	w.panicsFn = w.panics
	return addPeriodic(mgr, corednsQueue, time.Minute, w.run)
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
		log.Info("ABORT: cannot list coredns pods (API flap) — inconclusive")
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
	fqdn := w.probeFQDN(ctx)
	if fqdn == "" {
		log.Info("dns: skip layer 2 — no service <10m old with a ready endpoint (inconclusive)")
	} else {
		log.Info("dns: probing each coredns pod", "fqdn", fqdn)
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
			if w.dnsFn(ctx, ip, fqdn) {
				answered++
				delete(w.streak, name)
				log.Info("dns: fresh", "pod", name)
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
				metrics.IncError(corednsQueue)
				log.Info("SKIP recovery: inside cooldown",
					"agoS", ago, "cooldownS", corednsCooldownS)
				return nil
			}
		}
	}
	// Storm-gate: never evict while nodes are NotReady — eviction
	// only slows recovery during a cluster storm.
	notReady, err := countNotReadyNodes(ctx, w.cs)
	if err != nil {
		return fmt.Errorf("count not-ready nodes (storm gate): %w", err)
	}
	if notReady > 0 {
		metrics.IncError(corednsQueue)
		log.Info("SKIP recovery: nodes NotReady — cluster storm", "notReady", notReady)
		return nil
	}
	// Fleet not fully ready = a rollout is already recreating pods.
	if deploy.Status.ReadyReplicas < deploy.Status.Replicas {
		metrics.IncError(corednsQueue)
		log.Info("SKIP recovery: coredns not fully ready",
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
	log.Info("sweep done: stale coredns recovery issued")
	return nil
}

// logHit returns the first last-10m log line matching the informer
// death signature ("" = clean/unreadable). Bounded to 8s / 256KiB.
func (w *coreDNSWatchdog) logHit(ctx context.Context, pod string) string {
	lctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	since := int64(corednsLogSinceS)
	stream, err := w.cs.CoreV1().Pods(corednsNS).GetLogs(pod,
		&corev1.PodLogOptions{SinceSeconds: &since}).Stream(lctx)
	if err != nil {
		return ""
	}
	defer stream.Close()
	data, err := io.ReadAll(io.LimitReader(stream, corednsMaxLogBytes))
	if err != nil {
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

// probeFQDN returns <name>.<ns>.svc.cluster.local of the newest
// Service <10m old having an EndpointSlice with a ready endpoint, or
// "" when nothing qualifies (inconclusive).
func (w *coreDNSWatchdog) probeFQDN(ctx context.Context) string {
	svcs, err := w.cs.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return ""
	}
	sort.Slice(svcs.Items, func(i, j int) bool {
		return svcs.Items[i].CreationTimestamp.Time.
			After(svcs.Items[j].CreationTimestamp.Time)
	})
	type svcCand struct {
		ns, name string
		created  time.Time
	}
	n := len(svcs.Items)
	if n > 8 { // bash: top-8 newest BEFORE the age filter
		n = 8
	}
	cands := make([]svcCand, 0, n)
	for i := 0; i < n; i++ {
		s := &svcs.Items[i]
		cands = append(cands, svcCand{
			ns:      s.Namespace,
			name:    s.Name,
			created: s.CreationTimestamp.Time,
		})
	}
	// Release the cluster-wide ServiceList before issuing per-service
	// EndpointSlice queries.
	svcs = nil

	for _, svc := range cands {
		if time.Since(svc.created) >= corednsLogSinceS*time.Second {
			continue
		}
		eps, err := w.cs.DiscoveryV1().EndpointSlices(svc.ns).List(ctx,
			metav1.ListOptions{LabelSelector: "kubernetes.io/service-name=" + svc.name})
		if err != nil {
			continue
		}
		for _, es := range eps.Items {
			for _, ep := range es.Endpoints {
				// bash: conditions.ready == true — nil does NOT count.
				if ep.Conditions.Ready != nil && *ep.Conditions.Ready {
					return svc.name + "." + svc.ns + ".svc.cluster.local"
				}
			}
		}
	}
	return ""
}

// dnsProbe resolves fqdn directly through one coredns pod (UDP :53),
// equivalent to `nslookup <fqdn> <podIP>`.
func (w *coreDNSWatchdog) dnsProbe(ctx context.Context, podIP, fqdn string) bool {
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
	_, err := r.LookupHost(pctx, fqdn)
	return err == nil
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
	defer resp.Body.Close()
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

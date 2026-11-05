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
	"context"
	"net/http"
	"sort"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
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
	streak shared.StreakLedger
	// now is the clock seam — tests pin it so the recovery cooldown
	// window and the stamped timestamps are deterministic.
	// nil → time.Now.
	now shared.Clock
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
		cs:    d.CS,
		http:  &http.Client{Timeout: 5 * time.Second},
		queue: d.Name,
		now:   shared.SystemClock,
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
	w.streak.Prune(func(name string) bool {
		_, ok := podIP[name]
		return ok
	})
	stale := map[string]bool{}

	// ===== Layer 1: log fast-path =====
	for name := range podIP {
		if hit := w.logHitFn(ctx, name); hit != "" {
			stale[name] = true
			w.streak.Set(name, corednsStreakMax)
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
				w.streak.Reset(name)
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
				s := w.streak.Hit(name)
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
			w.streak.Set(name, corednsStreakMax)
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

// ksm_wedge.go — the kube-state-metrics wedge half of the
// controller-lease-guard check: detection shape c) documented in
// controller_lease_guard.go — a KSM pod whose log tail (or its
// kube_state_metrics_*_total error counters) shows a continuous
// reflector watch/list failure or a stuck 401 Unauthorized /
// expired SA token — the pod stays Ready while every kube_* metric
// it serves silently goes stale. The signature table, the 10m
// persistence window and the pod-bounce healer live here; the
// check type, the (a)/(b) lease-side duties and the shared
// controllerLeaseUnhealthyGauge live in controller_lease_guard.go.
package nodehealth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

const (
	// A KSM reflector/401 signature must persist 10m before the pod
	// counts as wedged — a single retry burst is self-healing.
	ksmWedgeMinAge     = 10 * time.Minute
	ksmPodHealCooldown = 30 * time.Minute
	// Log-tail bounds reuse the shared probefw tail defaults (200
	// lines / 256 KiB / 8s) — same shape as every pod-log probe.
	ksmLogTailLines = probefw.DefaultTailLines
	ksmLogMaxBytes  = probefw.LogMaxBytes
	ksmLogTimeout   = probefw.LogTimeout

	// node_automation_controller_lease_unhealthy reason labels.
	leaseReasonKSMUnauthorized    = "ksm_unauthorized"
	leaseReasonKSMReflectorErrors = "ksm_reflector_errors"
)

// ksmWedgeSignatures map a lower-cased log marker to the reason it
// reports — ordered most-specific first so a reflector line whose
// cause is a 401 still classifies as the auth wedge. "the server has
// asked for the client to provide credentials" is client-go's
// canonical expired-SA-token 401.
var ksmWedgeSignatures = []struct {
	marker string
	reason string
}{
	{"unauthorized", leaseReasonKSMUnauthorized},
	{"401", leaseReasonKSMUnauthorized},
	{"provide credentials", leaseReasonKSMUnauthorized},
	{"token expired", leaseReasonKSMUnauthorized},
	{"failed to list", leaseReasonKSMReflectorErrors},
	{"failed to watch", leaseReasonKSMReflectorErrors},
	{"unable to sync caches", leaseReasonKSMReflectorErrors},
}

// ---------------------------------------------------------------------------
// kube-state-metrics wedge healer
// ---------------------------------------------------------------------------

// checkKSMWedged scans Running kube-state-metrics pods for the
// reflector/token wedge, recording this sweep's tuples and finding
// strings on rep. A signature that persists past ksmWedgeMinAge
// reports the pod on the gauge AND bounces it — the restart
// re-mounts a fresh SA token and re-opens the watch streams a
// wedged client cannot recover.
func (p *controllerLeaseGuardCheck) checkKSMWedged(ctx context.Context,
	log logr.Logger, now time.Time, rep *probefw.SweepReport) error {

	pods, err := p.AllPods(ctx)
	if err != nil {
		// Never evaluated — carry the held ksm tuples forward so the
		// sweep-end reconcile keeps their series (the scan failed;
		// nothing was proven resolved).
		for k, lv := range p.emitted.Last() {
			if len(lv) == 3 && strings.HasPrefix(lv[2], "ksm_") {
				rep.Carry(k, lv)
			}
		}
		return fmt.Errorf("list pods (kube-state-metrics wedge scan): %w", err)
	}
	wedgeLive := map[string]bool{}
	for i := range pods {
		pod := &pods[i]
		if !isKSMPod(pod) || pod.DeletionTimestamp != nil ||
			pod.Status.Phase != corev1.PodRunning {
			continue
		}
		key := pod.Namespace + "/" + pod.Name
		// stampPatch delivers this pod's first-seen merge patch —
		// the durable half of the wedge window below: the window
		// gates a pod bounce, so the stamp lives on the pod itself
		// (and dies with it) for a restarted operator to resume
		// rather than re-arming a signature that already held.
		stampPatch := func(ctx context.Context, data []byte) error {
			_, err := p.CS.CoreV1().Pods(pod.Namespace).Patch(ctx,
				pod.Name, types.MergePatchType, data,
				metav1.PatchOptions{})
			return err
		}
		reason, err := p.ksmWedgeReason(ctx, pod)
		if err != nil {
			// Inconclusive, not clean — a broken log/metrics read
			// must not read as "no wedge": keep the first-seen
			// tracking and any held series for this pod.
			log.Info("WARN: ksm wedge signature inconclusive",
				"pod", key, "error", err)
			wedgeLive[key] = true
			for k, lv := range p.emitted.Last() {
				if strings.HasPrefix(k, key+"/") {
					rep.Carry(k, lv)
				}
			}
			continue
		}
		if reason == "" {
			// Resolved — the pod evaluated healthy, so the stamp
			// must leave BOTH clocks (a lingering annotation would
			// fast-trip the next wedge's window). A failed clear is
			// Warn'd inside and tolerated: the ledger Forget already
			// landed, only the durable half can linger a sweep.
			_ = heal.ClearPersistedFirstSeen(ctx, log, &p.wedgeSeen,
				pod, kube.AnnoFirstSeenKSMWedge, key, stampPatch)
			continue
		}
		wedgeLive[key] = true
		// The window gates the pod-delete remediation below — the
		// annotation-backed variant, so an operator restart resumes
		// the count instead of sitting a proven wedge out a second
		// full window (the inconclusive path above deliberately
		// does NOT clear: it keeps tracking + carried series).
		if !heal.FirstSeenPersisted(ctx, log, &p.wedgeSeen, pod,
			kube.AnnoFirstSeenKSMWedge, key, ksmWedgeMinAge, now,
			stampPatch) {
			continue
		}
		p.emitUnhealthy(rep, pod.Namespace, pod.Name, reason)
		rep.Find(key + "(" + reason + ")")
		p.DeletePodHeal(ctx, log, CheckNameControllerLeaseGuard,
			"ksm/"+key, pod, ksmPodHealCooldown, now)
	}
	p.wedgeSeen.Prune(func(k string) bool { return wedgeLive[k] })
	return nil
}

// isKSMPod matches kube-state-metrics pods by the
// app.kubernetes.io/name label the kube-prometheus-stack chart
// ships, falling back to the deployment name prefix for installs
// without the label.
func isKSMPod(pod *corev1.Pod) bool {
	return pod.Labels["app.kubernetes.io/name"] == "kube-state-metrics" ||
		strings.HasPrefix(pod.Name, "kube-state-metrics-")
}

// ksmWedgeReason resolves this sweep's wedge signature for one
// kube-state-metrics pod. The log tail is the primary signal — the
// injected seam in tests, the bounded GetLogs tail in production;
// when the tail reads clean, the Prometheus counter increase is the
// "or metrics" half of the detection (a spamming reflector can
// rotate the 401 storm out of the last tail lines between sweeps).
// "" is clean; an error means inconclusive.
func (p *controllerLeaseGuardCheck) ksmWedgeReason(ctx context.Context,
	pod *corev1.Pod) (string, error) {

	probe := p.ksmLogProbe
	if probe == nil {
		probe = func(ctx context.Context, pod *corev1.Pod) (string, error) {
			return ksmLogTailWedge(ctx, p.CS, pod)
		}
	}
	reason, err := probe(ctx, pod)
	if err != nil {
		return "", fmt.Errorf("log tail: %w", err)
	}
	if reason != "" {
		return reason, nil
	}
	errs, err := p.ksmReflectorErrorIncrease(ctx, pod)
	if err != nil {
		return "", fmt.Errorf("prometheus: %w", err)
	}
	if errs > 0 {
		return leaseReasonKSMReflectorErrors, nil
	}
	return "", nil
}

// ksmLogTailWedge is the production log-tail probe: the pod's last
// ksmLogTailLines lines (bounded by ksmLogMaxBytes / ksmLogTimeout)
// scanned for the wedge signatures — the reason of the first hit,
// "" when clean. A fetch failure is inconclusive, not healthy.
func ksmLogTailWedge(ctx context.Context, cs kubernetes.Interface,
	pod *corev1.Pod) (string, error) {

	reason := ""
	hit, err := probefw.PodLogTail(ctx, cs, pod, "",
		ksmLogTailLines, ksmLogMaxBytes, ksmLogTimeout,
		func(line string) bool {
			l := strings.ToLower(line)
			for _, sig := range ksmWedgeSignatures {
				if strings.Contains(l, sig.marker) {
					reason = sig.reason
					return true
				}
			}
			return false
		})
	if err != nil || !hit {
		return "", err
	}
	return reason, nil
}

// ksmReflectorErrorIncrease is the metrics half of the wedge OR: KSM
// exports per-resource list/watch counters labelled result="error" —
// a wedged stream shows a continuous increase. A missing series is
// clean; a query failure is inconclusive.
func (p *controllerLeaseGuardCheck) ksmReflectorErrorIncrease(
	ctx context.Context, pod *corev1.Pod) (float64, error) {

	// Each side defaults to vector(0): bare `sum + sum` yields an
	// EMPTY vector when only one of the two error counters exists
	// (PromQL arithmetic drops absent operands) — e.g. a wedge that
	// only ever produced watch errors would sum to nothing and the
	// signal would never fire.
	samples, err := p.PromQuery(ctx, fmt.Sprintf(
		`(sum(increase(kube_state_metrics_list_total{result="error",pod="%s"}[10m])) or vector(0)) + (sum(increase(kube_state_metrics_watch_total{result="error",pod="%s"}[10m])) or vector(0))`,
		pod.Name, pod.Name))
	if err != nil {
		return 0, err
	}
	total := 0.0
	for _, s := range samples {
		total += s.Value
	}
	return total, nil
}

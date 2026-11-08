// image_pull_storm.go — the image-pull-storm check (W10-GI5):
// containers waiting in ImagePullBackOff/ErrImagePull/
// RegistryUnavailable past the window — single-namespace vs
// cluster-registry-outage classification.
package nodehealth

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// imagePullStormCheck is the image-pull-storm watchdog.
type imagePullStormCheck struct {
	*probefw.Deps

	// seen tracks each container's first sweep inside a pull-failure
	// waiting state — the >=10m persistence window; pruned when the
	// container leaves the state so a resolved pull re-arms.
	seen state.FirstSeenLedger
	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1 (zero value usable; the serial sweep needs no lock).
	emitted state.GaugeLedger[string]
}

// newImagePullStormCheck builds the W10-GI5 check — its state is
// the first-seen persistence ledger and the emitted-gauge ledger
// (both zero-value usable).
func NewImagePullStormCheck(d *probefw.Deps) probefw.Check {
	return &imagePullStormCheck{Deps: d}
}

const (
	CheckNameImagePullStorm = "image-pull-storm"

	// W10-GI5 — image-pull-storm knobs.
	imagePullMinAge = 10 * time.Minute
)

// pullWaitingReasons are the container waiting reasons that
// mean "the image cannot be pulled".
var pullWaitingReasons = map[string]bool{
	"ImagePullBackOff":    true,
	"ErrImagePull":        true,
	"RegistryUnavailable": true,
}

// registryOutageMarkers are message substrings that flip a
// pull failure from "one bad tag" to "the registry path is down" —
// rate-limit, proxy and Harbor-cache signatures.
var registryOutageMarkers = []string{
	"toomanyrequests", "429", "proxyconnect tcp", "harbor",
}

var (
	// W10-GI5 — per-pod image-pull backoff.
	imagePullBackoffPodsGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_image_pull_backoff",
		Help: "1 while the pod has a container waiting in an image-pull failure >10m — W10-GI5.",
	}, []string{"namespace", "pod"})

	// W10-GI5 — cluster-wide registry/pull outage latch.
	registryPullOutageGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_automation_registry_pull_outage",
		Help: "1 while image-pull failures span >=2 namespaces or carry a registry-outage signature — W10-GI5.",
	})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		imagePullBackoffPodsGauge,
		registryPullOutageGauge)
}

// checkImagePullStorm scans all non-Succeeded pods for containers
// waiting in an image-pull failure persisting >10m (first-seen
// ledger — the waiting state carries no timestamp of its own). One
// affected namespace is a workload problem
// (workload_image_pull_backoff); >=2 namespaces or a
// registry-outage message marker is a cluster pull outage
// (cluster_registry_pull_outage → ClusterImagePullStorm alert).
func (p *imagePullStormCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	pods, err := p.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}
	type offender struct {
		ns, name, reason, message string
	}
	var offenders []offender
	namespaces := map[string]bool{}
	outage := false
	live := map[string]bool{} // container keys still storming this sweep
	for i := range pods {
		pod := &pods[i]
		if pod.Status.Phase == corev1.PodSucceeded ||
			pod.DeletionTimestamp != nil {
			continue
		}
		checkState := func(cs corev1.ContainerStatus) {
			w := cs.State.Waiting
			if w == nil || !pullWaitingReasons[w.Reason] {
				return
			}
			// ContainerStateWaiting carries no timestamp in the
			// Kubernetes API (the plan's waiting.startedAt does not
			// exist) — the first-seen ledger is the age source: the
			// container must hold the pull-failure state across
			// imagePullMinAge of observed sweeps before it counts.
			// Pod creation time cannot stand in — an hours-old pod
			// that only just started storming would flag instantly.
			key := "imgpull/" + pod.Namespace + "/" + pod.Name + "/" + cs.Name
			live[key] = true
			// Quiet site: the first-seen window needs no "tracking"
			// log line — Discard keeps the shared helper silent.
			if !probefw.Persisted(&p.seen, key, now, imagePullMinAge,
				logr.Discard()) {
				return
			}
			offenders = append(offenders, offender{
				ns: pod.Namespace, name: pod.Name,
				reason: w.Reason, message: w.Message,
			})
			namespaces[pod.Namespace] = true
			lower := strings.ToLower(w.Message)
			for _, marker := range registryOutageMarkers {
				if strings.Contains(lower, marker) {
					outage = true
					break
				}
			}
		}
		for _, s := range pod.Status.InitContainerStatuses {
			checkState(s)
		}
		for _, s := range pod.Status.ContainerStatuses {
			checkState(s)
		}
		for _, s := range pod.Status.EphemeralContainerStatuses {
			checkState(s)
		}
	}
	// Resolved/removed containers re-arm — a later storm restarts
	// the window instead of inheriting the stale stamp.
	p.seen.Prune(func(k string) bool { return live[k] })

	var rep probefw.SweepReport
	for _, o := range offenders {
		rep.Flag(imagePullBackoffPodsGauge, o.ns+"/"+o.name,
			[]string{o.ns, o.name})
	}
	rep.Close(&p.emitted, imagePullBackoffPodsGauge.DeleteLabelValues)
	if len(namespaces) >= 2 {
		outage = true
	}
	if outage {
		registryPullOutageGauge.Set(1)
	} else {
		registryPullOutageGauge.Set(0)
	}
	if len(offenders) == 0 {
		return probefw.Result{Pass: true}
	}
	sort.Slice(offenders, func(i, j int) bool {
		if offenders[i].ns != offenders[j].ns {
			return offenders[i].ns < offenders[j].ns
		}
		return offenders[i].name < offenders[j].name
	})
	var summary []string
	for i, o := range offenders {
		if i >= 10 {
			summary = append(summary, "...")
			break
		}
		summary = append(summary, fmt.Sprintf("%s/%s:%s", o.ns, o.name, o.reason))
	}
	detail := "workload_image_pull_backoff"
	if outage {
		detail = "cluster_registry_pull_outage"
	}
	// offenders counts container-level waiting states — report the
	// distinct pod count instead.
	podSet := map[string]bool{}
	for _, o := range offenders {
		podSet[o.ns+"/"+o.name] = true
	}
	log.Info("image pull storm detected", "detail", detail,
		"namespaces", len(namespaces), "pods", len(podSet))
	return probefw.WhyFold(probefw.Section(
		"%s: %d pod(s) across %d namespace(s) waiting >%s: %s",
		summary, detail, len(podSet), len(namespaces), imagePullMinAge))
}

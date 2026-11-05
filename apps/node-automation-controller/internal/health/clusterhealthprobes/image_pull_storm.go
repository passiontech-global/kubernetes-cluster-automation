// image_pull_storm.go — the image-pull-storm check (W10-GI5):
// containers waiting in ImagePullBackOff/ErrImagePull/
// RegistryUnavailable past the window — single-namespace vs
// cluster-registry-outage classification.
package clusterhealthprobes

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	checkNameImagePullStorm = "image-pull-storm"

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
// waiting in an image-pull failure >10m. One affected namespace is
// a workload problem (workload_image_pull_backoff); >=2 namespaces
// or a registry-outage message marker is a cluster pull outage
// (cluster_registry_pull_outage → ClusterImagePullStorm alert).
func (p *clusterHealthProber) checkImagePullStorm(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()
	pods, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list pods: %w", err)}
	}
	type offender struct {
		ns, name, reason, message string
	}
	var offenders []offender
	namespaces := map[string]bool{}
	outage := false
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Status.Phase == corev1.PodSucceeded ||
			pod.DeletionTimestamp != nil {
			continue
		}
		checkState := func(state corev1.ContainerState) {
			w := state.Waiting
			if w == nil || !pullWaitingReasons[w.Reason] {
				return
			}
			// ContainerStateWaiting carries no timestamp in the
			// Kubernetes API (the plan's waiting.startedAt does not
			// exist) — pod creation time is the sanctioned age
			// source, same convention as probePodRestarts: a pod
			// still waiting on its image >10m after creation is a
			// prolonged pull failure, not a slow first pull.
			if now.Sub(pod.CreationTimestamp.Time) < imagePullMinAge {
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
			checkState(s.State)
		}
		for _, s := range pod.Status.ContainerStatuses {
			checkState(s.State)
		}
		for _, s := range pod.Status.EphemeralContainerStatuses {
			checkState(s.State)
		}
	}

	current := map[string][]string{}
	for _, o := range offenders {
		lv := []string{o.ns, o.name}
		current[o.ns+"/"+o.name] = lv
		imagePullBackoffPodsGauge.WithLabelValues(lv...).Set(1)
	}
	reconcileEmittedGauges(checkNameImagePullStorm,
		imagePullBackoffPodsGauge, current)
	if len(namespaces) >= 2 {
		outage = true
	}
	if outage {
		registryPullOutageGauge.Set(1)
	} else {
		registryPullOutageGauge.Set(0)
	}
	if len(offenders) == 0 {
		return probeResult{pass: true}
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
	return probeResult{why: fmt.Sprintf(
		"%s: %d pod(s) across %d namespace(s) waiting >%s: %s",
		detail, len(podSet), len(namespaces), imagePullMinAge,
		strings.Join(summary, ", "))}
}

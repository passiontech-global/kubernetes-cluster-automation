// imagepull.go — the image-pull-storm-gate/maintenance-hold-stale image-pull stall census: the
// pod-shape predicate (any container status.waiting.reason in
// ImagePullBackOff/ErrImagePull) and the cluster-wide count behind
// the descheduler-storm-gate's storm signal (e) — a pull storm means
// images are not landing anywhere, so rebalancing just spreads
// unrunnable pods across more nodes. The statefulset-ondelete-roller
// runs the same predicate per owned pod to defer a set whose member
// cannot pull its (possibly new) image — deleting the next member on
// top stacks a second stuck pod. image-pull-storm's alerting health check
// (health/nodehealth/image_pull_storm) keeps its own richer scan
// (registry-outage markers, per-namespace classification, first-seen
// windows); this is the cheap predicate+census the GATING modules
// share.
package kube

import (
	"cmp"
	"context"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ImagePullStallReason returns the kubelet waiting reason
// ("ImagePullBackOff" or "ErrImagePull") when any of the pod's
// containers — init, regular or ephemeral — is currently waiting on
// an image-pull failure, "" when none is. The waiting state carries
// no timestamp of its own, so "how long" is the caller's concern
// (the storm gate reads the census per sweep; the roller defers for
// the cycle) — here only the CURRENT state counts, never LastState:
// a container that already recovered from a pull failure is running
// now and must not defer a roll.
func ImagePullStallReason(p *corev1.Pod) string {
	for _, cs := range p.Status.ContainerStatuses {
		if r := pullWaitingReason(cs); r != "" {
			return r
		}
	}
	for _, cs := range p.Status.InitContainerStatuses {
		if r := pullWaitingReason(cs); r != "" {
			return r
		}
	}
	for _, cs := range p.Status.EphemeralContainerStatuses {
		if r := pullWaitingReason(cs); r != "" {
			return r
		}
	}
	return ""
}

// pullWaitingReason extracts the stall reason from one container
// status — the two kubelet-native pull-failure spellings (as in
// image_pull_storm's pullWaitingReasons; upstream defines them in
// kubelet's images package, not k8s.io/api). Anything else
// (CrashLoopBackOff, CreateContainerConfigError) is not a pull stall.
func pullWaitingReason(cs corev1.ContainerStatus) string {
	if cs.State.Waiting == nil {
		return ""
	}
	switch cs.State.Waiting.Reason {
	case "ImagePullBackOff", "ErrImagePull":
		return cs.State.Waiting.Reason
	}
	return ""
}

// PodImagePullStalled reports whether any container of the pod is
// waiting on an image-pull failure.
func PodImagePullStalled(p *corev1.Pod) bool {
	return ImagePullStallReason(p) != ""
}

// CountImagePullStalledPods returns (podCount, namespaceCount) for
// the cluster-wide census of pods with at least one container
// waiting in ImagePullBackOff/ErrImagePull. Paged like every
// cluster-wide read; a List error is returned — the callers' storm
// verdicts must not compute on an empty read.
func CountImagePullStalledPods(ctx context.Context,
	cs kubernetes.Interface) (podCount, namespaceCount int, err error) {

	census, err := ScanImagePullCensus(ctx, cs)
	return census.StallPods, census.StallNamespaces, err
}

// RegistryPullOutage summarizes cluster-wide image-pull failures for one
// normalized registry host whose waiting messages match unmistakable
// registry-level outage/rate-limit signatures.
type RegistryPullOutage struct {
	Registry       string
	PodCount       int
	NamespaceCount int
	SamplePods     []string
}

// ImagePullCensus holds both the cluster-wide stalled pod/namespace totals
// and per-registry outage aggregations computed in a single Pod list pass.
type ImagePullCensus struct {
	StallPods       int
	StallNamespaces int
	RegistryOutages []RegistryPullOutage
}

// imagePullRegistryOutageMarkers are unmistakable registry-level error
// signatures matched case-insensitively against ContainerStateWaiting.Message
// when a container is waiting in ImagePullBackOff or ErrImagePull.
var imagePullRegistryOutageMarkers = []string{
	"429",
	"toomanyrequests",
	"too many requests",
	"rate limit",
	"503",
	"service unavailable",
	"502",
	"bad gateway",
	"504",
	"gateway timeout",
	"tls handshake timeout",
	"connection refused",
	"i/o timeout",
	"no such host",
	"dial tcp",
	"eof",
}

// IsRegistryOutageMessage reports whether a kubelet waiting message carries
// an unmistakable registry-level rate-limit or outage signature.
func IsRegistryOutageMessage(msg string) bool {
	if msg == "" {
		return false
	}
	lower := strings.ToLower(msg)
	for _, marker := range imagePullRegistryOutageMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// NormalizedRegistryHost extracts and normalizes the registry host from a
// container image reference, defaulting unqualified images (e.g. "nginx:1.25",
// "library/nginx:1.25") and Docker Hub aliases to "docker.io". Returns ""
// when image is empty.
func NormalizedRegistryHost(image string) string {
	img := strings.TrimSpace(image)
	if img == "" {
		return ""
	}
	slash := strings.IndexByte(img, '/')
	if slash < 0 {
		return "docker.io"
	}
	first := img[:slash]
	if !strings.ContainsAny(first, ".:") && first != "localhost" {
		return "docker.io"
	}
	host := strings.ToLower(first)
	switch host {
	case "index.docker.io", "registry-1.docker.io":
		return "docker.io"
	default:
		return host
	}
}

// CountImagePullRegistryOutage scans all Pods for containers waiting in
// ImagePullBackOff/ErrImagePull with registry-level outage/429 messages and
// returns per-registry affected pod and namespace counts.
func CountImagePullRegistryOutage(ctx context.Context,
	cs kubernetes.Interface) ([]RegistryPullOutage, error) {

	census, err := ScanImagePullCensus(ctx, cs)
	return census.RegistryOutages, err
}

// ScanImagePullCensus scans all Pods once to compute both the total stalled
// pod/namespace counts and per-registry outage aggregations.
func ScanImagePullCensus(ctx context.Context,
	cs kubernetes.Interface) (ImagePullCensus, error) {

	var out ImagePullCensus
	nsSeen := map[string]bool{}
	regPods := map[string]map[string]bool{}
	regNS := map[string]map[string]bool{}

	err := ListEach(ctx,
		metav1.ListOptions{Limit: DefaultListPageSize},
		Pods(cs, metav1.NamespaceAll),
		func(items []corev1.Pod) error {
			for i := range items {
				p := &items[i]
				if p.Status.Phase == corev1.PodSucceeded ||
					p.Status.Phase == corev1.PodFailed {
					continue
				}
				podStalled := false
				podKey := p.Namespace + "/" + p.Name

				inspect := func(statuses []corev1.ContainerStatus, specList []corev1.Container) {
					for _, cs := range statuses {
						if pullWaitingReason(cs) == "" {
							continue
						}
						podStalled = true
						if !IsRegistryOutageMessage(cs.State.Waiting.Message) {
							continue
						}
						img := findContainerImage(specList, cs.Name)
						img = cmp.Or(img, cs.Image)
						reg := NormalizedRegistryHost(img)
						if reg == "" {
							reg = "unknown"
						}
						if regPods[reg] == nil {
							regPods[reg] = map[string]bool{}
							regNS[reg] = map[string]bool{}
						}
						regPods[reg][podKey] = true
						regNS[reg][p.Namespace] = true
					}
				}

				inspect(p.Status.ContainerStatuses, p.Spec.Containers)
				inspect(p.Status.InitContainerStatuses, p.Spec.InitContainers)
				inspectEphemeral(p, func(cs corev1.ContainerStatus, img string) {
					podStalled = true
					if !IsRegistryOutageMessage(cs.State.Waiting.Message) {
						return
					}
					reg := NormalizedRegistryHost(img)
					if reg == "" {
						reg = "unknown"
					}
					if regPods[reg] == nil {
						regPods[reg] = map[string]bool{}
						regNS[reg] = map[string]bool{}
					}
					regPods[reg][podKey] = true
					regNS[reg][p.Namespace] = true
				})

				if podStalled {
					out.StallPods++
					nsSeen[p.Namespace] = true
				}
			}
			return nil
		})
	if err != nil {
		return ImagePullCensus{}, err
	}
	out.StallNamespaces = len(nsSeen)

	if len(regPods) > 0 {
		regs := make([]string, 0, len(regPods))
		for r := range regPods {
			regs = append(regs, r)
		}
		slices.Sort(regs)
		out.RegistryOutages = make([]RegistryPullOutage, 0, len(regs))
		for _, r := range regs {
			pods := make([]string, 0, len(regPods[r]))
			for pk := range regPods[r] {
				pods = append(pods, pk)
			}
			slices.Sort(pods)
			const maxSamples = 5
			if len(pods) > maxSamples {
				pods = pods[:maxSamples]
			}
			out.RegistryOutages = append(out.RegistryOutages, RegistryPullOutage{
				Registry:       r,
				PodCount:       len(regPods[r]),
				NamespaceCount: len(regNS[r]),
				SamplePods:     pods,
			})
		}
	}
	return out, nil
}

func findContainerImage(containers []corev1.Container, name string) string {
	for i := range containers {
		if containers[i].Name == name {
			return containers[i].Image
		}
	}
	return ""
}

func inspectEphemeral(p *corev1.Pod, fn func(cs corev1.ContainerStatus, img string)) {
	for _, cs := range p.Status.EphemeralContainerStatuses {
		if pullWaitingReason(cs) == "" {
			continue
		}
		img := ""
		for i := range p.Spec.EphemeralContainers {
			if p.Spec.EphemeralContainers[i].Name == cs.Name {
				img = p.Spec.EphemeralContainers[i].Image
				break
			}
		}
		fn(cs, cmp.Or(img, cs.Image))
	}
}

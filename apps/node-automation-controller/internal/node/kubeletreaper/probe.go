// probe.go — the kubelet-reaper probe path: the bounded healthz
// retry loop (probe) and the one-worker tunnel guard's
// konnectivity-agent degraded check. Split out of
// kubelet_reaper.go so the sweep file stays under the ~500-LOC bar.
package kubeletreaper

import (
	"context"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// konnectivityAgentNS is where the konnectivity-agent DaemonSet
// pods live — the server→node proxy path every kubelet healthz
// probe traverses.
const konnectivityAgentNS = "kube-system"

// konnectivityDegraded reports whether the cluster runs
// konnectivity-agent pods AND none of them is Ready — the evidence
// that a cluster-wide probe failure is a broken proxy tunnel rather
// than a dead kubelet. Matching is by pod-name prefix, not label:
// distributions label the agent differently (k8s-app vs app) but
// every implementation names the pods konnectivity-agent-*. Zero
// agent pods means "no tunnel evidence" — the caller treats that
// as not-degraded and lets the per-node lease+grace gates decide.
func (r *kubeletReaper) konnectivityDegraded(ctx context.Context) (bool, error) {
	pods, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.Pods(r.cs, konnectivityAgentNS))
	if err != nil {
		return false, err
	}
	found, ready := 0, 0
	for i := range pods {
		p := &pods[i]
		if !strings.HasPrefix(p.Name, "konnectivity-agent") ||
			p.DeletionTimestamp != nil {
			continue
		}
		found++
		for _, c := range p.Status.Conditions {
			if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
				ready++
				break
			}
		}
	}
	return found > 0 && ready == 0, nil
}

// probe asks kube.KubeletHealthz up to 4 times (10s apart, 8s per
// attempt) — a body starting with "ok" wins. The REST-path details
// live in the helper; the retry loop and the taint decision it feeds
// are this module's policy.
func (r *kubeletReaper) probe(ctx context.Context, node string) bool {
	// One timer reused across the inter-probe gaps — a fresh
	// time.After per attempt leaves each channel allocated until GC.
	// Armed stopped+drained so Reset never races an earlier fire; each
	// wait below consumes the pending fire, leaving the channel empty
	// for the next Reset.
	gap := time.NewTimer(kubeletReaperProbeGap)
	if !gap.Stop() {
		<-gap.C
	}
	defer gap.Stop()
	for i := range kubeletReaperProbes {
		if i > 0 {
			gap.Reset(kubeletReaperProbeGap)
			select {
			case <-ctx.Done():
				return false
			case <-gap.C:
			}
		}
		body, err := kube.KubeletHealthz(ctx, r.cs, node)
		if err == nil && strings.HasPrefix(strings.TrimSpace(string(body)), "ok") {
			return true
		}
		// sweep() only sees the bool — log WHY the attempt failed
		// (apiserver-proxy error vs. a 200 whose body isn't "ok",
		// which means the proxy reached the wrong backend).
		log := logf.FromContext(ctx)
		if err != nil {
			log.Info("WARN: kubelet healthz probe failed",
				"node", node, "attempt", i+1, "of", kubeletReaperProbes,
				"error", err)
		} else {
			log.Info("WARN: kubelet healthz probe returned non-ok body",
				"node", node, "attempt", i+1, "of", kubeletReaperProbes,
				"body", truncateLog(string(body), 200))
		}
	}
	return false
}

// truncateLog caps a string spliced into a log value — a proxy
// response can be an arbitrarily large error page.
func truncateLog(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

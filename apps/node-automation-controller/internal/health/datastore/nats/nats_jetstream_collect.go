// nats_jetstream_collect.go — the census half of the
// nats-jetstream-health check: which StatefulSets are NATS (the
// app.kubernetes.io/name=nats helm marker), which namespaces they
// cover, and the member-pod maps every later phase resolves
// Prometheus series and log scans against. Split out of
// nats_jetstream_health.go — see that file for the check.
package nats

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// natsCensus is one sweep's view of the NATS fleet: the namespaces
// the member StatefulSets cover (namespace-scope findings gate on
// it), the member pods keyed both ways a signal can name them, and
// the per-StatefulSet Ready tally the quorum-safe bounce reads.
type natsCensus struct {
	namespaces    map[string]bool
	memberByName  map[string]*corev1.Pod // "ns/name"
	memberByShort map[string]*corev1.Pod // bare name — series w/o namespace label
	// ambiguousShort marks bare names claimed by pods in MORE THAN
	// ONE namespace — two NATS clusters can both run "nats-0", and a
	// series without a namespace label must never resolve to an
	// arbitrary cluster's member (the heal would bounce the wrong
	// StatefulSet's pod).
	ambiguousShort map[string]bool
	readyBySTS     map[string]int // "ns/stsName" -> Running+Ready members
}

// resolvePod maps a Prometheus series' (namespace, pod) labels back
// to a member pod; an empty namespace falls back to the bare-name
// index (series without a namespace label). An ambiguous bare name
// resolves to nil — unattributable evidence is skipped, never
// guessed.
func (c *natsCensus) resolvePod(ns, name string) *corev1.Pod {
	if ns != "" {
		return c.memberByName[ns+"/"+name]
	}
	if c.ambiguousShort[name] {
		return nil
	}
	return c.memberByShort[name]
}

// collectNATS discovers the NATS StatefulSets and member pods.
// Absence means no NATS deployed: tolerate, pass clean — and
// (importantly) never pay the pods List on clusters without it. A
// nil census with nil error is that clean-pass signal; the caller
// still reconciles the ledgers so a stale emitted 1 cannot leak.
// The snapshot returns the cluster-wide list; the label filter
// applies client-side. A pods list failure on a populated cluster
// is Infra — the census cannot be proven.
func collectNATS(ctx context.Context, d *probefw.Deps) (*natsCensus, error) {
	allSTS, err := d.AllStatefulSets(ctx)
	if err != nil {
		return nil, fmt.Errorf("list nats statefulsets: %w", err)
	}
	var stss []appsv1.StatefulSet
	for i := range allSTS {
		if allSTS[i].Labels["app.kubernetes.io/name"] == natsAppLabelValue {
			stss = append(stss, allSTS[i])
		}
	}
	if len(stss) == 0 {
		return nil, nil
	}
	c := &natsCensus{
		namespaces:     map[string]bool{},
		memberByName:   map[string]*corev1.Pod{},
		memberByShort:  map[string]*corev1.Pod{},
		ambiguousShort: map[string]bool{},
		readyBySTS:     map[string]int{},
	}
	for i := range stss {
		c.namespaces[stss[i].Namespace] = true
	}
	pods, err := d.PodsMatching(ctx, metav1.NamespaceAll,
		"app.kubernetes.io/name="+natsAppLabelValue)
	if err != nil {
		return nil, fmt.Errorf("list nats pods: %w", err)
	}
	for i := range pods {
		pod := pods[i]
		if pod.DeletionTimestamp != nil {
			continue
		}
		c.memberByName[pod.Namespace+"/"+pod.Name] = pod
		if prev := c.memberByShort[pod.Name]; prev != nil {
			if prev.Namespace != pod.Namespace {
				// Same pod name in two namespaces — the bare-name
				// index can no longer attribute ns-less series.
				delete(c.memberByShort, pod.Name)
				c.ambiguousShort[pod.Name] = true
			}
		} else if !c.ambiguousShort[pod.Name] {
			c.memberByShort[pod.Name] = pod
		}
		if probefw.PodRunningReady(pod) {
			c.readyBySTS[natsSTSKey(pod)]++
		}
	}
	return c, nil
}

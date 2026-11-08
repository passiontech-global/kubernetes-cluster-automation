// verdict.go — the fencing-evidence ladder for one suspect node:
// confirmedDead (medik8s remediation CR, or Ready=Unknown>30m plus a
// dead kubelet probe) and the remediation-CR plumbing that backs it.
// Pure extraction from dead_node_sweeper.go — the safety story lives
// in doc.go.
package deadnodesweeper

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// deadNodeUnknownAge: Ready=Unknown must persist this long before
// verdict path (b) is even considered — covers monitor-grace (40s),
// lease retry storms and short network partitions.
const deadNodeUnknownAge = 30 * time.Minute

// medik8s remediation CRs — a fencer naming a node is the strongest
// death certificate available in-cluster.
var (
	selfNodeRemediationGVR    = kube.GVRSelfNodeRemediation
	fenceAgentsRemediationGVR = kube.GVRFenceAgentsRemediation
)

// confirmedDead is the safety gate — dead only with independent
// fencing evidence: (a) a medik8s remediation CR (viaSNR=true), or
// (b) Ready=Unknown>30m + a dead kubelet probe (viaSNR=false — no
// fencer has certified the death, so the caller owes the node the
// stateful split-brain gate before tainting). reason carries
// the evidence for the caller's logs; a dead=false result leaves it
// empty.
func (s *deadNodeSweeper) confirmedDead(ctx context.Context, n *corev1.Node,
	rem *remediationCache, nodeNames map[string]bool) (dead, viaSNR bool, reason string, err error) {
	log := logf.FromContext(ctx)

	// Path (a): a fencer CR exists for the node.
	fenced, err := s.hasRemediationCR(ctx, n.Name, rem, nodeNames)
	if err != nil {
		return false, false, "", err
	}
	if fenced {
		log.Info("fencing evidence: medik8s remediation CR", "node", n.Name)
		return true, true, "medik8s remediation CR", nil
	}

	// Path (b): Ready=Unknown held for >30m (the node controller
	// stopped getting heartbeats long ago) AND the kubelet does not
	// answer /healthz through the apiserver proxy.
	c := kube.NodeCondition(n, corev1.NodeReady)
	if c == nil || c.Status != corev1.ConditionUnknown {
		return false, false, "", nil // NotReady/False alone is not a death certificate
	}
	if c.LastTransitionTime.IsZero() ||
		s.now.Now().Sub(c.LastTransitionTime.Time) <= deadNodeUnknownAge {
		return false, false, "", nil
	}
	ok, err := s.probeFn(ctx, n.Name)
	if err != nil {
		// A probe that errors out IS a failed probe — the kubelet
		// did not serve healthz (same meaning as kubelet reaper's
		// DoRaw error). Logged for forensics, not counted as a
		// module failure.
		log.Error(err, "kubelet healthz probe errored — counts as failed", "node", n.Name)
		return true, false, "Ready=Unknown>30m + kubelet probe failed", nil
	}
	if !ok {
		log.Info("fencing evidence: Ready=Unknown>30m + kubelet probe failed", "node", n.Name)
		return true, false, "Ready=Unknown>30m + kubelet probe failed", nil
	}
	return false, false, "", nil
}

// remediationNodeNameAnno is the annotation medik8s NHC (>= v0.6)
// stamps on remediation CRs it names "<nodeName>-<templateName>"
// (escalatingRemediations / multi-template setups) — the CR name no
// longer equals the node name, so the annotation carries the
// fencing target (W12 P0-7).
const remediationNodeNameAnno = "remediation.medik8s.io/node-name"

// remediationCache memoizes the once-per-sweep remediation CR
// listing — the same API read serves every suspect node in the
// cycle, so N suspects cost two List calls total, not 2N. A list
// failure is cached too: the verdict stays consistent across the
// sweep instead of re-hammering a flapping API per node.
type remediationCache struct {
	fetched bool
	items   []unstructured.Unstructured
	err     error
}

// remediationItems returns both CRDs' objects, listing at most once
// per cache instance. A missing CRD is "no evidence" for that GVR —
// other list failures are real and sticky for the sweep.
func (s *deadNodeSweeper) remediationItems(ctx context.Context,
	rem *remediationCache) ([]unstructured.Unstructured, error) {
	// A missing dynamic client is a wiring bug, not "no fencing
	// evidence" — unverifiable fails closed like every other check
	// (same contract as descheduler-storm-gate's dyn guard).
	if s.dyn == nil {
		return nil, errors.New("no dynamic client — remediation CR check unverifiable")
	}
	if rem.fetched {
		return rem.items, rem.err
	}
	rem.fetched = true
	for _, gvr := range []schema.GroupVersionResource{
		selfNodeRemediationGVR, fenceAgentsRemediationGVR,
	} {
		items, err := kube.ListAll(ctx,
			metav1.ListOptions{Limit: kube.DefaultListPageSize},
			kube.DynamicPage(s.dyn.Resource(gvr).Namespace(metav1.NamespaceAll)))
		if err != nil {
			if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
				continue // CRD not installed on this cluster
			}
			rem.err = fmt.Errorf("list %s: %w", gvr.Resource, err)
			return nil, rem.err
		}
		rem.items = append(rem.items, items...)
	}
	return rem.items, nil
}

// hasRemediationCR reports whether any medik8s remediation object
// targets the node: the remediation.medik8s.io/node-name annotation
// (AUTHORITATIVE when present — a CR stamped for another node is
// never evidence here), CR name == node name (the 1:1 shape both
// CRDs historically use), or a "<nodeName>-" name prefix (the
// template-suffixed shape NHC v0.6+ emits). The prefix fallback is
// guarded by the known node set: a CR like "worker-1-gpu" or
// "worker-1-gpu-<tpl>" belongs to the node worker-1-gpu, and a bare
// HasPrefix match would otherwise let it fence worker-1.
func (s *deadNodeSweeper) hasRemediationCR(ctx context.Context, nodeName string,
	rem *remediationCache, nodeNames map[string]bool) (bool, error) {
	items, err := s.remediationItems(ctx, rem)
	if err != nil {
		return false, err
	}
	for i := range items {
		crName := items[i].GetName()
		if anno := items[i].GetAnnotations()[remediationNodeNameAnno]; anno != "" {
			// The annotation is the fencing target — when it is
			// present it decides alone: no name or prefix match can
			// override it (a "worker-1-gpu-<tpl>" CR annotated for
			// worker-1-gpu must not fence worker-1).
			if anno == nodeName {
				return true, nil
			}
			continue
		}
		if crName == nodeName {
			return true, nil
		}
		if strings.HasPrefix(crName, nodeName+"-") &&
			!ownedByLongerNode(crName, nodeName, nodeNames) {
			return true, nil
		}
	}
	return false, nil
}

// ownedByLongerNode reports whether crName is actually named after a
// DIFFERENT known node with a longer name — the "worker-1-gpu" vs
// "worker-1" prefix-collision guard: a bare HasPrefix match would
// let a CR that belongs to worker-1-gpu fence worker-1.
func ownedByLongerNode(crName, nodeName string, nodeNames map[string]bool) bool {
	for other := range nodeNames {
		if len(other) <= len(nodeName) {
			continue // only a strictly-longer name can steal the prefix
		}
		if crName == other || strings.HasPrefix(crName, other+"-") {
			return true
		}
	}
	return false
}

// probe is a single kube.KubeletHealthz attempt — a body starting
// with "ok" is healthy. No retries: the 30m Unknown window already
// absorbed transient wobble.
func (s *deadNodeSweeper) probe(ctx context.Context, nodeName string) (bool, error) {
	body, err := kube.KubeletHealthz(ctx, s.cs, nodeName)
	if err != nil {
		return false, err
	}
	return strings.HasPrefix(strings.TrimSpace(string(body)), "ok"), nil
}

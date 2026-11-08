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
	"io"
	"net"
	"net/url"
	"strings"
	"syscall"
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

// probeErrDeadEvidence classifies a KubeletHealthz probe error. The
// probe rides the apiserver's node-proxy tunnel, so err != nil hides
// two very different stories:
//
//   - DEAD evidence (true): the transport itself demonstrably failed
//     while asking the kubelet endpoint to answer —
//     context.DeadlineExceeded (nothing answered within
//     kubeletHealthzTimeout), connection refused/reset/unreachable
//     (syscall errors surfaced through *net.OpError / *url.Error),
//     or io.EOF / io.ErrUnexpectedEOF (connection torn down
//     mid-response). Ready=Unknown>30m plus a transport this dead is
//     a usable death certificate.
//
//   - INCONCLUSIVE (false): the APISERVER answered with an error —
//     HTTP >= 500 (its proxy could not reach the kubelet: exactly
//     what a one-way partition on the controller's side looks like,
//     even while a healthy kubelet keeps posting node status),
//     401/403 (RBAC on the proxy subresource), or an unparseable
//     response. None of these certify the kubelet dead, so the
//     caller fails closed instead of fencing.
func probeErrDeadEvidence(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	// net/http wraps transport failures as *url.Error around a
	// *net.OpError around the syscall error.
	var urle *url.Error
	if errors.As(err, &urle) {
		err = urle.Err
	}
	var ope *net.OpError
	if errors.As(err, &ope) {
		return errors.Is(ope.Err, syscall.ECONNREFUSED) ||
			errors.Is(ope.Err, syscall.ECONNRESET) ||
			errors.Is(ope.Err, syscall.EHOSTUNREACH)
	}
	return false
}

// confirmedDead is the safety gate — dead only with independent
// fencing evidence: (a) a medik8s remediation CR (viaSNR=true), or
// (b) Ready=Unknown>30m + a dead kubelet probe (viaSNR=false — no
// fencer has certified the death, so the caller owes the node the
// stateful split-brain gate before tainting). A probe error is only
// death evidence when it is transport-dead (probeErrDeadEvidence);
// apiserver-side errors (proxy 5xx, 401/403, unparseable) are
// inconclusive — the node is skipped this sweep, at Warn not Error.
// reason carries the evidence for the caller's logs; a dead=false
// result leaves it empty.
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
		if probeErrDeadEvidence(err) {
			// Transport-level failure — nothing answered the probe
			// (or the connection died mid-response). The kubelet
			// endpoint did not serve healthz: evidence, not a
			// module failure (same meaning the kubelet reaper's
			// DoRaw error carried).
			log.Info("fencing evidence: Ready=Unknown>30m + kubelet probe errored (transport dead)",
				"node", n.Name, "err", err)
			return true, false, "Ready=Unknown>30m + kubelet probe failed", nil
		}
		// The apiserver itself answered with an error (HTTP >= 500,
		// 401/403, unparseable body): that is the proxy PATH failing
		// — the one-way-partition shape where the kubelet may be
		// perfectly alive and posting status — so the error
		// certifies nothing about the kubelet. Fail closed: skip
		// the node this sweep, and Warn rather than Error (a
		// deliberately withheld verdict, not a fault).
		log.Info("probe error inconclusive — kubelet not certified dead, node skipped this sweep",
			"node", n.Name, "err", err)
		return false, false, "", nil
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

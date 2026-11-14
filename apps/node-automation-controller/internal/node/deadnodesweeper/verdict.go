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

// probeErrDeadEvidence classifies a KubeletHealthz probe error against
// the ambient sweep context. The probe rides the apiserver's
// node-proxy tunnel, so err != nil hides very different stories — and
// only one of them is about the kubelet:
//
//   - INCONCLUSIVE (false): everything that says the PATH or the
//     controller itself failed rather than the kubelet — the sweep
//     context already done (ctx.Err() != nil: shutdown/cycle
//     deadline, the probe result reflects the shutdown), RBAC 401/403
//     or rate-limit 429 (the APISERVER answered — the kubelet question
//     was never delivered), a controller↔apiserver transport failure
//     (dial refused/reset/unreachable, EOF mid-response: the kubelet
//     sits BEHIND the apiserver's konnectivity hop and cannot cause
//     these), a proxy 5xx that does not name the kubelet hop, or any
//     unparseable response. None of these certify the kubelet dead,
//     so the caller fails closed instead of fencing.
//
//   - DEAD evidence (true): the apiserver answered AND named the
//     kubelet hop as the failure — a proxy 500/502/503/504 whose
//     response text carries the node-proxy's unreachable-kubelet
//     markers ("error trying to reach service", "connection refused",
//     "no route to host", "i/o timeout"), or a per-request timeout
//     (context.DeadlineExceeded while ctx is still alive: the probe's
//     own 8s budget expired with nothing answering through the
//     tunnel). Ready=Unknown>30m plus evidence of this class is a
//     usable death certificate — subject to the sweep's healthy-node
//     canary check (confirmedDead) that rules out a global
//     konnectivity proxy outage.
func probeErrDeadEvidence(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	// The sweep context is already done — a shutdown/cancellation
	// error says nothing about the kubelet endpoint.
	if ctx.Err() != nil {
		return false
	}
	// RBAC (401/403) and rate-limit (429): the apiserver answered —
	// the kubelet question was never delivered.
	if apierrors.IsUnauthorized(err) || apierrors.IsForbidden(err) ||
		apierrors.IsTooManyRequests(err) {
		return false
	}
	// Per-request timeout: kubeletHealthz bounds each fetch with a
	// request-scoped .Timeout, so its expiry surfaces as
	// DeadlineExceeded while the ambient ctx is still alive — nothing
	// answered the tunnel hop. The ctx guard above already separated
	// this shape from a sweep cancellation (Canceled, or
	// DeadlineExceeded with ctx.Err() != nil).
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return proxyUnreachableKubelet(err)
}

// kubeletUnreachableMarkers are the body texts the apiserver's
// node-proxy handler emits when the proxy could not deliver the probe
// to the kubelet endpoint. A proxy 5xx carrying one of these names the
// kubelet hop itself as the failure — the one shape where a 5xx is
// kubelet evidence rather than a controller-side path failure.
var kubeletUnreachableMarkers = []string{
	"error trying to reach service",
	"connection refused",
	"no route to host",
	"i/o timeout",
}

// proxyUnreachableKubelet reports whether err is an apiserver proxy
// 500/502/503/504 whose response text names the kubelet hop. The raw
// marker text can sit in the Status message (client-go's generic
// >=500 response shape) or only in the UnexpectedServerResponse cause
// (503/504 rewrite the message), so both are searched.
func proxyUnreachableKubelet(err error) bool {
	var se *apierrors.StatusError
	if !errors.As(err, &se) {
		return false
	}
	st := se.Status()
	switch st.Code {
	case 500, 502, 503, 504:
	default:
		return false
	}
	parts := []string{st.Message}
	if st.Details != nil {
		for _, c := range st.Details.Causes {
			parts = append(parts, c.Message)
		}
	}
	text := strings.Join(parts, " ")
	for _, m := range kubeletUnreachableMarkers {
		if strings.Contains(text, m) {
			return true
		}
	}
	return false
}

// confirmedDead is the safety gate — dead only with independent
// fencing evidence: (a) a medik8s remediation CR (viaSNR=true), or
// (b) Ready=Unknown>30m + kubelet probe evidence of death (viaSNR=
// false — no fencer has certified the death, so the caller owes the
// node the stateful split-brain gate before tainting). A probe ERROR
// is only death evidence when probeErrDeadEvidence classifies it so
// AND the sweep's canary (one healthy Ready=True node name, "" when
// none exists) certifies the proxy path still answers: a global
// konnectivity proxy outage produces the identical per-node failure,
// and must never fence. Any other probe error is inconclusive — the
// node is skipped this sweep, at Info not Error. reason carries the
// evidence for the caller's logs; a dead=false result leaves it empty.
func (s *deadNodeSweeper) confirmedDead(ctx context.Context, n *corev1.Node,
	rem *remediationCache, nodeNames map[string]bool, canary string) (dead, viaSNR bool, reason string, err error) {
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
		// The apiserver's tunnel demonstrably failed while asking
		// THIS kubelet to answer — but only a canary that still gets
		// answers on the same path distinguishes a dead kubelet from
		// a globally broken konnectivity proxy (or a cluster-wide
		// Unknown wave, which has no Ready canary at all).
		if probeErrDeadEvidence(ctx, err) && s.canaryCertifies(ctx, canary) {
			log.Info("fencing evidence: Ready=Unknown>30m + kubelet probe errored (kubelet unreachable through proxy)",
				"node", n.Name, "err", err)
			return true, false, "Ready=Unknown>30m + kubelet probe failed", nil
		}
		// Anything else certifies nothing about the kubelet: the
		// proxy PATH failed (RBAC, rate limit, markerless 5xx,
		// controller↔apiserver transport, shutdown) or the canary
		// could not certify it — exactly the shape where the kubelet
		// may be perfectly alive and posting status. Fail closed:
		// skip the node this sweep, at Info not Error (a
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

// canaryCertifies runs the healthy-node canary probe: a transport-
// level verdict for the suspect is trustworthy only when the same
// proxy path just answered for a node that is Ready. A global
// konnectivity proxy outage produces the identical per-node failures
// everywhere — and no Ready node to certify the path (canary ""), so
// any canary failure, or the absence of a canary, leaves the verdict
// inconclusive.
func (s *deadNodeSweeper) canaryCertifies(ctx context.Context, canary string) bool {
	if canary == "" {
		return false // no Ready node to certify the proxy path
	}
	ok, err := s.probeFn(ctx, canary)
	return err == nil && ok
}

// healthyCanaryName picks the sweep's canary: the first Ready=True
// node in census order, or "" when no node is Ready — the empty result
// is itself the global-outage shape the canary check must be
// conservative about.
func healthyCanaryName(nodes []corev1.Node) string {
	for i := range nodes {
		if kube.NodeReady(&nodes[i]) {
			return nodes[i].Name
		}
	}
	return ""
}

// remediationNodeNameAnno is the annotation medik8s NHC (>= v0.6)
// stamps on remediation CRs it names "<nodeName>-<templateName>"
// (escalatingRemediations / multi-template setups) — the CR name no
// longer equals the node name, so the annotation carries the
// fencing target (medik8s-nhc-cr-names).
const remediationNodeNameAnno = "remediation.medik8s.io/node-name"

// remediationCache memoizes the once-per-sweep remediation CR
// listing.
type remediationCache = memo[[]unstructured.Unstructured]

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
	return rem.get(func() ([]unstructured.Unstructured, error) {
		var items []unstructured.Unstructured
		for _, gvr := range []schema.GroupVersionResource{
			selfNodeRemediationGVR, fenceAgentsRemediationGVR,
		} {
			page, err := kube.ListAll(ctx,
				metav1.ListOptions{Limit: kube.DefaultListPageSize},
				kube.DynamicPage(s.dyn.Resource(gvr).Namespace(metav1.NamespaceAll)))
			if err != nil {
				if kube.IsCRDAbsent(err) {
					continue // CRD not installed on this cluster
				}
				return nil, fmt.Errorf("list %s: %w", gvr.Resource, err)
			}
			items = append(items, page...)
		}
		return items, nil
	})
}

// hasRemediationCR reports whether any medik8s remediation object
// targets the node AND has actually fenced it: the remediation.medik8s.io/node-name
// annotation (AUTHORITATIVE when present — a CR stamped for another node is
// never evidence here), CR name == node name (the 1:1 shape both
// CRDs historically use), or a "<nodeName>-" name prefix (the
// template-suffixed shape NHC v0.6+ emits). The prefix fallback is
// guarded by the known node set: a CR like "worker-1-gpu" or
// "worker-1-gpu-<tpl>" belongs to the node worker-1-gpu, and a bare
// HasPrefix match would otherwise let it fence worker-1.
//
// P1 fix: CR EXISTENCE is not fencing. A SelfNodeRemediation or
// FenceAgentsRemediation is created when the drain STARTS and only
// certifies the node once its status conditions report success —
// treating mere existence as fenced skipped the stateful-holder
// split-brain gate at the 15m mark while medik8s was still mid-
// drain on a node that could come back and corrupt RWO/RWOP volumes.
// A matched CR without a Succeeded condition (still running, failed,
// or conditions not yet reconciled) is NOT evidence; the caller
// falls through to the probe path and owes the stateful gate.
func (s *deadNodeSweeper) hasRemediationCR(ctx context.Context, nodeName string,
	rem *remediationCache, nodeNames map[string]bool) (bool, error) {
	items, err := s.remediationItems(ctx, rem)
	if err != nil {
		return false, err
	}
	for i := range items {
		cr := &items[i]
		if cr.GetDeletionTimestamp() != nil {
			continue // being deleted — stale evidence, not a live fence
		}
		crName := cr.GetName()
		matched := false
		if anno := cr.GetAnnotations()[remediationNodeNameAnno]; anno != "" {
			// The annotation is the fencing target — when it is
			// present it decides alone: no name or prefix match can
			// override it (a "worker-1-gpu-<tpl>" CR annotated for
			// worker-1-gpu must not fence worker-1).
			matched = anno == nodeName
		} else if crName == nodeName {
			matched = true
		} else if strings.HasPrefix(crName, nodeName+"-") &&
			!ownedByLongerNode(crName, nodeName, nodeNames) {
			matched = true
		}
		if matched && remediationCRSucceeded(cr) {
			return true, nil
		}
	}
	return false, nil
}

// remediationCRSucceeded reports whether the remediation CR's status
// conditions certify the fence/drain COMPLETED: a condition whose
// type ends in "Succeeded" (medik8s SNR reports "Succeeded";
// FenceAgentsRemediation reports "FenceAgentSucceeded") reading
// True. A "Failed"=True condition is an explicit non-success — the
// remediation gave up, which is the opposite of fencing evidence.
// CRs with no conditions yet (just created, status unreconciled)
// read as not-fenced.
func remediationCRSucceeded(cr *unstructured.Unstructured) bool {
	conds, found, err := unstructured.NestedSlice(cr.Object,
		"status", "conditions")
	if err != nil || !found {
		return false
	}
	for _, c := range conds {
		m, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		typ, _ := m["type"].(string)
		status, _ := m["status"].(string)
		if strings.HasSuffix(typ, "Succeeded") {
			return status == "True"
		}
	}
	return false
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

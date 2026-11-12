// secret_probe.go — the resourceVersion-keyed target-Secret probe
// cache of externalsecret-nudge (item J): one metadata LIST per
// ExternalSecret namespace per pass replaces the per-ES
// Secrets().Get whenever the Secret's resourceVersion is unchanged
// — the steady state costs 0 GETs/hour instead of 2 per ES per pass.
//
// Correctness contract: a cached verdict is replayed ONLY while
// every input that produced it is provably unchanged — the ES's own
// resourceVersion (any spec/status write bumps it), the target
// Secret's UID (delete+recreate), and its resourceVersion (any Data
// write). An empty resourceVersion is treated as unverifiable and
// never validates a cache entry — fake clientsets that leave RVs
// blank degrade to the previous live-Get-every-pass behavior
// instead of risking a stale verdict. A Secret absent from a
// freshly-built namespace index needs no Get at all: the LIST
// itself is this pass's authoritative answer.
package externalsecretnudge

import (
	"bytes"
	"context"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// secretGVR is the core/v1 Secret resource the probe index lists —
// typedFallbackCovers already maps it onto the typed clientset, so
// test fakes answer the metadata path without a metadata client.
var secretGVR = schema.GroupVersionResource{
	Group:    "",
	Version:  "v1",
	Resource: "secrets",
}

// secretMeta is one index row: the Secret identity fields the
// verdict cache validates against — everything else about the
// Secret is unknowable until its RV actually moves.
type secretMeta struct {
	uid types.UID
	rv  string
}

// probeStatus is the three-way outcome of one target-Secret probe —
// mirrors kube.ConfirmAbsent's shape so callers keep the same
// NotFound-silent / error-IncError / ok-proceed split the direct
// Get used to produce.
type probeStatus int

const (
	probeOK probeStatus = iota
	probeNotFound
	probeError
)

// esSecretVerdict is the cached outcome of inspecting one
// ExternalSecret's target Secret .Data — the empty-key audit set
// AND the empty-skeleton eligibility in one entry, since both
// derive from the same (es, secret) pair. Valid only while
// validFor() confirms every input RV/UID is unchanged.
type esSecretVerdict struct {
	esRV       string
	targetName string
	secretUID  types.UID
	secretRV   string
	// emptyKeys is the auditEmptySecretKeys verdict — target key →
	// the reason string flagEmptyKey logs. nil = no empty keys.
	emptyKeys map[string]string
	// skeleton is true when the Secret qualified as an
	// empty ESO-owned skeleton (len(Data)==0 + ownerRef match);
	// skeletonUID is the UID deleteEmptySkeletonSecret
	// preconditions its Delete on. A separate bool because a
	// fixture/real Secret can legitimately carry an empty UID —
	// "UID unset" must not read as "not a skeleton".
	skeleton    bool
	skeletonUID types.UID
}

// validFor reports whether this verdict still describes the live
// (es, secret) pair: same ES resourceVersion, same resolved target
// name, same Secret UID and resourceVersion — and both RVs
// non-empty, because an unverifiable version can never prove
// "unchanged".
func (v *esSecretVerdict) validFor(esRV, targetName string,
	uid types.UID, rv string) bool {
	return v.esRV != "" && v.secretRV != "" &&
		v.esRV == esRV && v.targetName == targetName &&
		v.secretUID == uid && v.secretRV == rv
}

// buildSecretIndex lists Secrets once per ExternalSecret namespace
// through ListPartialOrFallback — the metadata endpoint in
// production, the typed/dynamic fallback under fakes — and records
// each namespace's success separately: a namespace whose LIST
// failed stays out of secretIndexOK so its probes degrade to live
// Gets instead of trusting a partial census. List failures are
// tolerated (IncError + fallback): the module keeps working on
// clusters whose RBAC grants secret Get but not List.
func (n *externalSecretNudge) buildSecretIndex(ctx context.Context,
	namespaces map[string]bool) {

	log := logf.FromContext(ctx)
	n.secretIndex = map[string]secretMeta{}
	n.secretIndexOK = map[string]bool{}
	for ns := range namespaces {
		items, err := kube.ListPartialOrFallback(ctx, n.meta, n.cs, n.dyn,
			secretGVR, ns,
			metav1.ListOptions{Limit: kube.DefaultListPageSize})
		if err != nil {
			metrics.IncError(n.queue)
			log.Error(err, "secret index list failed — target-secret probes fall back to live GETs",
				"namespace", ns)
			continue
		}
		n.secretIndexOK[ns] = true
		for i := range items {
			p := &items[i]
			n.secretIndex[p.GetNamespace()+"/"+p.GetName()] =
				secretMeta{uid: p.GetUID(), rv: p.GetResourceVersion()}
		}
	}
}

// esProbeNamespaces collects the distinct namespaces the ExternalSecret
// list touches — the index only pays LISTs where a target Secret can
// actually live (the target always sits in the ES's own namespace).
func esProbeNamespaces(list *unstructured.UnstructuredList) map[string]bool {
	out := map[string]bool{}
	for i := range list.Items {
		if ns := list.Items[i].GetNamespace(); ns != "" {
			out[ns] = true
		}
	}
	return out
}

// secretVerdict returns the .Data inspection verdict for one
// ExternalSecret's target Secret — from the RV-keyed persistent
// cache when every input is provably unchanged (the common case:
// 0 API reads), from a live Get on any miss, or probeNotFound when
// this pass's fresh index proves the Secret absent. probeError
// carries the underlying Get error for the caller's log.
func (n *externalSecretNudge) secretVerdict(ctx context.Context,
	es *unstructured.Unstructured) (*esSecretVerdict, probeStatus, error) {

	ns, name := es.GetNamespace(), es.GetName()
	target := esTargetSecretName(es)
	esRV := es.GetResourceVersion()
	esKey := ns + "/" + name

	// Index hit: this pass's LIST already proved the Secret exists
	// with a concrete UID/RV — a matching cache entry replays with
	// ZERO reads. An empty index RV can never validate (validFor),
	// so fake-client fixtures degrade to the live-Get path.
	if n.secretIndexOK[ns] {
		if meta, ok := n.secretIndex[ns+"/"+target]; !ok {
			return nil, probeNotFound, nil // fresh LIST says absent — authoritative this pass
		} else if v, hit := n.secretVerdicts[esKey]; hit &&
			v.validFor(esRV, target, meta.uid, meta.rv) {
			return &v, probeOK, nil
		}
	}

	// Miss (or unverifiable index): the live Get is the fallback —
	// identical to the pre-cache behavior, still memoized within
	// the pass by secretReads.
	secret, err := n.readTargetSecret(ctx, ns, target)
	switch {
	case apierrors.IsNotFound(err):
		return nil, probeNotFound, nil
	case err != nil:
		return nil, probeError, err
	}
	v := n.buildSecretVerdict(es, target, secret)
	if n.secretVerdicts == nil {
		n.secretVerdicts = map[string]esSecretVerdict{}
	}
	n.secretVerdicts[esKey] = *v
	return v, probeOK, nil
}

// buildSecretVerdict computes both consumer verdicts from one live
// Secret read — the empty-key audit set and the empty-skeleton
// eligibility — so a single Get serves auditEmptySecretKeys and
// deleteEmptySkeletonSecret alike.
func (n *externalSecretNudge) buildSecretVerdict(es *unstructured.Unstructured,
	target string, secret *corev1.Secret) *esSecretVerdict {

	v := &esSecretVerdict{
		esRV:       es.GetResourceVersion(),
		targetName: target,
		secretUID:  secret.UID,
		secretRV:   secret.ResourceVersion,
	}
	// Skeleton eligibility — the deleteEmptySkeletonSecret contract:
	// len(Data)==0 AND a controller ownerRef proving THIS ExternalSecret
	// (same name AND UID — a recreated ES never inherits the old
	// Secret's skeleton verdict).
	if len(secret.Data) == 0 {
		for _, or := range secret.OwnerReferences {
			if or.Kind == "ExternalSecret" && or.Name == es.GetName() &&
				or.UID == es.GetUID() {
				v.skeleton = true
				v.skeletonUID = secret.UID
				break
			}
		}
	}
	// Empty-key audit verdict — declared keys absent from Data plus
	// present-but-blank keys; the data pass runs second so its reason
	// wins on overlap, exactly as the two sequential flagEmptyKey
	// calls did.
	empty := map[string]string{}
	for k := range esDeclaredKeys(es) {
		if _, present := secret.Data[k]; !present {
			empty[k] = "declared key missing from target secret"
		}
	}
	for k, val := range secret.Data {
		if len(bytes.TrimSpace(val)) == 0 {
			empty[k] = "key is empty/whitespace-only"
		}
	}
	if len(empty) > 0 {
		v.emptyKeys = empty
	}
	return v
}

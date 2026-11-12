// helm_secret_prune.go — the shared superseded-helm-release-secret
// prune. Two modules run the same documented duplicate of this logic
// and both now call this helper:
//
//   - helmrelease-unlocker (integration/helmreleaseunlocker, 10m):
//     the kine-bloat-guard hygiene sweep. Helm writes one
//     sh.helm.release.v1 Secret per revision and never
//     garbage-collects the superseded ones — each embeds the full
//     compressed chart, so a frequently-upgraded release grows Kine
//     (and the storage backend behind it) without bound.
//   - api-object-sprawl-report-gc (health/nodehealth, 5m): the same
//     prune folded into the helm_release_secrets census — its read is
//     load-bearing beyond the deletes (the census gauge + sprawl
//     report findings), so it cannot drop or defer the scan.
//
// NOTE on the deliberate duplication (kept verbatim from both
// sides): neither consumer can drop its cluster-wide read. The
// unlocker cannot reuse its own unlock path's per-HR lists (they are
// namespace+release scoped and only run for HRs stuck past the
// threshold), and scoping to HelmRelease namespaces would miss
// plain-helm releases or fan out one LIST per namespace. The sprawl
// check's list feeds the api_object_count census and findings, so
// dropping or deferring it would change the report, not just the
// deletes. There is no helm-release-namespace index to scope either
// list to (a per-namespace fan-out would replace one paged LIST
// with N). The trees cannot share a live read either (different
// sweep ctx and cadence) — but the SELECTION and DELETE policy is
// one contract, enforced here.
package helmprune

import (
	"context"
	"sort"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// helmReleaseSecretType is the Secret type helm writes per revision.
const helmReleaseSecretType = "helm.sh/release.v1"

// HelmSecretPruneHooks carries the site-specific side effects of the
// shared prune — logging posture (shell-parity DELETE/ACTION lines),
// per-site metrics and report findings stay with the caller, the
// selection and delete policy do not. All hooks are optional; a nil
// hook is skipped.
type HelmSecretPruneHooks struct {
	// Excess fires once per release whose superseded secrets exceed
	// the cap, BEFORE any delete — the census consumer's excess
	// gauge + sprawl-report finding land here.
	Excess func(ns, release string, superseded, cap int)
	// PreDelete fires just before each candidate delete is issued —
	// the unlocker's shell-parity ACTION line lives here.
	PreDelete func(s *corev1.Secret, version, supersededTotal int)
	// Deleted fires after each successful delete — the per-namespace
	// pruned-counter increment and the DELETE log live here.
	Deleted func(s *corev1.Secret, version int)
	// DeleteFailed fires for non-NotFound delete failures; the
	// next-oldest candidate is still tried.
	DeleteFailed func(s *corev1.Secret, err error)
}

// helmSecretsGVR is the core/v1 secrets GVR the metadata read lists —
// helm release secrets are plain kube.Secrets, so no dedicated GVR exists.
var helmSecretsGVR = corev1.SchemeGroupVersion.WithResource("secrets")

// PruneSupersededHelmSecrets caps the superseded helm release secrets
// kept per release, deleting the OLDEST excess with a UID
// precondition, and returns the helm-typed secrets it listed (the
// census consumer counts them into api_object_count).
//
// The read is cluster-wide and server-side filtered to SUPERSEDED
// revisions — owner=helm is the same label the unlocker's unlock()
// selects on, and every superseded revision also carries
// status=superseded (helm v3's standard pair, same labels the test
// fixtures build), so the live deployed/pending/failed revisions
// never cross the wire. The per-release `highest` computation then
// runs over superseded revisions only: the delete set is unchanged —
// the "never touch the newest rollback point" guard still skips the
// top superseded revision, and a live deployed revision was never a
// candidate anyway. Paged like every cluster-wide list here.
//
// For every release — grouped by storage namespace + the `name`
// label, the same identity unlock() scopes its revision scan to —
// secrets with status=="superseded" and a valid integer `version`
// label are sorted ascending; when a release holds more than
// maxSuperseded the OLDEST excess are deleted with a UID
// precondition. deployed, pending-*, and failed secrets are NEVER
// touched — they are live install/rollback state, not history — and
// neither is the highest-version secret of the release, which stays
// the newest rollback point even when it is itself superseded. A
// NotFound delete means another actor won the race — the prune goal
// is met, not an error.
//
// Only the LIST error is returned (the caller owns its failure
// posture); delete failures surface through hooks.DeleteFailed and
// never abort the sweep.
//
// This is the typed-only entry kept for callers that have no
// metadata client to hand (and every fake-clientset unit test):
// meta/dyn are nil, so the read stays the typed kube.ListAll. Callers
// holding a metadata.Interface (Deps.Meta / the check's p.Meta)
// should call PruneSupersededHelmSecretsMeta instead — same
// contract, metadata-only wire read.
func PruneSupersededHelmSecrets(ctx context.Context,
	cs kubernetes.Interface, maxSuperseded int,
	hooks HelmSecretPruneHooks) ([]corev1.Secret, error) {

	return PruneSupersededHelmSecretsMeta(ctx, nil, cs, nil,
		maxSuperseded, hooks)
}

// PruneSupersededHelmSecretsMeta is PruneSupersededHelmSecrets with
// the metadata client threaded through: meta feeds
// kube.ListPartialOrFallback's preferred read (PartialObjectMetadata —
// ObjectMeta WITHOUT the compressed chart payload each revision
// embeds, so a cluster-wide scan no longer decodes thousands of
// .Data blobs into the heap just to count namespaces), cs serves
// the typed fallback when meta cannot, and dyn is the last-resort
// fallback for a metadata client that cannot serve the GVR.
func PruneSupersededHelmSecretsMeta(ctx context.Context,
	meta metadata.Interface, cs kubernetes.Interface,
	dyn dynamic.Interface, maxSuperseded int,
	hooks HelmSecretPruneHooks) ([]corev1.Secret, error) {

	// The field selector pushes the Secret.type filter to the
	// apiserver — helm release secrets are a tiny slice of the
	// secrets table, and the compressed chart payloads behind every
	// other type never cross the wire.
	opts := metav1.ListOptions{
		LabelSelector: "owner=helm,status=superseded",
		FieldSelector: "type=" + helmReleaseSecretType,
		Limit:         kube.DefaultListPageSize}

	var secrets []corev1.Secret
	var err error
	if meta != nil {
		secrets, err = listHelmSecretsPartial(ctx, meta, cs, dyn, opts)
	} else {
		secrets, err = listHelmSecretsTyped(ctx, cs, opts)
	}
	if err != nil {
		return nil, err
	}
	// Group by storage namespace + release name. Values, not
	// pointers: byRelease must not pin pointers into the
	// cluster-wide `secrets` backing array — `secrets = nil` below
	// is only a real release once nothing references its elements.
	type relKey struct{ ns, name string }
	byRelease := map[relKey][]corev1.Secret{}
	var helmTyped []corev1.Secret
	for i := range secrets {
		s := &secrets[i]
		helmTyped = append(helmTyped, *s)
		if release := s.Labels["name"]; release != "" {
			k := relKey{s.Namespace, release}
			byRelease[k] = append(byRelease[k], *s)
		}
	}
	secrets = nil // release the cluster-wide slice before issuing deletes

	type supersededSecret struct {
		s *corev1.Secret
		v int
	}
	for k, relSecrets := range byRelease {
		// Highest revision across ALL statuses — the one secret that
		// is never pruned even when it is itself superseded.
		highest := -1
		var superseded []supersededSecret
		for i := range relSecrets {
			s := &relSecrets[i]
			v, err := strconv.Atoi(s.Labels["version"])
			if err != nil {
				continue // unversioned — never ours to judge
			}
			if v > highest {
				highest = v
			}
			if s.Labels["status"] == "superseded" {
				superseded = append(superseded, supersededSecret{s, v})
			}
		}
		excess := len(superseded) - maxSuperseded
		if excess <= 0 {
			continue
		}
		if hooks.Excess != nil {
			hooks.Excess(k.ns, k.name, len(superseded), maxSuperseded)
		}
		sort.Slice(superseded, func(i, j int) bool {
			return superseded[i].v < superseded[j].v
		})
		toDelete := excess
		for _, cand := range superseded {
			if toDelete <= 0 {
				break
			}
			if cand.v == highest {
				continue // never touch the highest-version secret
			}
			if hooks.PreDelete != nil {
				hooks.PreDelete(cand.s, cand.v, len(superseded))
			}
			err := cs.CoreV1().Secrets(cand.s.Namespace).Delete(ctx,
				cand.s.Name, kube.UIDDeleteOptions(cand.s.UID, ""))
			if apierrors.IsNotFound(err) {
				// Already gone — another actor won the race; the
				// prune goal for this slot is met, so it still
				// counts toward toDelete. Skipping the decrement
				// would delete one secret too many — a newer
				// revision than the cap requires.
				toDelete--
				continue
			}
			if err != nil {
				if hooks.DeleteFailed != nil {
					hooks.DeleteFailed(cand.s, err)
				}
				continue // try the next-oldest instead of giving up
			}
			if hooks.Deleted != nil {
				hooks.Deleted(cand.s, cand.v)
			}
			toDelete--
		}
	}
	return helmTyped, nil
}

// listHelmSecretsPartial is the metadata-client read: every listed
// object arrives as PartialObjectMetadata — ObjectMeta only, no
// .Data — which is the entire point of the helper (a typed LIST
// decodes each revision's compressed chart before the prune can
// drop it). Secret.Type is not ObjectMeta and cannot cross the
// metadata endpoint, so the projected kube.Secrets carry the helm type
// the field selector already guaranteed server-side; on the
// unfiltered BadRequest retry the owner=helm,status=superseded
// label pair is the remaining guard (same exposure the typed
// path's client-side check covers for fakes — a secret wearing
// helm's full label set is already impersonating a revision).
func listHelmSecretsPartial(ctx context.Context,
	meta metadata.Interface, cs kubernetes.Interface,
	dyn dynamic.Interface, opts metav1.ListOptions) ([]corev1.Secret, error) {

	poms, err := kube.ListPartialOrFallback(ctx, meta, cs, dyn,
		helmSecretsGVR, metav1.NamespaceAll, opts)
	if err != nil && apierrors.IsBadRequest(err) {
		// A field-selector-unsupported apiserver answers 400 —
		// retry unfiltered rather than fail the sweep on what was
		// only a wire-bytes optimization (mirrors the typed path).
		opts.FieldSelector = ""
		poms, err = kube.ListPartialOrFallback(ctx, meta, cs, dyn,
			helmSecretsGVR, metav1.NamespaceAll, opts)
	}
	if err != nil {
		return nil, err
	}
	secrets := make([]corev1.Secret, 0, len(poms))
	for i := range poms {
		secrets = append(secrets, corev1.Secret{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Secret",
				APIVersion: "v1",
			},
			ObjectMeta: poms[i].ObjectMeta,
			Type:       corev1.SecretType(helmReleaseSecretType),
		})
	}
	return secrets, nil
}

// listHelmSecretsTyped is the no-metadata-client read — the path
// every fake-clientset unit test takes. It stays a typed kube.ListAll
// (NOT kube.ListPartialOrFallback's typed fallback, which would project
// to PartialObjectMetadata and lose Secret.Type): the client-side
// Type filter is load-bearing here because fakes do not enforce
// field selectors — the Opaque-typed decoy fixtures rely on it.
// .Data still decodes on this path, but it only ever serves tests
// and meta-less degraded wiring; production always has Deps.Meta.
func listHelmSecretsTyped(ctx context.Context, cs kubernetes.Interface,
	opts metav1.ListOptions) ([]corev1.Secret, error) {

	raw, err := kube.ListAll(ctx, opts, kube.Secrets(cs, metav1.NamespaceAll))
	if err != nil && apierrors.IsBadRequest(err) {
		// Same defensive retry as before: the client-side Type
		// filter already guarantees correctness, so an apiserver
		// that rejects the field selector costs wire bytes, not
		// the sweep.
		opts.FieldSelector = ""
		raw, err = kube.ListAll(ctx, opts, kube.Secrets(cs, metav1.NamespaceAll))
	}
	if err != nil {
		return nil, err
	}
	secrets := make([]corev1.Secret, 0, len(raw))
	for i := range raw {
		s := &raw[i]
		if s.Type != corev1.SecretType(helmReleaseSecretType) {
			continue
		}
		// The decision needs only metadata — each revision embeds
		// the compressed chart (MBs). Drop the payload before the
		// byRelease grouping pins it in RAM for the whole sweep;
		// deletes and the census count namespaces/labels only.
		s.Data = nil
		secrets = append(secrets, *s)
	}
	return secrets, nil
}

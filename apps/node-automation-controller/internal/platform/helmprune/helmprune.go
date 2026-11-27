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
	"cmp"
	"context"
	"slices"
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
// kept per release (and prunes stale failed revisions strictly older
// than the currently deployed revision), deleting the OLDEST excess
// with a UID precondition, and returns the helm-typed secrets it listed
// (the census consumer counts them into api_object_count).
//
// The read is cluster-wide and server-side filtered to owner=helm +
// type=helm.sh/release.v1 via PartialObjectMetadata so zero .Data
// crosses the wire while still seeing deployed, superseded, failed,
// and pending-* revisions per release.
//
// For every release — grouped by storage namespace + the `name` label,
// the same identity unlock() scopes its revision scan to — we first
// compute highestDeployed (max integer `version` with
// status=="deployed", or -1 if none exists):
//   - status=="deployed", status=="pending-*", and any revision
//     v >= highestDeployed (when highestDeployed >= 0) are NEVER touched.
//   - status=="failed" with v < highestDeployed is always pruned (stale
//     failed attempts superseded by a later deployed revision); when
//     highestDeployed < 0 (e.g. failed initial install), failed secrets
//     are NEVER deleted so operators keep them for debugging.
//   - status=="superseded" (with v < highestDeployed when deployed
//     exists) is sorted ascending and pruned oldest-first down to
//     keepCap (which largeCap can tighten to 0 when highestDeployed >= 0
//     and the release's serialized JSON size reaches largeCap.Threshold).
//     When highestDeployed < 0, the highest superseded revision is always
//     preserved as the sole fallback rollback point.
//
// A NotFound delete means another actor won the race — the prune goal
// is met, not an error. Only the LIST error is returned (the caller
// owns its failure posture); delete failures surface through
// hooks.DeleteFailed and never abort the sweep.
//
// This is the typed-only entry kept for callers that have no
// metadata client to hand (and every fake-clientset unit test):
// meta/dyn are nil, so the read stays the typed kube.ListAll. Callers
// holding a metadata.Interface (Deps.Meta / the check's p.Meta)
// should call PruneSupersededHelmSecretsMeta or
// PruneSupersededHelmSecretsMetaWithCap instead — same contract,
// metadata-only wire read.
func PruneSupersededHelmSecrets(ctx context.Context,
	cs kubernetes.Interface, maxSuperseded int,
	hooks HelmSecretPruneHooks) ([]corev1.Secret, error) {

	return PruneSupersededHelmSecretsMeta(ctx, nil, cs, nil,
		maxSuperseded, hooks)
}

// DefaultLargeSecretThreshold is the 512 KiB serialized-JSON row guard
// matching sprawl's kineLargeObjectThreshold (512 KiB).
const DefaultLargeSecretThreshold = 512 * 1024

// DefaultLargeSecretCap tightens oversized (>= 512 KiB serialized JSON)
// Helm release secrets to keep 0 superseded revisions whenever a live
// deployed revision exists (matching maxHistory: 1 and clearing
// KineLargeObjectDetected automatically).
var DefaultLargeSecretCap = LargeSecretCap{
	Threshold:     DefaultLargeSecretThreshold,
	MaxSuperseded: 0,
}

// LargeSecretCap tightens maxSuperseded for releases whose serialized
// JSON Secret size reaches Threshold bytes (e.g. >=512 KiB Kine
// large-object guard, matching kube.JSONSize / kine_large_objects.go)
// so giant charts do not retain multi-hundred-KiB rows in Kine. A zero
// Threshold disables size-based tightening.
type LargeSecretCap struct {
	Threshold     int
	MaxSuperseded int
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

	return PruneSupersededHelmSecretsMetaWithCap(ctx, meta, cs, dyn,
		maxSuperseded, LargeSecretCap{}, hooks)
}

// PruneSupersededHelmSecretsMetaWithCap extends PruneSupersededHelmSecretsMeta
// with an optional tighter keep cap for releases whose serialized JSON
// secret size reaches largeCap.Threshold bytes.
func PruneSupersededHelmSecretsMetaWithCap(ctx context.Context,
	meta metadata.Interface, cs kubernetes.Interface,
	dyn dynamic.Interface, maxSuperseded int,
	largeCap LargeSecretCap,
	hooks HelmSecretPruneHooks) ([]corev1.Secret, error) {

	// The field selector pushes the Secret.type filter to the
	// apiserver — helm release secrets are a tiny slice of the
	// secrets table, and the compressed chart payloads behind every
	// other type never cross the wire. Selecting owner=helm (without
	// status=superseded) lets us see deployed and failed revisions
	// per release while still transferring zero .Data via
	// PartialObjectMetadata.
	opts := metav1.ListOptions{
		LabelSelector: "owner=helm",
		FieldSelector: "type=" + helmReleaseSecretType,
		Limit:         kube.DefaultListPageSize}

	var secrets []corev1.Secret
	var dataSizes map[string]int
	var err error
	if meta != nil {
		secrets, err = listHelmSecretsPartial(ctx, meta, cs, dyn, opts)
	} else {
		secrets, dataSizes, err = listHelmSecretsTyped(ctx, cs, opts, largeCap.Threshold > 0)
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

	type revisionSecret struct {
		s *corev1.Secret
		v int
	}
	for k, relSecrets := range byRelease {
		// Pass 1: find highestDeployed (max version with status=="deployed").
		highestDeployed := -1
		for i := range relSecrets {
			s := &relSecrets[i]
			if s.Labels["status"] != "deployed" {
				continue
			}
			v, err := strconv.Atoi(s.Labels["version"])
			if err != nil {
				continue
			}
			if v > highestDeployed {
				highestDeployed = v
			}
		}

		// Pass 2: collect prunable superseded and stale failed revisions.
		// Never touch deployed, pending-*, or any revision v >= highestDeployed.
		// When highestDeployed < 0, never touch failed revisions and record
		// highestSuperseded so the newest superseded revision stays protected.
		highestSuperseded := -1
		var highestSupersededSec *corev1.Secret
		var superseded []revisionSecret
		var oldFailed []revisionSecret
		for i := range relSecrets {
			s := &relSecrets[i]
			v, err := strconv.Atoi(s.Labels["version"])
			if err != nil {
				continue // unversioned — never ours to judge
			}
			if highestDeployed >= 0 && v >= highestDeployed {
				continue
			}
			switch s.Labels["status"] {
			case "superseded":
				superseded = append(superseded, revisionSecret{s, v})
				if v > highestSuperseded {
					highestSuperseded = v
					highestSupersededSec = s
				}
			case "failed":
				if highestDeployed >= 0 {
					oldFailed = append(oldFailed, revisionSecret{s, v})
				}
			}
		}

		deleteCandidate := func(cand revisionSecret, total int) bool {
			if hooks.PreDelete != nil {
				hooks.PreDelete(cand.s, cand.v, total)
			}
			err := cs.CoreV1().Secrets(cand.s.Namespace).Delete(ctx,
				cand.s.Name, kube.UIDDeleteOptions(cand.s.UID, ""))
			if apierrors.IsNotFound(err) {
				// Already gone — another actor won the race; the
				// prune goal for this slot is met.
				return true
			}
			if err != nil {
				if hooks.DeleteFailed != nil {
					hooks.DeleteFailed(cand.s, err)
				}
				return false // try the next-oldest instead of giving up
			}
			if hooks.Deleted != nil {
				hooks.Deleted(cand.s, cand.v)
			}
			return true
		}

		// Prune all stale failed revisions strictly older than highestDeployed.
		if len(oldFailed) > 0 {
			slices.SortFunc(oldFailed, func(a, b revisionSecret) int {
				return cmp.Compare(a.v, b.v)
			})
			for _, cand := range oldFailed {
				deleteCandidate(cand, len(oldFailed))
			}
		}

		keepCap := maxSuperseded
		effectiveLargeCap := largeCap.MaxSuperseded
		if highestDeployed < 0 && effectiveLargeCap < 1 {
			// No deployed revision exists — keep the highest superseded
			// revision as a fallback rollback point and avoid spurious
			// excess findings when only that single revision remains.
			effectiveLargeCap = 1
		}
		if largeCap.Threshold > 0 && effectiveLargeCap < keepCap &&
			len(superseded) > effectiveLargeCap {
			isLarge := false
			if dataSizes != nil {
				for _, cand := range superseded {
					if dataSizes[cand.s.Namespace+"/"+cand.s.Name] >= largeCap.Threshold {
						isLarge = true
						break
					}
				}
			} else if highestSupersededSec != nil {
				// PartialObjectMetadata omits .Data — fetch only the
				// newest prunable superseded revision for releases above
				// effectiveLargeCap to measure its serialized JSON size
				// (matching kine_large_objects.go 1:1).
				if full, gerr := cs.CoreV1().Secrets(highestSupersededSec.Namespace).
					Get(ctx, highestSupersededSec.Name, metav1.GetOptions{}); gerr == nil {
					isLarge = secretJSONSize(full) >= largeCap.Threshold
				}
			}
			if isLarge {
				keepCap = effectiveLargeCap
			}
		}
		excess := len(superseded) - keepCap
		if excess <= 0 {
			continue
		}
		if hooks.Excess != nil {
			hooks.Excess(k.ns, k.name, len(superseded), keepCap)
		}
		slices.SortFunc(superseded, func(a, b revisionSecret) int {
			return cmp.Compare(a.v, b.v)
		})
		toDelete := excess
		for _, cand := range superseded {
			if toDelete <= 0 {
				break
			}
			if highestDeployed < 0 && cand.v == highestSuperseded {
				continue // no deployed revision — never delete the highest superseded secret
			}
			if deleteCandidate(cand, len(superseded)) {
				toDelete--
			}
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
// unfiltered BadRequest retry the owner=helm label is the remaining
// guard (same exposure the typed path's client-side check covers for
// fakes — a secret wearing helm's full label set is already
// impersonating a revision).
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

// secretJSONSize returns s's serialized JSON byte size via kube.JSONSize,
// matching sprawl's kine_large_objects.go 1:1 (including base64 expansion
// of Secret.Data, which adds ~33% over raw len(v), plus ObjectMeta).
func secretJSONSize(s *corev1.Secret) int {
	if n, err := kube.JSONSize(s); err == nil {
		return int(n)
	}
	n := 0
	for _, v := range s.Data {
		n += ((len(v) + 2) / 3) * 4
	}
	for _, v := range s.StringData {
		n += len(v)
	}
	return n
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
	opts metav1.ListOptions, recordSizes bool) ([]corev1.Secret, map[string]int, error) {

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
		return nil, nil, err
	}
	secrets := make([]corev1.Secret, 0, len(raw))
	var sizes map[string]int
	if recordSizes {
		sizes = make(map[string]int, len(raw))
	}
	for i := range raw {
		s := &raw[i]
		if s.Type != corev1.SecretType(helmReleaseSecretType) {
			continue
		}
		if recordSizes {
			sizes[s.Namespace+"/"+s.Name] = secretJSONSize(s)
		}
		// The decision needs only metadata — each revision embeds
		// the compressed chart (MBs). Drop the payload before the
		// byRelease grouping pins it in RAM for the whole sweep;
		// deletes and the census count namespaces/labels only.
		s.Data = nil
		secrets = append(secrets, *s)
	}
	return secrets, sizes, nil
}

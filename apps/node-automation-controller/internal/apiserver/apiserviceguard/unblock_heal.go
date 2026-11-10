// unblock_heal.go — duty (c) of apiservice-guard, the namespace-terminating-wedged
// dead-APIService unblocker: an aggregated APIService in a protected
// namespace that stays Available=False wedges every namespace
// termination whose GC still references its API group, so the sweep
// restarts the backing Service's pods — maintenance-gated,
// UID-preconditioned, capped, and cooled down per APIService. Its
// state (the per-APIService heal cooldown) lives on unblockHealer;
// shared deps are reached through snap.g.
package apiserviceguard

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

const (
	// namespace-terminating-wedged — dead-APIService unblocker. An aggregated APIService
	// in a protected namespace that stays Available=False wedges
	// every namespace termination whose GC still references its API
	// group. The unblock pass is the ONLY path allowed to restart
	// those backends, and only when the wedge is proven: unavailable
	// >=15m AND a namespace stuck Terminating >=15m whose
	// conditions/events name the group.
	apiServiceUnblockMinAge   = 15 * time.Minute
	apiServiceUnblockPodCap   = 10
	apiServiceUnblockCooldown = 15 * time.Minute
	// W19-CP2 standalone unblock: an aggregated APIService in a
	// protected namespace that stays Available=False >=30m gets its
	// backing pods restarted even with NO namespace stuck
	// Terminating — KEDA/cert-manager/prometheus-operator adapters
	// deadlock their own consumers (HPA, cert orders, scrape
	// configs) without ever wedging a namespace deletion, so the
	// Terminating-namespace evidence alone never fires for them.
	apiServiceStandaloneUnblockMinAge   = 30 * time.Minute
	apiServiceStandaloneUnblockCooldown = 30 * time.Minute
)

// apiServiceProtectedNamespaces is the plan's skipNamespaces set —
// APIServices backed in these namespaces are core-ish infra the
// guard otherwise never touches. Membership here does NOT skip the
// availability metric; it scopes which backends the unblock healer
// may restart. W19-CP2 added keda/cert-manager/prometheus-operator —
// aggregated adapters whose outage stalls HPA scaling, cert
// issuance and Prometheus scraping respectively — plus operators:
// OLM installs KEDA there, so v1beta1.external.metrics.k8s.io's
// spec.service.namespace is "operators", not "keda".
var apiServiceProtectedNamespaces = map[string]bool{
	"kube-system":         true,
	"linkerd":             true,
	"linkerd-viz":         true,
	"monitoring":          true,
	"keda":                true,
	"cert-manager":        true,
	"prometheus-operator": true,
	"operators":           true,
}

// unblockHealer owns the namespace-terminating-wedged sweep's per-sweep state — embedded
// in apiServiceGuard so the facade's method set (and every
// in-package test fixture built on it) is unchanged by the split.
// Shared deps (cs/dyn/now/verdict) are reached through snap.g; only
// the heal cooldown lives here.
type unblockHealer struct {
	// unblocked is "<apiservice name>" -> last unblock-heal time —
	// bounds restart churn on a backend that wedges again right
	// after its pods are recreated.
	unblocked state.CooldownSet
	// standaloneUnblocked is the same ledger for the W19-CP2
	// standalone path (no Terminating-namespace evidence) — a
	// separate keyspace so a standalone heal cannot mask or be
	// masked by a wedge-evidence heal on the same APIService.
	standaloneUnblocked state.CooldownSet
}

// unblockCandidate is one APIService that passed the cheap
// unavailability+namespace+group gates — the shared input of the
// wedge-evidence pass and the W19-CP2 standalone pass.
type unblockCandidate struct {
	svc   *unstructured.Unstructured
	group string
}

// sweepUnblock consumes the same per-run snapshot. It heals ONLY the
// protected-namespace backends (the plan's skipNamespaces set) and
// ONLY when the wedge is proven end-to-end:
//
//	spec.service.namespace in apiServiceProtectedNamespaces
//	AND Available=False for >= apiServiceUnblockMinAge (15m)
//	AND >=1 Namespace stuck Terminating >=15m whose conditions or
//	    events reference the APIService's API group.
//
// The heal is a backing-pod restart: the aggregated-apiserver pods
// behind spec.service are evicted (UID-preconditioned,
// PDB-respecting, capped) so their controllers recreate them — the
// least destructive action that clears a wedged aggregation without
// touching the operator-owned APIService object itself.
func (u *unblockHealer) sweepUnblock(ctx context.Context, snap *apiServiceSnapshot) error {
	g := snap.g
	now := g.now.Now()
	// PruneExpired runs BEFORE the error gate so the cooldown ledger
	// is pruned on EVERY cycle — an apiservices list flap must not
	// leave decommissioned backends' stamps accumulating forever.
	// unblocked keys on APIService names that die with the resource —
	// bound the map so decommissioned backends' stamps cannot
	// accumulate in the first place.
	u.unblocked.PruneExpired(now, apiServiceUnblockCooldown)
	u.standaloneUnblocked.PruneExpired(now, apiServiceStandaloneUnblockCooldown)
	if snap.err != nil {
		return fmt.Errorf("list apiservices — unblock pass skipped: %w", snap.err)
	}

	// Candidate pass — cheap unstructured reads only; the namespace
	// scan below is skipped entirely when nothing qualifies.
	var cands []unblockCandidate
	for i := range snap.svcs.Items {
		svc := &snap.svcs.Items[i]
		unavailSince, ok := apiServiceUnavailableSince(svc)
		if !ok || now.Sub(unavailSince) < apiServiceUnblockMinAge {
			continue
		}
		svcNs, _, _ := apiServiceBackend(svc)
		if !apiServiceProtectedNamespaces[svcNs] {
			continue
		}
		group := apiServiceGroup(svc.GetName())
		if group == "" {
			continue // "v1." core registration — never unblocked
		}
		cands = append(cands, unblockCandidate{svc: svc, group: group})
	}
	if len(cands) == 0 {
		return nil
	}

	// Wedge evidence: namespaces stuck Terminating >=15m, each with
	// a lowercased corpus of its conditions + events for group
	// matching.
	stuck, err := u.stuckTerminatingNamespaces(ctx, snap, now)
	if err != nil {
		return err
	}
	if len(stuck) == 0 {
		// W19-CP2: no Terminating-namespace wedge — the standalone
		// pass heals every candidate dead >=30m (KEDA/cert-manager/
		// prometheus-operator adapters stall their consumers
		// silently without ever wedging a namespace deletion).
		return u.sweepStandaloneUnblock(ctx, snap, cands, now)
	}

	for _, c := range cands {
		var refs []string
		for ns, corpus := range stuck {
			if corpusHasToken(corpus, c.group) {
				refs = append(refs, ns)
			}
		}
		if len(refs) == 0 {
			// No stuck namespace references THIS group — the wedge
			// evidence cannot fire, but an unrelated namespace
			// wedged Terminating must not mask a dead adapter:
			// fall back to the standalone gate per candidate.
			u.standaloneHealCandidate(ctx, snap, c, now)
			continue
		}
		u.healCandidate(ctx, snap, c.svc, c.group, &u.unblocked,
			apiServiceUnblockCooldown, now, refs)
	}
	return nil
}

// sweepStandaloneUnblock is the W19-CP2 no-wedge path: every
// protected-namespace APIService unavailable for
// apiServiceStandaloneUnblockMinAge (30m — double the wedge-evidence
// bar, since there is no Terminating namespace corroborating) gets
// the same backing-pod restart under its own cooldown ledger.
func (u *unblockHealer) sweepStandaloneUnblock(ctx context.Context,
	snap *apiServiceSnapshot, cands []unblockCandidate, now time.Time) error {

	for _, c := range cands {
		u.standaloneHealCandidate(ctx, snap, c, now)
	}
	return nil
}

// standaloneHealCandidate applies the W19-CP2 standalone gate to one
// candidate — unavailability >= apiServiceStandaloneUnblockMinAge —
// then runs the shared heal tail under the standalone cooldown
// ledger. Shared by sweepStandaloneUnblock (no Terminating
// namespaces at all) and the wedge-evidence loop (a candidate whose
// group no stuck namespace references — an unrelated wedged
// namespace must not mask it).
func (u *unblockHealer) standaloneHealCandidate(ctx context.Context,
	snap *apiServiceSnapshot, c unblockCandidate, now time.Time) {

	unavailSince, _ := apiServiceUnavailableSince(c.svc)
	if now.Sub(unavailSince) < apiServiceStandaloneUnblockMinAge {
		return
	}
	u.healCandidate(ctx, snap, c.svc, c.group,
		&u.standaloneUnblocked, apiServiceStandaloneUnblockCooldown,
		now, nil)
}

// healCandidate runs the shared heal tail for one candidate:
// resolve live backing pods → heal.AllowedV preamble (per-name
// cooldown + maintenance mutex) → capped UID-preconditioned eviction
// → stamp + metric + ACTION log only when a pod was actually
// evicted. refs carries the wedge-evidence namespace names for the
// log (nil on the standalone path).
func (u *unblockHealer) healCandidate(ctx context.Context,
	snap *apiServiceSnapshot, svc *unstructured.Unstructured,
	group string, cooldown *state.CooldownSet, cooldownDur time.Duration,
	now time.Time, refs []string) bool {

	g := snap.g
	log := logf.FromContext(ctx)
	svcNs, svcName, _ := apiServiceBackend(svc)
	// Confirm a live restart target BEFORE the heal preamble: the
	// wedge evidence alone doesn't mean anything is left to
	// restart, and AllowedV spends a fleet-wide budget grant on
	// every proceed — a stale/empty backend must not burn one.
	targets, err := u.backingPodTargets(ctx, g, svcNs, svcName)
	if err != nil {
		log.Error(err, "unblock heal target lookup failed",
			"apiservice", svc.GetName(), "service", svcNs+"/"+svcName)
		metrics.IncError(g.queue)
		return false
	}
	if len(targets) == 0 {
		log.Info("unblock heal skipped — no live backing pod to restart",
			"apiservice", svc.GetName(), "service", svcNs+"/"+svcName)
		return false
	}
	// Wedge proven AND a target exists — the heal is gated per target
	// inside deleteBackingPods (heal.EvictPodV = AllowedV → EvictPod →
	// refund-on-refused in one call): per-APIService cooldown is the
	// caller's stamp below, the maintenance mutex (a cordon/drain/kured
	// reboot or an in-flight k0s upgrade defers the restart, and
	// "cannot verify" fails closed AND IncErrors the queue) is memoized
	// on the facade's verdict so a run of candidates pays one
	// evaluation, and the fleet-wide budget grant is spent on a
	// DELIVERED eviction only — a PDB refusal refunds it instead of
	// silently starving every other heal-gated module.
	deleted := u.deleteBackingPods(ctx, g, svc.GetName(), targets, now)
	// Stamp the cooldown, count the heal and log ACTION only on a
	// DELIVERED heal — a pass that deleted nothing (NotFound
	// races) must not open the suppression window or log an
	// unblock that did not happen.
	if deleted > 0 {
		cooldown.Stamp(svc.GetName(), now)
		metrics.APIServiceUnblockHealsTotal.
			WithLabelValues(svcNs, "backing_pods_deleted").Inc()
		log.Info("ACTION: unblocked dead APIService",
			"apiservice", svc.GetName(), "group", group,
			"service", svcNs+"/"+svcName,
			"terminatingNamespaces", refs, "podsDeleted", deleted,
			"standalone", refs == nil)
		return true
	}
	return false
}

// corpusHasToken reports whether the lowercased namespace corpus
// references the candidate's API group as a WHOLE token: the byte
// immediately before a match must be a space, newline or quote (or
// the match starts the corpus). Plain strings.Contains is not
// enough: a stale event naming the full APIService name — failed
// calling webhook "v1beta1.metrics.k8s.io" — substring-matches the
// candidate group metrics.k8s.io inside the longer name (the dot
// before "metrics" is not a boundary), and one unrelated webhooks
// incident would then license restarting up to
// apiServiceUnblockPodCap healthy metric-adapter pods. Genuine
// evidence names the bare group with a token boundary (quoted or
// space-delimited), which still matches.
func corpusHasToken(corpus, token string) bool {
	if token == "" {
		return false
	}
	for start := 0; start < len(corpus); {
		rel := strings.Index(corpus[start:], token)
		if rel < 0 {
			return false
		}
		idx := start + rel
		if idx == 0 || isTokenBoundary(corpus[idx-1]) {
			return true
		}
		start = idx + 1
	}
	return false
}

// isTokenBoundary reports whether b ends a token inside the
// stuck-namespace corpus — the corpus joins conditions/events with
// spaces and newlines, and quoted references (failed calling webhook
// "<group>") keep their quotes after lowercasing.
func isTokenBoundary(b byte) bool {
	return b == ' ' || b == '\n' || b == '"'
}

// stuckTerminatingNamespaces returns "<ns name>" -> lowercased
// reference corpus (conditions + events) for every namespace that
// has been in phase Terminating for >= apiServiceUnblockMinAge. A
// namespace without a deletionTimestamp cannot prove its age — it
// is skipped (fail closed). The census itself is the shared
// per-run snapshot (the orphan pass lists the same input once).
func (u *unblockHealer) stuckTerminatingNamespaces(ctx context.Context,
	snap *apiServiceSnapshot, now time.Time) (map[string]string, error) {
	g := snap.g
	log := logf.FromContext(ctx)
	nss, err := snap.nss, snap.nsErr
	if err != nil {
		return nil, fmt.Errorf("list namespaces (unblock pass): %w", err)
	}
	out := map[string]string{}
	for i := range nss {
		ns := &nss[i]
		if ns.Status.Phase != corev1.NamespaceTerminating ||
			ns.DeletionTimestamp == nil ||
			now.Sub(ns.DeletionTimestamp.Time) < apiServiceUnblockMinAge {
			continue
		}
		var corpus strings.Builder
		for _, c := range ns.Status.Conditions {
			corpus.WriteString(strings.ToLower(string(c.Type)))
			corpus.WriteByte(' ')
			corpus.WriteString(strings.ToLower(c.Reason))
			corpus.WriteByte(' ')
			corpus.WriteString(strings.ToLower(c.Message))
			corpus.WriteByte('\n')
		}
		evs, err := kube.ListAll(ctx,
			metav1.ListOptions{Limit: apiServiceListPageSize},
			kube.Events(g.cs, ns.Name))
		if err != nil {
			// Conditions-only corpus still carries
			// NamespaceContentRemaining/DiscoveryFailed detail —
			// a partial corpus beats skipping the namespace.
			log.Info("WARN: events list failed — conditions-only corpus",
				"namespace", ns.Name, "error", err)
		} else {
			for j := range evs {
				e := &evs[j]
				corpus.WriteString(strings.ToLower(e.Reason))
				corpus.WriteByte(' ')
				corpus.WriteString(strings.ToLower(e.Message))
				corpus.WriteByte('\n')
			}
		}
		out[ns.Name] = corpus.String()
	}
	return out, nil
}

// backingPodTargets resolves the Service-backed pods an unblock heal
// may restart: the backing Service's selector pods that are alive and
// non-terminating (a pod already going down does not need the heal —
// deleting it again buys nothing and burns a budget grant). A gone
// Service or an empty selector yields no targets — the caller skips
// the candidate without touching the heal preamble. Caller has NOT
// yet taken the maintenance-mutex verdict: this is read-only.
func (u *unblockHealer) backingPodTargets(ctx context.Context,
	g *apiServiceGuard, svcNs, svcName string) ([]corev1.Pod, error) {
	log := logf.FromContext(ctx)
	svc, err := g.cs.CoreV1().Services(svcNs).Get(ctx, svcName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// The backend Service itself is gone — pod restart is
		// impossible; the operator that owns it must recreate it.
		log.Info("unblock heal skipped — backing service gone",
			"service", svcNs+"/"+svcName)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get backing service %s/%s: %w", svcNs, svcName, err)
	}
	if len(svc.Spec.Selector) == 0 {
		log.Info("unblock heal skipped — backing service has no selector",
			"service", svcNs+"/"+svcName)
		return nil, nil
	}
	pods, err := kube.ListAll(ctx, metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(svc.Spec.Selector).String(),
		Limit:         apiServiceListPageSize,
	}, kube.Pods(g.cs, svcNs))
	if err != nil {
		return nil, fmt.Errorf("list backing pods %s: %w", svcNs, err)
	}
	var targets []corev1.Pod
	for i := range pods {
		p := &pods[i]
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		if p.DeletionTimestamp != nil {
			continue // already terminating — its replacement carries the fix
		}
		targets = append(targets, *p)
	}
	return targets, nil
}

// deleteBackingPods evicts the pre-resolved restart targets, capped
// per call. Each kill rides heal.EvictPodV — the gate+act+refund
// composite: the UID-preconditioned, PDB-respecting Eviction API the
// unmeshed path runs on (a raw Delete would bypass every
// PodDisruptionBudget and could take the backend's last Ready replica
// mid-outage), the memoized maintenance-mutex verdict (nil heals — the
// per-APIService cooldown is healCandidate's stamp-on-delivered below,
// NOT a per-target pre-check: a multi-pod fan-out must not have its
// second target blocked by the first delivery's stamp), and a
// fleet-wide budget grant spent on DELIVERED evictions only — a 429
// refusal is refunded, keeping a PDB-hung backend from starving every
// other heal-gated module. A refusal is a deferral — the pod stays,
// nothing is metered, and `deleted` staying 0 keeps healCandidate from
// stamping the cooldown or logging an unblock that did not happen.
// NotFound races are quiet no-ops; any other eviction failure is
// metered and logged with the pod's own context. An unverifiable
// mutex check fails the pass closed: IncError once, stop — the memo
// makes the first target hit it anyway.
func (u *unblockHealer) deleteBackingPods(ctx context.Context,
	g *apiServiceGuard, apiService string, targets []corev1.Pod,
	now time.Time) int {
	log := logf.FromContext(ctx)
	deleted := 0
	for i := range targets {
		if deleted >= apiServiceUnblockPodCap {
			break
		}
		p := &targets[i]
		// heals is nil (the cooldown is healCandidate's stamp-on-
		// delivered below) so key rides only the preamble's defer
		// logs — without it a refused/unverifiable target logs
		// "target=" with no APIService attribution.
		proceed, unverifiable, evicted, refused, err :=
			heal.EvictPodV(ctx, log, &g.verdict, g.cs, g.dyn,
				nil, apiService, 0, p, now)
		switch {
		case unverifiable:
			metrics.IncError(g.queue)
			log.Info("heal deferred: maintenance check unverifiable — fail closed",
				"pod", p.Namespace+"/"+p.Name)
			return deleted
		case !proceed:
			continue // mutex held / budget denied — nothing this pass
		case refused:
			log.Info("DEFER: PDB refused backing pod eviction — keeping pod alive",
				"pod", p.Namespace+"/"+p.Name)
			continue
		case apierrors.IsNotFound(err):
			continue
		case err != nil:
			metrics.IncError(g.queue)
			log.Error(err, "backing pod eviction failed",
				"pod", p.Namespace+"/"+p.Name)
			continue
		case !evicted:
			continue // proceeded but nothing landed — treat like a race
		}
		deleted++
	}
	return deleted
}

// Port of hooks/55-admission-webhook-guard.sh.
//
// Removes "orphan" admission webhook entries whose backend Service lives
// in a namespace that no longer exists (e.g. Flux pruned linkerd → the
// cluster-scoped MutatingWebhookConfiguration outlived its control plane
// and every pod create fail-closed, incident 2026-10-20).
//
// Rules (faithful to bash):
//   - namespace exists + Service exists      → nothing.
//   - namespace exists + Service missing     → WARN only, never patch
//     (a mid-rollout Service looks exactly like this).
//   - namespace gone                         → remove that webhook entry
//     only; sibling entries in the same config are kept.
//
// Safety: the namespace list is snapshotted once — any error aborts the
// run before anything is patched (an API flap must never be read as
// "namespace deleted").
//
// C1 — self-deadlock circuit breaker (env WEBHOOK_CIRCUIT_BREAKER_ENABLED,
// default on): a sub-webhook with failurePolicy=Fail whose backend
// Service reports 0 Ready endpoints for webhookDeadThreshold straight
// is a cluster-wide deadlock — every admission it matches fails closed,
// including the creates that would bring the backend back. The breaker
// flips such entries to Ignore and records their names in the
// node.ops/circuit-broken-webhooks annotation on the config; when the
// Service reports >= 1 Ready endpoint again the declared Fail policy
// is restored and the annotation shrinks (removed when empty).
package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/controller/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

const (
	webhookGuardQueue = "admission-webhook-guard"

	// webhookCircuitAnno records, on the webhook config object itself,
	// the comma-separated names of the sub-webhooks the C1 circuit
	// breaker flipped to failurePolicy=Ignore — the trip record
	// survives pod restarts and is human-readable in kubectl describe.
	// Comma-separated is unambiguous: webhook names are DNS-1123
	// subdomains, which can never contain a comma.
	webhookCircuitAnno = "node.ops/circuit-broken-webhooks"

	// webhookDeadThreshold is how long a fail-closed sub-webhook's
	// backend Service must report 0 Ready endpoints before the breaker
	// trips it to Ignore.
	webhookDeadThreshold = 5 * time.Minute

	// kind label values for the WebhookCircuit* metrics — the short
	// forms matching webhookPatch.mutating.
	webhookKindMutating   = "mutating"
	webhookKindValidating = "validating"
)

type webhookGuard struct {
	cs kubernetes.Interface
	// nowFn is the clock seam for the dead-backend streak — tests pin
	// a scripted now to reach past webhookDeadThreshold. nil → time.Now.
	nowFn func() time.Time
	// deadSince is the first-seen timestamp of each
	// kind/config/sub-webhook sighted fail-closed against a Service
	// with 0 Ready endpoints. A sighting that disappears (endpoints
	// back, entry removed) resets the streak.
	deadSince map[string]time.Time
}

// SetupWebhookGuard registers the 5-minute sweep (was crontab */5).
func SetupWebhookGuard(mgr ctrl.Manager, cs kubernetes.Interface) error {
	g := &webhookGuard{cs: cs, nowFn: time.Now,
		deadSince: map[string]time.Time{}}
	return shared.AddPeriodic(mgr, webhookGuardQueue, 5*time.Minute, g.run)
}

// circuitBreakerEnabled reads the kill-switch every run — an env flip
// takes effect on the next sweep without a code change.
func circuitBreakerEnabled() bool {
	return os.Getenv("WEBHOOK_CIRCUIT_BREAKER_ENABLED") != "false"
}

// webhookPatch is one queued replace of /webhooks on a single config
// (bash did per-index removes; one atomic replace per config is the
// equivalent and cannot shift indices mid-patch).
type webhookPatch struct {
	mutating bool
	name     string
	payload  []byte
}

func (g *webhookGuard) run(ctx context.Context) error {
	// The orphan sweep and the circuit breaker are independent duties —
	// a failure in one must never skip the other, so both run and their
	// errors join (nil+nil → nil).
	orphanErr := g.sweepOrphans(ctx)
	var breakerErr error
	if circuitBreakerEnabled() {
		breakerErr = g.sweepCircuitBreaker(ctx)
	}
	return errors.Join(orphanErr, breakerErr)
}

func (g *webhookGuard) sweepOrphans(ctx context.Context) error {
	log := logf.FromContext(ctx)

	// Namespace snapshot — the ONLY source of "deleted" truth. Any error
	// or a missing kube-system means API flap: abort, patch nothing.
	nsList, err := g.cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list namespaces (API flap) — abort: %w", err)
	}
	namespaces := make(map[string]bool, len(nsList.Items))
	for _, ns := range nsList.Items {
		namespaces[ns.Name] = true
	}
	nsList = nil
	if !namespaces["kube-system"] {
		return fmt.Errorf("kube-system absent from namespace list (API flap) — abort")
	}

	// Service snapshot feeds only the WARN branch — a failure here
	// degrades to namespace-only checking, it must not block orphans.
	haveSvc := true
	services := map[string]bool{}
	svcList, err := g.cs.CoreV1().Services(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(webhookGuardQueue)
		log.Info("WARN: cannot list services — skipping service check (namespace check still runs)", "error", err)
		haveSvc = false
	} else {
		for _, s := range svcList.Items {
			services[s.Namespace+"/"+s.Name] = true
		}
	}
	svcList = nil

	mwc, err := g.cs.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list mutatingwebhookconfigurations (API flap) — abort: %w", err)
	}
	vwc, err := g.cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list validatingwebhookconfigurations (API flap) — abort: %w", err)
	}

	var patches []webhookPatch
	collect := func(mutating bool, cfgName string, filtered any, dirty bool) {
		if !dirty {
			return
		}
		payload, err := json.Marshal([]map[string]any{{
			"op": "replace", "path": "/webhooks", "value": filtered,
		}})
		if err != nil {
			log.Error(err, "marshal webhook patch", "config", cfgName)
			return
		}
		patches = append(patches, webhookPatch{mutating: mutating, name: cfgName, payload: payload})
	}

	for _, cfg := range mwc.Items {
		filtered := make([]admissionv1.MutatingWebhook, 0, len(cfg.Webhooks))
		dirty := false
		for i, w := range cfg.Webhooks {
			if g.orphanEntry(log, "mutatingwebhookconfigurations", cfg.Name, i, w.ClientConfig.Service, namespaces, services, haveSvc) {
				dirty = true
				continue
			}
			filtered = append(filtered, w)
		}
		collect(true, cfg.Name, filtered, dirty)
	}
	for _, cfg := range vwc.Items {
		filtered := make([]admissionv1.ValidatingWebhook, 0, len(cfg.Webhooks))
		dirty := false
		for i, w := range cfg.Webhooks {
			if g.orphanEntry(log, "validatingwebhookconfigurations", cfg.Name, i, w.ClientConfig.Service, namespaces, services, haveSvc) {
				dirty = true
				continue
			}
			filtered = append(filtered, w)
		}
		collect(false, cfg.Name, filtered, dirty)
	}

	if len(patches) == 0 {
		log.Info("sweep done: no orphan admission webhooks")
		return nil
	}

	failed := false
	for _, p := range patches {
		log.Info("PATCH: replace /webhooks (drop orphan entries)", "config", p.name)
		if p.mutating {
			_, err = g.cs.AdmissionregistrationV1().MutatingWebhookConfigurations().Patch(ctx, p.name, types.JSONPatchType, p.payload, metav1.PatchOptions{})
		} else {
			_, err = g.cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().Patch(ctx, p.name, types.JSONPatchType, p.payload, metav1.PatchOptions{})
		}
		if err != nil {
			log.Error(err, "webhook config patch failed", "config", p.name)
			failed = true
		}
	}
	if failed {
		return fmt.Errorf("some webhook config patches failed — orphan webhooks may remain")
	}
	log.Info("sweep done: removed orphan webhook entries (namespace deleted)",
		"configsPatched", len(patches))
	return nil
}

// orphanEntry classifies one webhook entry. Returns true only when the
// backend Service's namespace is gone (→ caller drops the entry).
// A missing Service in a still-live namespace warns and is never patched.
func (g *webhookGuard) orphanEntry(log logr.Logger, kind, cfg string, idx int, svcRef *admissionv1.ServiceReference, namespaces, services map[string]bool, haveSvc bool) bool {
	if svcRef == nil || svcRef.Namespace == "" {
		return false // malformed/no-service entry — not an orphan
	}
	if !namespaces[svcRef.Namespace] {
		log.Info(fmt.Sprintf("ORPHAN: %s/%s webhook[%d] -> %s/%s (namespace gone) — removing entry",
			kind, cfg, idx, svcRef.Namespace, svcRef.Name))
		return true
	}
	if haveSvc && !services[svcRef.Namespace+"/"+svcRef.Name] {
		log.Info(fmt.Sprintf("WARN: %s/%s webhook[%d] -> %s/%s (Service missing) — warn only, not patched",
			kind, cfg, idx, svcRef.Namespace, svcRef.Name))
	}
	return false
}

// ---------------------------------------------------------------------------
// C1 — admission webhook self-deadlock circuit breaker.
// ---------------------------------------------------------------------------

func (g *webhookGuard) now() time.Time {
	if g.nowFn != nil {
		return g.nowFn()
	}
	return time.Now()
}

// sweepCircuitBreaker trips fail-closed sub-webhooks whose backend
// Service has reported 0 Ready endpoints continuously for
// webhookDeadThreshold, and restores previously tripped entries once
// the Service has endpoints again. It runs after the orphan sweep so
// it always evaluates post-prune state; a patch failure on one config
// is logged and the sweep continues with the rest.
func (g *webhookGuard) sweepCircuitBreaker(ctx context.Context) error {
	log := logf.FromContext(ctx)
	now := g.now()
	if g.deadSince == nil {
		g.deadSince = map[string]time.Time{}
	}

	ready, err := g.readyEndpointCounts(ctx)
	if err != nil {
		return err
	}
	mwcs, err := g.cs.AdmissionregistrationV1().MutatingWebhookConfigurations().
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list mutatingwebhookconfigurations — circuit breaker skipped: %w", err)
	}
	vwcs, err := g.cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list validatingwebhookconfigurations — circuit breaker skipped: %w", err)
	}

	// seen marks the deadSince keys still under evaluation — streaks
	// for entries gone since the last sweep are pruned below.
	seen := map[string]bool{}
	var failed []string
	for i := range mwcs.Items {
		cfg := &mwcs.Items[i]
		payload, trips, recovered := g.circuitPatch(log, webhookKindMutating,
			cfg.Name, cfg.Annotations[webhookCircuitAnno],
			mutHookViews(cfg.Webhooks), cfg.Webhooks, ready, now, seen)
		if payload == nil {
			continue
		}
		if _, err := g.cs.AdmissionregistrationV1().MutatingWebhookConfigurations().
			Patch(ctx, cfg.Name, types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
			log.Error(err, "circuit breaker patch failed", "config", cfg.Name)
			failed = append(failed, cfg.Name)
			continue
		}
		circuitMetrics(webhookKindMutating, cfg.Name, trips, recovered)
	}
	for i := range vwcs.Items {
		cfg := &vwcs.Items[i]
		payload, trips, recovered := g.circuitPatch(log, webhookKindValidating,
			cfg.Name, cfg.Annotations[webhookCircuitAnno],
			valHookViews(cfg.Webhooks), cfg.Webhooks, ready, now, seen)
		if payload == nil {
			continue
		}
		if _, err := g.cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().
			Patch(ctx, cfg.Name, types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
			log.Error(err, "circuit breaker patch failed", "config", cfg.Name)
			failed = append(failed, cfg.Name)
			continue
		}
		circuitMetrics(webhookKindValidating, cfg.Name, trips, recovered)
	}

	for k := range g.deadSince {
		if !seen[k] {
			delete(g.deadSince, k)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("circuit breaker patches failed for: %s",
			strings.Join(failed, ", "))
	}
	return nil
}

// readyEndpointCounts builds the ns/service → Ready-endpoint census
// from one cluster-wide EndpointSlice list. The
// kubernetes.io/service-name label binds each slice to its Service; a
// nil conditions.ready counts as ready (the field defaults to true
// server-side). No degraded mode: without a complete census "0 ready"
// is indistinguishable from "no data", so a list error skips the whole
// breaker rather than trip healthy webhooks.
func (g *webhookGuard) readyEndpointCounts(ctx context.Context) (map[string]int, error) {
	sliceList, err := g.cs.DiscoveryV1().EndpointSlices(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list endpointslices — circuit breaker skipped: %w", err)
	}
	ready := map[string]int{}
	for _, s := range sliceList.Items {
		svc := s.Labels[discoveryv1.LabelServiceName]
		if svc == "" {
			continue // no owning Service — cannot map to a webhook backend
		}
		key := s.Namespace + "/" + svc
		for _, ep := range s.Endpoints {
			if ep.Conditions.Ready == nil || *ep.Conditions.Ready {
				ready[key]++
			}
		}
	}
	return ready, nil
}

// hookView is the breaker's uniform projection over MutatingWebhook /
// ValidatingWebhook — identical relevant fields, distinct Go types.
// set writes the failurePolicy back into the config's webhook list so
// the whole list can be re-serialized into the merge patch.
type hookView struct {
	name string
	fp   *admissionv1.FailurePolicyType
	svc  *admissionv1.ServiceReference
	set  func(*admissionv1.FailurePolicyType)
}

func mutHookViews(ws []admissionv1.MutatingWebhook) []hookView {
	out := make([]hookView, len(ws))
	for i := range ws {
		out[i] = hookView{
			name: ws[i].Name, fp: ws[i].FailurePolicy,
			svc: ws[i].ClientConfig.Service,
			set: func(fp *admissionv1.FailurePolicyType) {
				ws[i].FailurePolicy = fp
			},
		}
	}
	return out
}

func valHookViews(ws []admissionv1.ValidatingWebhook) []hookView {
	out := make([]hookView, len(ws))
	for i := range ws {
		out[i] = hookView{
			name: ws[i].Name, fp: ws[i].FailurePolicy,
			svc: ws[i].ClientConfig.Service,
			set: func(fp *admissionv1.FailurePolicyType) {
				ws[i].FailurePolicy = fp
			},
		}
	}
	return out
}

// circuitPatch evaluates one config's sub-webhooks against the ready
// census and builds the merge patch that flips long-dead entries to
// Ignore, restores recovered ones to Fail and rewrites the
// circuit-broken annotation (merge-patch null removes the key when the
// set empties). hooks views the config's live webhook list; raw is
// that same list re-serialized wholesale into the patch (merge
// semantics replace arrays). Returns nil payload when nothing changed;
// trips/recovered are the names whose metric updates the caller must
// apply only after the patch lands.
func (g *webhookGuard) circuitPatch(log logr.Logger, kind, cfgName, annoVal string,
	hooks []hookView, raw any, ready map[string]int, now time.Time,
	seen map[string]bool) ([]byte, []string, []string) {

	broken := parseCircuitAnnotation(annoVal)
	// present holds every live sub-webhook name — the staleness check
	// below compares the annotation against it (a freshly tripped name
	// is present even though it was not in the annotation yet).
	present := map[string]bool{}
	ignore, fail := admissionv1.Ignore, admissionv1.Fail
	changed := false
	var trips, recovered []string

	for _, h := range hooks {
		present[h.name] = true
		key := kind + "/" + cfgName + "/" + h.name
		isBroken := broken[h.name]
		// svcReady < 0 marks "not Service-backed" — URL webhooks and
		// malformed refs are unmeasurable, the breaker never trips them.
		svcReady := -1
		svc := ""
		if h.svc != nil && h.svc.Namespace != "" && h.svc.Name != "" {
			svc = h.svc.Namespace + "/" + h.svc.Name
			svcReady = ready[svc]
		}
		switch {
		case isBroken && svcReady != 0:
			// RECOVER — the Service has >= 1 Ready endpoint again, or
			// the entry was repointed off its Service entirely
			// (svcReady < 0): the breaker cannot measure a URL, so it
			// hands back the declared Fail and steps out.
			h.set(&fail)
			delete(broken, h.name)
			recovered = append(recovered, h.name)
			changed = true
			log.Info(fmt.Sprintf("CIRCUIT-RECOVER: %s/%s webhook %q -> %s — restoring failurePolicy=Fail",
				kind, cfgName, h.name, svcRefString(h.svc)))
		case isBroken:
			// Still dead — the annotation is the SSOT, so re-assert
			// Ignore if the policy was flipped back externally.
			if h.fp == nil || *h.fp != admissionv1.Ignore {
				h.set(&ignore)
				changed = true
			}
			metrics.WebhookCircuitBroken.WithLabelValues(kind, cfgName, h.name).Set(1)
		case svcReady == 0 && failClosed(h.fp):
			seen[key] = true
			first, ok := g.deadSince[key]
			if !ok {
				g.deadSince[key] = now
				log.Info("circuit breaker: fail-closed webhook on a dead Service — tracking",
					"config", cfgName, "webhook", h.name, "service", svc)
				continue
			}
			if now.Sub(first) < webhookDeadThreshold {
				continue
			}
			// TRIP — dead backend past the threshold. deadSince is
			// deliberately NOT cleared here: if the patch fails the
			// annotation never lands, so keeping the streak lets the
			// next sweep retry immediately instead of re-opening a
			// fresh 5m window. Once the entry is broken it no longer
			// marks seen[key], so the ledger prunes itself.
			h.set(&ignore)
			broken[h.name] = true
			trips = append(trips, h.name)
			changed = true
			log.Info(fmt.Sprintf("CIRCUIT-TRIP: %s/%s webhook %q -> %s (0 ready endpoints >= %s) — patching failurePolicy=Ignore",
				kind, cfgName, h.name, svc, webhookDeadThreshold))
		}
	}

	// Stale annotation names (the sub-webhook itself is gone — e.g.
	// removed by the orphan sweep) drop out so the record stays exact.
	for name := range broken {
		if !present[name] {
			delete(broken, name)
			metrics.WebhookCircuitBroken.WithLabelValues(kind, cfgName, name).Set(0)
			changed = true
			log.Info("CIRCUIT-CLEAN: annotation entry has no live webhook — dropping",
				"kind", kind, "config", cfgName, "webhook", name)
		}
	}
	if !changed {
		return nil, nil, nil
	}

	anno := map[string]any{webhookCircuitAnno: nil} // merge-patch null deletes the key
	if len(broken) > 0 {
		anno[webhookCircuitAnno] = strings.Join(slices.Sorted(maps.Keys(broken)), ",")
	}
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"annotations": anno},
		"webhooks": raw,
	})
	if err != nil {
		log.Error(err, "marshal circuit breaker patch", "config", cfgName)
		return nil, nil, nil
	}
	return payload, trips, recovered
}

// circuitMetrics applies the trip/recovery side-effects — called only
// after the config patch landed, so a failed patch retries next sweep
// without double-counting trips.
func circuitMetrics(kind, cfgName string, trips, recovered []string) {
	for _, n := range trips {
		metrics.WebhookCircuitBroken.WithLabelValues(kind, cfgName, n).Set(1)
		metrics.WebhookCircuitBreakerTripsTotal.WithLabelValues(kind, cfgName).Inc()
	}
	for _, n := range recovered {
		metrics.WebhookCircuitBroken.WithLabelValues(kind, cfgName, n).Set(0)
	}
}

// failClosed reports whether the entry currently fails closed. A nil
// failurePolicy defaults to Fail server-side; anything not explicitly
// Ignore is treated as fail-closed.
func failClosed(fp *admissionv1.FailurePolicyType) bool {
	return fp == nil || *fp != admissionv1.Ignore
}

// parseCircuitAnnotation splits the comma-separated annotation value
// into a name set. Webhook names are DNS-1123 subdomains — commas can
// never appear in them, so the plain split is unambiguous.
func parseCircuitAnnotation(v string) map[string]bool {
	out := map[string]bool{}
	for _, n := range strings.Split(v, ",") {
		if n = strings.TrimSpace(n); n != "" {
			out[n] = true
		}
	}
	return out
}

// svcRefString renders a webhook's Service reference for log lines.
func svcRefString(ref *admissionv1.ServiceReference) string {
	if ref == nil || ref.Namespace == "" || ref.Name == "" {
		return "<none>"
	}
	return ref.Namespace + "/" + ref.Name
}

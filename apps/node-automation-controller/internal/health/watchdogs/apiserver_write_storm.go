// apiserver_write_storm.go — the apiserver-write-storm-breaker
// check (P0.1): the API write-amplification storm signature —
// PUT/PATCH/CREATE request rate AND write-path p99 latency both
// blown past their bounds for >=10m. A storm like this is usually
// self-inflicted: a Flux Kustomization/HelmRelease reconcile loop
// (or a misconfigured controller) hammering the apiserver with
// writes until etcd/raft latency collapses and EVERY client stalls.
//
// Past the persistence window the check:
//   - emits node_automation_apiserver_write_storm (per top
//     write-offender user/resource pair) + one deduped cluster
//     Event naming the offender,
//   - suspends every Flux Kustomization/HelmRelease that is still
//     Ready (actively writing) — EXCLUDING the flux-system and
//     node-ops namespaces and any object carrying
//     kube.AnnoWriteStormExempt — stamping each suspended object
//     with kube.AnnoWriteStormSuspendedBy so the restore pass can
//     never resurrect a hand-suspended object,
//   - on recovery restores ONLY the objects carrying its own stamp.
//
// The suspend/restore passes run through the shared maintenance
// mutex + heal budget like every destructive-adjacent act, and the
// whole breaker is env-gated by its registry GateEnv row
// (NODE_AUTOMATION_WRITE_STORM_BREAKER_ENABLED).
package watchdogs

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// apiserverWriteStormCheck is the write-amplification detector +
// Flux relief valve.
type apiserverWriteStormCheck struct {
	*probefw.Deps

	// seen tracks the storm signature's first-seen sweep — the
	// persistence window; pruned on recovery so a later storm
	// re-arms.
	seen state.FirstSeenLedger
	// emitted is the emitted-gauge ledger — storm pairs that stop
	// breaching get DeleteLabelValues'd rather than leaking a
	// stale 1.
	emitted state.GaugeLedger[string]
	// eventHealed is the in-RAM half of the Event dedupe cooldown.
	eventHealed state.CooldownSet
	// reliefDue gates the suspend/restore pass — without it every
	// non-storm sweep would census every Flux object cluster-wide
	// just to discover nothing is stamped. Starts true so a
	// controller restart still finds objects a previous process
	// suspended.
	reliefDue bool
	// suspended flips on the first delivered suspend patch and
	// re-arms the restore pass on recovery.
	suspended bool
	// healEnabled is the NODE_AUTOMATION_WRITE_STORM_HEAL_ENABLED
	// sub-gate — detection, the gauge and the Event keep running
	// with heals off; only the suspend/restore passes stand down.
	healEnabled bool
}

// NewAPIServerWriteStormCheck builds the apiserver-write-storm-breaker check.
func NewAPIServerWriteStormCheck(d *probefw.Deps) probefw.Check {
	return &apiserverWriteStormCheck{Deps: d, reliefDue: true,
		healEnabled: envx.Gate("NODE_AUTOMATION_WRITE_STORM_HEAL_ENABLED", true)}
}

const (
	CheckNameAPIServerWriteStorm = "apiserver-write-storm-breaker"

	// The storm signature needs BOTH halves: mutating request rate
	// above writeStormRate AND their p99 latency above
	// writeStormP99Seconds — rate alone is a busy cluster, latency
	// alone is a slow etcd; together they are the amplification
	// loop.
	writeStormRate       = 20.0 // mutating req/sec over 5m
	writeStormP99Seconds = 1.0  // write p99 latency in seconds
	// The signature must hold this long before relief fires — a
	// deploy wave or a single reconcile burst must not suspend
	// Flux objects.
	writeStormMinAge = 10 * time.Minute
	// One cluster Event per window — the storm can last hours.
	writeStormEventCooldown = 30 * time.Minute
	// The Flux suspend/restore census re-checks at most this often
	// (idempotent patches — the cooldown exists to keep the sweep
	// cheap, not to gate correctness).
	writeStormReliefCooldown = 15 * time.Minute
	// writeStormMaxSuspends caps the per-pass suspend blast radius —
	// a storm on a big cluster can see hundreds of Ready Flux
	// objects; suspending them all in one sweep is itself a write
	// storm. The remainder waits for the next relief window.
	writeStormMaxSuspends = 10
)

var (
	// apiserver-write-storm-breaker — 1 per top write-offender
	// (client, resource) pair while the storm signature persists.
	apiserverWriteStormGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_apiserver_write_storm",
		Help: "1 while an apiserver write storm is active, per top write-offender client/resource pair — apiserver-write-storm-breaker.",
	}, []string{"client", "resource"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(apiserverWriteStormGauge)
}

// writeStormQueries are the PromQL reads the signature is built
// from: mutating-request rate, write-path p99 latency, and the top
// write talkers that name the offender.
const (
	writeStormRateQuery = `sum(rate(apiserver_request_total{verb=~"PUT|PATCH|CREATE"}[5m]))`
	writeStormP99Query  = `histogram_quantile(0.99, sum by (le) ` +
		`(rate(apiserver_request_duration_seconds_bucket{verb=~"PUT|PATCH|CREATE",code=~"2.."}[5m])))`
	// apiserver_request_total labels the caller "client" (the
	// impersonated username), NOT "user" — grouping by user yields
	// an empty label and every offender reports as "-/resource".
	writeStormTopQuery = `topk(5, sum by (client, resource) ` +
		`(rate(apiserver_request_total{verb=~"PUT|PATCH|CREATE"}[5m])))`
)

// Run evaluates the write-storm signature: mutating rate above
// writeStormRate AND write p99 above writeStormP99Seconds,
// persisted writeStormMinAge. Past the window it emits the
// offender gauge, fires one deduped Event, and runs the Flux
// suspend pass; on recovery it restores only the objects it
// suspended itself.
func (p *apiserverWriteStormCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	p.eventHealed.PruneExpired(now, writeStormEventCooldown)
	var rep probefw.SweepReport

	rate, rerr := p.PromQuery(ctx, writeStormRateQuery)
	p99, perr := p.PromQuery(ctx, writeStormP99Query)
	if rerr != nil || perr != nil {
		// Inconclusive, not clear — carry held tuples forward so a
		// scrape flap cannot flap a live storm off.
		for k, lv := range p.emitted.Last() {
			rep.Carry(k, lv)
		}
		if rerr != nil {
			rep.InfraErr(fmt.Errorf("write storm rate query: %w", rerr))
		}
		if perr != nil {
			rep.InfraErr(fmt.Errorf("write storm p99 query: %w", perr))
		}
		return rep.Result(&p.emitted, apiserverWriteStormGauge.DeleteLabelValues,
			"apiserver write storm: ", ", ")
	}

	storm := sumSamples(rate) > writeStormRate &&
		sumSamples(p99) > writeStormP99Seconds
	if !storm {
		p.seen.Forget("storm")
		if (p.reliefDue || p.suspended) &&
			p.restoreSuspendedFlux(ctx, log, now) {
			p.reliefDue = false
			p.suspended = false
		}
		return rep.Result(&p.emitted, apiserverWriteStormGauge.DeleteLabelValues,
			"apiserver write storm: ", ", ")
	}
	first, _ := p.seen.Observe("storm", now)
	if now.Sub(first) < writeStormMinAge {
		return rep.Result(&p.emitted, apiserverWriteStormGauge.DeleteLabelValues,
			"apiserver write storm: ", ", ")
	}

	// Storm proven — name the offenders. The topk query is
	// best-effort: a failure still leaves the storm reported under
	// a "-/-" pair rather than dropping the signal.
	top, terr := p.PromQuery(ctx, writeStormTopQuery)
	if terr != nil {
		log.Info("WARN: write storm top-talker query failed — offenders unnamed",
			"error", terr)
		rep.InfraErr(fmt.Errorf("write storm top-talker query: %w", terr))
	}
	emitted := false
	for _, s := range top {
		client := s.Label("client")
		resource := s.Label("resource")
		if client == "" {
			client = "-"
		}
		if resource == "" {
			resource = "-"
		}
		key := client + "/" + resource
		rep.Emit(apiserverWriteStormGauge, key, []string{client, resource}, key)
		emitted = true
	}
	if !emitted {
		rep.Emit(apiserverWriteStormGauge, "-/-", []string{"-", "-"}, "-")
	}

	p.emitWriteStormEvent(ctx, log, top, now)
	p.suspendStormFlux(ctx, log, now)
	return rep.Result(&p.emitted, apiserverWriteStormGauge.DeleteLabelValues,
		"apiserver write storm: ", ", ")
}

// emitWriteStormEvent fires ONE deduped Warning event per cooldown
// window naming the top write offender — the on-call breadcrumb a
// metric alone cannot carry.
func (p *apiserverWriteStormCheck) emitWriteStormEvent(ctx context.Context,
	log logr.Logger, top []promq.Sample, now time.Time) {

	ck := probefw.SelfHealKey(CheckNameAPIServerWriteStorm, "event")
	if p.eventHealed.CooledDown(ck, writeStormEventCooldown, now) {
		return
	}
	msg := "apiserver write storm: PUT/PATCH/CREATE rate + write p99 sustained"
	if len(top) > 0 {
		s := top[0]
		msg = fmt.Sprintf("apiserver write storm: top write offender %s/%s",
			s.Label("client"), s.Label("resource"))
	}
	if err := kube.EmitWarningEvent(ctx, p.CS, kube.WarningEvent{
		Name:      "apiserver-write-storm-" + now.Format("20060102-150405"),
		Namespace: "kube-system",
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Namespace",
			Name:       "kube-system",
		},
		Reason:            "APIServerWriteStorm",
		Note:              msg,
		ReportingInstance: p.Name,
		Now:               now,
	}); err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: write storm event create failed (RBAC?)",
			"error", err)
		return
	}
	p.eventHealed.Stamp(ck, now)
	log.Info("EVENT: APIServerWriteStorm", "detail", msg)
}

// fluxWriteStormExemptNS are the namespaces whose Flux objects the
// breaker never suspends — suspending flux-system would freeze the
// very machinery that could be fixing the storm, node-ops owns the
// self-heal stack itself, and the kube-* core namespaces carry the
// control plane's own GitOps objects (a suspended core Kustomization
// deepens the outage it is meant to relieve).
var fluxWriteStormExemptNS = map[string]bool{
	"flux-system":     true,
	"node-ops":        true,
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
}

// fluxWriteStormObject is one suspendable Flux object.
type fluxWriteStormObject struct {
	gvr  schema.GroupVersionResource
	ns   string
	name string
	obj  *unstructured.Unstructured
}

// suspendStormFlux flips spec.suspend=true on every eligible Flux
// Kustomization/HelmRelease — once per relief cooldown window,
// gated on the shared maintenance mutex (fail closed). Eligible =
// Ready=True (still writing), not already suspended, not stamped
// by a previous run, not in an exempt namespace, and not carrying
// kube.AnnoWriteStormExempt.
func (p *apiserverWriteStormCheck) suspendStormFlux(ctx context.Context,
	log logr.Logger, now time.Time) {

	ck := probefw.SelfHealKey(CheckNameAPIServerWriteStorm, "flux-relief")
	if !p.healEnabled {
		return // detect-only: gauge + event already fired upstream
	}
	if p.Heals.CooledDown(ck, writeStormReliefCooldown, now) {
		return
	}
	targets := p.stormFluxTargets(ctx, log, false)
	if len(targets) == 0 {
		// Nothing eligible — do NOT stamp the relief cooldown: a
		// stamped empty pass would suppress the next storm's real
		// suspend for the whole window.
		return
	}
	proceed, unverifiable := p.HealAllowed(ctx, log, &p.Heals,
		ck, writeStormReliefCooldown, now)
	switch {
	case unverifiable:
		metrics.IncError(p.Name)
		return
	case !proceed:
		return
	}
	slices.SortFunc(targets, func(a, b *fluxWriteStormObject) int {
		if c := strings.Compare(a.ns, b.ns); c != 0 {
			return c
		}
		if c := strings.Compare(a.gvr.Resource, b.gvr.Resource); c != 0 {
			return c
		}
		return strings.Compare(a.name, b.name)
	})
	patched := 0
	for _, t := range targets {
		if patched >= writeStormMaxSuspends {
			log.Info("write storm suspend capped for this pass",
				"cap", writeStormMaxSuspends, "remaining", len(targets)-patched)
			break
		}
		patch := []byte(fmt.Sprintf(
			`{"spec":{"suspend":true},"metadata":{"annotations":{%q:%q}}}`,
			kube.AnnoWriteStormSuspendedBy,
			now.Format(time.RFC3339)))
		if _, err := p.Dyn.Resource(t.gvr).Namespace(t.ns).Patch(ctx,
			t.name, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
			metrics.IncError(p.Name)
			log.Error(err, "write storm flux suspend failed",
				"kind", t.gvr.Resource, "object", t.ns+"/"+t.name)
			continue
		}
		log.Info("ACTION: suspended flux object for write-storm relief",
			"kind", t.gvr.Resource, "object", t.ns+"/"+t.name)
		kube.RecordAnnoPatch(ctx, t.obj, patch)
		patched++
	}
	if patched > 0 {
		p.Heals.Stamp(ck, now)
		p.suspended = true
		p.InvalidateUnstructured(ctx)
	}
}

// restoreSuspendedFlux unsuspends every Flux object carrying the
// check's own AnnoWriteStormSuspendedBy stamp — the storm cleared,
// so the relief window ends. Objects suspended by anyone else (no
// stamp) are left alone by construction. Returns true only when
// the pass completed cleanly — a failed list or patch keeps the
// caller's reliefDue/suspended flags armed so the next sweep
// retries instead of stranding stamped objects suspended forever.
func (p *apiserverWriteStormCheck) restoreSuspendedFlux(ctx context.Context,
	log logr.Logger, now time.Time) bool {

	targets := p.stormFluxTargets(ctx, log, true)
	if targets == nil {
		return false // census failed — inconclusive, keep armed
	}
	ok := true
	restored := 0
	for _, t := range targets {
		patch := []byte(fmt.Sprintf(
			`{"spec":{"suspend":false},"metadata":{"annotations":{%q:null}}}`,
			kube.AnnoWriteStormSuspendedBy))
		if _, err := p.Dyn.Resource(t.gvr).Namespace(t.ns).Patch(ctx,
			t.name, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
			metrics.IncError(p.Name)
			log.Error(err, "write storm flux restore failed",
				"kind", t.gvr.Resource, "object", t.ns+"/"+t.name)
			ok = false
			continue
		}
		log.Info("ACTION: restored flux object after write-storm relief",
			"kind", t.gvr.Resource, "object", t.ns+"/"+t.name)
		kube.RecordAnnoPatch(ctx, t.obj, patch)
		restored++
	}
	if restored > 0 {
		p.InvalidateUnstructured(ctx)
	}
	return ok
}

// stormFluxTargets collects the Flux objects the breaker may act
// on. stampedOnly=true returns ONLY objects carrying
// AnnoWriteStormSuspendedBy (the restore pass); false returns the
// suspend candidates. A nil return means "census failed" — so a
// SUCCESSFUL census with zero matches must return a non-nil empty
// slice, otherwise the restore pass reads a clean "nothing left to
// restore" as a failed LIST and keeps reliefDue armed forever.
func (p *apiserverWriteStormCheck) stormFluxTargets(ctx context.Context,
	log logr.Logger, stampedOnly bool) []*fluxWriteStormObject {

	out := make([]*fluxWriteStormObject, 0)
	for _, gvr := range []schema.GroupVersionResource{kube.GVRFluxKustomization, kube.GVRHelmReleaseV2} {
		objs, err := p.AllUnstructured(ctx, gvr)
		if kube.IsCRDAbsent(err) {
			continue // this Flux kind not installed — nothing to do
		}
		if err != nil {
			metrics.IncError(p.Name)
			log.Info("WARN: write storm flux census failed",
				"kind", gvr.Resource, "error", err)
			if stampedOnly {
				return nil
			}
			continue
		}
		for i := range objs {
			o := &objs[i]
			if fluxWriteStormExemptNS[o.GetNamespace()] {
				continue
			}
			stamp := kube.EffectiveAnno(ctx, o, kube.AnnoWriteStormSuspendedBy)
			if stampedOnly {
				if stamp != "" {
					out = append(out, &fluxWriteStormObject{
						gvr: gvr, ns: o.GetNamespace(), name: o.GetName(), obj: o})
				}
				continue
			}
			if stamp != "" {
				continue // already suspended by a previous storm
			}
			if suspended, _ := kube.NestedBool(o.Object, "spec", "suspend"); suspended {
				continue
			}
			// Truthiness, not presence: an explicit "false" opts the
			// object back IN (the same spelling apiserver_relist_storm
			// uses). Treating any value as exempt lets a single
			// stray annotation silently disable storm relief.
			if strings.EqualFold(
				strings.TrimSpace(kube.EffectiveAnno(ctx, o, kube.AnnoWriteStormExempt)),
				"true") {
				continue
			}
			// Only suspend objects still Ready — a Ready=False
			// object is not writing; suspending it buys nothing
			// and deepens the outage it is already reporting.
			cond, ok := kube.ConditionOf(o.Object, "Ready")
			if !ok || cond.Status != "True" {
				continue
			}
			out = append(out, &fluxWriteStormObject{
				gvr: gvr, ns: o.GetNamespace(), name: o.GetName(), obj: o})
		}
	}
	return out
}

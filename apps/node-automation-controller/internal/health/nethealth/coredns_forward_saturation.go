// coredns_forward_saturation.go — the coredns-forward-saturation
// check (P1.7b): CoreDNS's forward plugin rejecting concurrent
// upstream queries (coredns_forward_max_concurrent_rejects_total
// climbing) means the resolver pool is saturated — every rejected
// query is a client-visible DNS timeout, and under an API/apiserver
// storm the blast radius is the whole cluster's name resolution.
//
// Signature: sum(rate(coredns_forward_max_concurrent_rejects_total
// [5m])) > 0 persisting >=5m. Past the window the check:
//   - emits node_automation_coredns_forward_saturation + one deduped
//     cluster Event,
//   - stamps kube.AnnoCoreDNSBoostUntil (now+30m) on the
//     kube-system/coredns Deployment — the coredns-patcher reads
//     the stamp and adds COREDNS_SATURATION_BOOST_REPLICAS to the
//     proportional replica pin while it is fresh,
//   - bumps .spec.replicas immediately by the same boost amount so
//     relief does not wait for the next patcher reconcile.
//
// The annotation IS the persisted cooldown: the boost action only
// fires when the stamp is absent or expired, so a re-detection
// inside the window re-arms the gauge/event but never double-
// bumps replicas. The patch goes through heal.FluxPatchGate — the
// Deployment is k0s/GitOps-owned and a Git source pinning replicas
// would otherwise ping-pong the bump every sweep.
package nethealth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// coreDNSForwardSaturationCheck is the forward-reject detector +
// replica-boost healer.
type coreDNSForwardSaturationCheck struct {
	*probefw.Deps

	// seen tracks the reject signature's first-seen sweep — the
	// persistence window; pruned on recovery.
	seen state.FirstSeenLedger
	// emitted is the emitted-gauge ledger.
	emitted state.GaugeLedger[string]
	// eventHealed dedupes the cluster Event per window.
	eventHealed state.CooldownSet
	// boostReplicas is COREDNS_SATURATION_BOOST_REPLICAS resolved
	// at construction — the SAME knob the coredns-patcher reads,
	// so the check's one-shot bump and the patcher's steady-state
	// boost can never drift apart.
	boostReplicas int32
}

// NewCoreDNSForwardSaturationCheck builds the check.
func NewCoreDNSForwardSaturationCheck(d *probefw.Deps) probefw.Check {
	return &coreDNSForwardSaturationCheck{Deps: d,
		boostReplicas: int32(envx.GetenvIntMin(
			"COREDNS_SATURATION_BOOST_REPLICAS", 2, 0))}
}

const (
	CheckNameCoreDNSForwardSaturation = "coredns-forward-saturation"

	// The reject signature must hold this long before relief —
	// a single burst of concurrent queries is normal.
	coreDNSFwdSatMinAge = 5 * time.Minute
	// One cluster Event per window.
	coreDNSFwdSatEventCooldown = 30 * time.Minute
	// The boost window stamped on the Deployment — the patcher's
	// replica boost and this check's one-shot bump share it.
	coreDNSFwdSatBoostWindow = 30 * time.Minute
	// coreDNSFwdSatBoostWindow doubles as the heal-budget cooldown —
	// one boost grant per window matches the stamp's own semantics.
)

var (
	// coredns-forward-saturation — 1 while forward rejects
	// persist past the window.
	coreDNSForwardSaturationGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_coredns_forward_saturation",
		Help: "1 while CoreDNS forward max_concurrent rejects persist past the window — coredns-forward-saturation.",
	}, []string{"namespace", "name"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(coreDNSForwardSaturationGauge)
}

// coreDNSFwdSatRejectsQuery is the PromQL read: rejected concurrent
// forward queries per second over 5m.
const coreDNSFwdSatRejectsQuery = `sum(rate(coredns_forward_max_concurrent_rejects_total[5m]))`

// Run evaluates the saturation signature and, past the window,
// stamps the boost + bumps replicas once per boost window.
func (p *coreDNSForwardSaturationCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	var rep probefw.SweepReport

	rejects, rerr := p.PromQuery(ctx, coreDNSFwdSatRejectsQuery)
	if rerr != nil {
		// Inconclusive, not clear — carry held tuples forward so a
		// scrape flap cannot flap a live saturation off.
		for k, lv := range p.emitted.Last() {
			rep.Carry(k, lv)
		}
		rep.InfraErr(fmt.Errorf("coredns forward saturation query: %w", rerr))
		return rep.Result(&p.emitted,
			coreDNSForwardSaturationGauge.DeleteLabelValues,
			"coredns forward saturation: ", ", ")
	}
	saturated := sumSamples(rejects) > 0
	if !saturated {
		p.seen.Forget("coredns")
		return rep.Result(&p.emitted,
			coreDNSForwardSaturationGauge.DeleteLabelValues,
			"coredns forward saturation: ", ", ")
	}
	first, _ := p.seen.Observe("coredns", now)
	if now.Sub(first) < coreDNSFwdSatMinAge {
		return rep.Result(&p.emitted,
			coreDNSForwardSaturationGauge.DeleteLabelValues,
			"coredns forward saturation: ", ", ")
	}

	key := "kube-system/coredns"
	rep.Flag(coreDNSForwardSaturationGauge, key,
		[]string{"kube-system", "coredns"})
	rep.Find(key)
	p.emitSaturationEvent(ctx, log, now)
	p.boostCoreDNS(ctx, log, now)
	return rep.Result(&p.emitted,
		coreDNSForwardSaturationGauge.DeleteLabelValues,
		"coredns forward saturation: ", ", ")
}

// emitSaturationEvent fires ONE deduped Warning event per window.
func (p *coreDNSForwardSaturationCheck) emitSaturationEvent(ctx context.Context,
	log logr.Logger, now time.Time) {

	ck := probefw.SelfHealKey(CheckNameCoreDNSForwardSaturation, "event")
	if p.eventHealed.CooledDown(ck, coreDNSFwdSatEventCooldown, now) {
		return
	}
	if err := kube.EmitWarningEvent(ctx, p.CS, kube.WarningEvent{
		Name:      "coredns-forward-saturation-" + now.Format("20060102-150405"),
		Namespace: "kube-system",
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Deployment",
			Namespace:  "kube-system",
			Name:       "coredns",
		},
		Reason:            "CoreDNSForwardSaturation",
		Note:              "coredns forward max_concurrent rejects sustained — replica boost window stamped",
		ReportingInstance: p.Name,
		Now:               now,
	}); err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: coredns saturation event create failed (RBAC?)",
			"error", err)
		return
	}
	p.eventHealed.Stamp(ck, now)
	log.Info("EVENT: CoreDNSForwardSaturation")
}

// boostCoreDNS stamps AnnoCoreDNSBoostUntil (now+boost window) and
// bumps .spec.replicas by the boost amount — but only when the
// existing stamp is absent or expired (the stamp IS the persisted
// cooldown). The write goes through heal.FluxPatchGate: the
// Deployment is k0s-owned and a Git-pinned replica count would
// otherwise ping-pong the bump.
func (p *coreDNSForwardSaturationCheck) boostCoreDNS(ctx context.Context,
	log logr.Logger, now time.Time) {

	dep, err := p.CS.AppsV1().Deployments("kube-system").
		Get(ctx, "coredns", metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return
	case err != nil:
		metrics.IncError(p.Name)
		log.Info("WARN: coredns boost deployment get failed", "error", err)
		return
	}
	if until, ok := kube.AnnoTimeCtx(ctx, dep, kube.AnnoCoreDNSBoostUntil); ok &&
		now.Before(until) {
		return // boost window still fresh — stamp is the cooldown
	}
	if p.boostReplicas <= 0 {
		return // operator disabled the bump — the stamp alone buys nothing
	}
	if !heal.FluxPatchGate("deployment", dep, "kube-system/coredns", now) {
		log.Info("SKIP: coredns boost patch — Flux Heal-Revert Loop " +
			"(Git owns this Deployment; fix the source)")
		return
	}
	// The replica bump is a live-workload write — it must pass the
	// shared maintenance mutex + heal budget like every other
	// destructive-adjacent act (fail closed on unverifiable).
	ck := probefw.SelfHealKey(CheckNameCoreDNSForwardSaturation, "boost")
	proceed, unverifiable := p.HealAllowed(ctx, log, &p.Heals,
		ck, coreDNSFwdSatBoostWindow, now)
	switch {
	case unverifiable:
		metrics.IncError(p.Name)
		return
	case !proceed:
		return
	}
	until := now.Add(coreDNSFwdSatBoostWindow).UTC().Format(time.RFC3339)
	current := int32(0)
	if dep.Spec.Replicas != nil {
		current = *dep.Spec.Replicas
	}
	boosted := current + p.boostReplicas
	payload, err := json.Marshal(map[string]any{
		"spec": map[string]any{"replicas": boosted},
		"metadata": map[string]any{"annotations": map[string]any{
			kube.AnnoCoreDNSBoostUntil: until,
		}},
	})
	if err != nil {
		metrics.IncError(p.Name)
		return
	}
	if _, err := p.CS.AppsV1().Deployments("kube-system").Patch(ctx,
		"coredns", types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "coredns boost patch failed")
		return
	}
	log.Info("ACTION: coredns forward saturation boost",
		"replicas", current, "->", boosted, "boostUntil", until)
	// Mirror the landed annotation + replica count for later checks
	// this sweep.
	kube.RecordAnnoPatch(ctx, dep, payload)
	dep.Spec.Replicas = &boosted
	p.InvalidateDeployments(ctx)
}

// sumSamples totals a PromQuery result — the scalar query returns
// at most one sample, but summing keeps a multi-series surprise
// from silently under-reading. (Local copy: the watchdogs helper
// is package-private.)
func sumSamples(samples []promq.Sample) float64 {
	total := 0.0
	for _, s := range samples {
		total += s.Value
	}
	return total
}

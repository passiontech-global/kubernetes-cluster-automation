// gitops_mass_prune_guard.go — Wave 4C #13 GitOps mass-prune safety guard
// (gitops-mass-prune-guard): tracks per-object inventory counts across sweeps
// for prune-enabled Flux Kustomizations and ArgoCD Applications (skipping
// initial warm-up and newly observed objects). Flags mass_prune_anomaly when
// prev >= 10 and inventory drops strictly > 40% without
// passiontech.dev/mass-prune-expected=true (or with an active
// ArtifactFailed/ComparisonError/SourceError condition).
//
// Default posture is detect-only (node_automation_gitops_mass_prune_alert +
// Warning Event GitOpsMassPruneDetected). Opt-in circuit breaker ONLY for Flux
// Kustomizations annotated passiontech.dev/mass-prune-guard=suspend: gated by
// HealAllowed + cooldown (bypassing FluxPatchGate like emergency storm
// relief), patches spec.suspend=true + passiontech.dev/mass-prune-suspended-by,
// and NEVER auto-unsuspends or suspends ArgoCD Applications.
package gitops

import (
	"context"
	json "encoding/json/v2"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

const (
	CheckNameGitOpsMassPruneGuard = "gitops-mass-prune-guard"

	gitopsMassPruneMinBaseline     = 10
	gitopsMassPruneDropPercent     = 40
	gitopsMassPruneEventCooldown   = 30 * time.Minute
	gitopsMassPruneSuspendCooldown = 30 * time.Minute
	gitopsMassPruneEventReason     = "GitOpsMassPruneDetected"
)

var (
	gitopsMassPruneAlertGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_gitops_mass_prune_alert",
		Help: "1 while a prune-enabled Flux Kustomization or ArgoCD Application exhibits a >40% inventory drop from >=10 resources without opt-out.",
	}, []string{"kind", "namespace", "name"})

	gitopsMassPruneSuspendsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_automation_gitops_mass_prune_suspends_total",
		Help: "Flux Kustomizations suspended by the opt-in GitOps mass-prune circuit breaker, by kind.",
	}, []string{"kind"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		gitopsMassPruneAlertGauge,
		gitopsMassPruneSuspendsTotal,
	)
}

type gitopsMassPruneGuardCheck struct {
	*probefw.Deps

	prevInventory map[string]int
	warmedUp      map[string]bool
	emitted       state.GaugeLedger[string]
	eventCooldown state.CooldownSet
	suspendHealed state.CooldownSet
}

// NewGitOpsMassPruneGuardCheck builds the gitops-mass-prune-guard check.
func NewGitOpsMassPruneGuardCheck(d *probefw.Deps) probefw.Check {
	return &gitopsMassPruneGuardCheck{Deps: d}
}

type gitopsPruneSource struct {
	gvr          schema.GroupVersionResource
	kind         string
	pruneEnabled func(*unstructured.Unstructured) bool
	inventoryLen func(*unstructured.Unstructured) int
	canSuspend   bool
}

var gitopsPruneSources = []gitopsPruneSource{
	{
		gvr:  kube.GVRFluxKustomization,
		kind: "Kustomization",
		pruneEnabled: func(u *unstructured.Unstructured) bool {
			prune, ok := kube.NestedBool(u.Object, "spec", "prune")
			return ok && prune
		},
		inventoryLen: func(u *unstructured.Unstructured) int {
			entries, _ := kube.NestedSlice(u.Object, "status", "inventory", "entries")
			return len(entries)
		},
		canSuspend: true,
	},
	{
		gvr:  kube.GVRArgoCDApplication,
		kind: "Application",
		pruneEnabled: func(u *unstructured.Unstructured) bool {
			prune, ok := kube.NestedBool(u.Object, "spec", "syncPolicy", "automated", "prune")
			return ok && prune
		},
		inventoryLen: func(u *unstructured.Unstructured) int {
			resources, _ := kube.NestedSlice(u.Object, "status", "resources")
			return len(resources)
		},
		canSuspend: false,
	},
}

func (c *gitopsMassPruneGuardCheck) Run(ctx context.Context) probefw.Result {
	if r := c.RequireDyn("gitops mass prune guard"); r != nil {
		return *r
	}
	log := logf.FromContext(ctx)
	now := c.Now()

	c.eventCooldown.PruneExpired(now, gitopsMassPruneEventCooldown)
	c.suspendHealed.PruneExpired(now, gitopsMassPruneSuspendCooldown)
	if c.prevInventory == nil {
		c.prevInventory = map[string]int{}
	}
	if c.warmedUp == nil {
		c.warmedUp = map[string]bool{}
	}

	var rep probefw.SweepReport
	for _, src := range gitopsPruneSources {
		c.scanSource(ctx, log, now, src, &rep)
	}

	return rep.Result(&c.emitted, gitopsMassPruneAlertGauge.DeleteLabelValues,
		"gitops mass-prune detected: ", ", ")
}

func (c *gitopsMassPruneGuardCheck) scanSource(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	src gitopsPruneSource,
	rep *probefw.SweepReport,
) {
	items, err := c.AllUnstructured(ctx, src.gvr)
	switch {
	case kube.IsCRDAbsent(err):
		c.resetKindBaseline(src.kind)
		return
	case apierrors.IsForbidden(err):
		log.V(1).Info("WARN: gitops mass-prune list skipped (403)", "kind", src.kind, "error", err)
		c.carryKindHeld(src.kind, rep)
		return
	case err != nil:
		c.carryKindHeld(src.kind, rep)
		rep.InfraErr(fmt.Errorf("list %s: %w", src.gvr.Resource, err))
		return
	}

	seenKeys := make(map[string]bool, len(items))
	kindWarmed := c.warmedUp[src.kind]

	for i := range items {
		u := &items[i]
		if u.GetDeletionTimestamp() != nil || !src.pruneEnabled(u) {
			continue
		}
		ns, name := u.GetNamespace(), u.GetName()
		key := src.kind + "/" + ns + "/" + name
		seenKeys[key] = true
		curr := src.inventoryLen(u)

		prev, hasPrev := c.prevInventory[key]
		if !kindWarmed || !hasPrev {
			c.prevInventory[key] = curr
			continue
		}

		dropped := prev >= gitopsMassPruneMinBaseline &&
			curr < prev &&
			(prev-curr)*100 > gitopsMassPruneDropPercent*prev
		expected := strings.EqualFold(
			strings.TrimSpace(kube.EffectiveAnno(ctx, u, kube.AnnoMassPruneExpected)),
			"true")
		hasErr := hasActiveRenderOrSourceError(u)
		anomaly := dropped && (!expected || hasErr)

		if !anomaly {
			c.prevInventory[key] = curr
			continue
		}

		if src.canSuspend && strings.EqualFold(
			strings.TrimSpace(kube.EffectiveAnno(ctx, u, kube.AnnoMassPruneGuard)),
			"suspend") {
			if c.maybeSuspendKustomization(ctx, log, now, u) {
				// Target vanished between list and patch — drop its baseline
				// and skip alert emission so GaugeLedger prunes any stale series.
				delete(seenKeys, key)
				delete(c.prevInventory, key)
				continue
			}
		}

		// Retain pre-drop prevInventory[key] while anomalous so
		// GaugeLedger does not flicker clear on the next sweep.
		detail := fmt.Sprintf("%s/%s/%s(prev=%d,curr=%d)", src.kind, ns, name, prev, curr)
		rep.Emit(gitopsMassPruneAlertGauge, key, []string{src.kind, ns, name}, detail)
		c.emitAnomalyEvent(ctx, log, now, src.kind, u, prev, curr)
	}

	c.warmedUp[src.kind] = true
	prefix := src.kind + "/"
	for k := range c.prevInventory {
		if strings.HasPrefix(k, prefix) && !seenKeys[k] {
			delete(c.prevInventory, k)
		}
	}
}

func (c *gitopsMassPruneGuardCheck) resetKindBaseline(kind string) {
	c.warmedUp[kind] = false
	prefix := kind + "/"
	for k := range c.prevInventory {
		if strings.HasPrefix(k, prefix) {
			delete(c.prevInventory, k)
		}
	}
}

func (c *gitopsMassPruneGuardCheck) carryKindHeld(kind string, rep *probefw.SweepReport) {
	prefix := kind + "/"
	for k, lv := range c.emitted.Last() {
		if strings.HasPrefix(k, prefix) {
			rep.Carry(k, lv)
		}
	}
}

func (c *gitopsMassPruneGuardCheck) emitAnomalyEvent(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	kind string,
	u *unstructured.Unstructured,
	prev, curr int,
) {
	ns, name := u.GetNamespace(), u.GetName()
	ck := probefw.SelfHealKey(CheckNameGitOpsMassPruneGuard, "event/"+kind+"/"+ns+"/"+name)
	evNS := ns
	if evNS == "" {
		evNS = "default"
	}
	probefw.EmitWarningDeduped(ctx, c.CS, log, &c.eventCooldown, ck, gitopsMassPruneEventCooldown, now, kube.WarningEvent{
		Name:      kube.TruncatedEventName("mass-prune."+kind+"."+ns+"."+name, kind+"/"+ns+"/"+name, now),
		Namespace: evNS,
		Regarding: corev1.ObjectReference{
			APIVersion: u.GetAPIVersion(),
			Kind:       kind,
			Namespace:  ns,
			Name:       name,
			UID:        u.GetUID(),
		},
		Reason: gitopsMassPruneEventReason,
		Note: fmt.Sprintf(
			"GitOps mass-prune detected on %s %s/%s: tracked inventory dropped from %d to %d (>%d%%)",
			kind, ns, name, prev, curr, gitopsMassPruneDropPercent),
		ReportingInstance: c.Name,
	})
}

func (c *gitopsMassPruneGuardCheck) maybeSuspendKustomization(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	u *unstructured.Unstructured,
) (vanished bool) {
	if suspended, _ := kube.NestedBool(u.Object, "spec", "suspend"); suspended {
		return false
	}
	ns, name := u.GetNamespace(), u.GetName()
	ck := probefw.SelfHealKey(CheckNameGitOpsMassPruneGuard, "suspend/"+ns+"/"+name)
	proceed, unverifiable := c.HealAllowed(ctx, log, &c.suspendHealed,
		ck, gitopsMassPruneSuspendCooldown, now)
	switch {
	case unverifiable:
		metrics.IncError(c.Name)
		return false
	case !proceed:
		return false
	}

	patch, err := json.Marshal(map[string]any{
		"spec": map[string]any{"suspend": true},
		"metadata": map[string]any{
			"annotations": map[string]string{
				kube.AnnoMassPruneSuspendedBy: CheckNameGitOpsMassPruneGuard,
			},
		},
	})
	if err != nil {
		heal.RefundGrant(now)
		metrics.IncError(c.Name)
		return false
	}
	if _, err := c.Dyn.Resource(kube.GVRFluxKustomization).Namespace(ns).Patch(
		ctx, name, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		switch {
		case apierrors.IsForbidden(err):
			heal.RefundGrant(now)
			log.V(1).Info("WARN: Flux Kustomization mass-prune suspend forbidden (RBAC pending)",
				"object", ns+"/"+name)
		case kube.IsCRDAbsent(err):
			heal.RefundGrant(now)
			log.V(1).Info("WARN: Flux Kustomization mass-prune suspend target not found (404)",
				"object", ns+"/"+name, "error", err)
			return true
		default:
			metrics.IncError(c.Name)
			log.Error(err, "Flux Kustomization mass-prune suspend failed", "object", ns+"/"+name)
		}
		return false
	}
	c.suspendHealed.Stamp(ck, now)
	kube.RecordAnnoPatch(ctx, u, patch)
	c.InvalidateUnstructuredGVR(ctx, kube.GVRFluxKustomization)
	gitopsMassPruneSuspendsTotal.WithLabelValues("Kustomization").Inc()
	log.Info("ACTION: suspended Flux Kustomization via mass-prune circuit breaker",
		"object", ns+"/"+name)
	return false
}

func hasActiveRenderOrSourceError(u *unstructured.Unstructured) bool {
	active := false
	kube.ForEachCondition(u.Object, func(cond kube.Condition) bool {
		lt := strings.ToLower(cond.Type)
		lr := strings.ToLower(cond.Reason)
		if isRenderOrSourceErrToken(lt) && cond.Status != "False" {
			active = true
			return false
		}
		if isRenderOrSourceErrToken(lr) &&
			(cond.Status == "False" || cond.Status == "" || (cond.Type == "Stalled" && cond.Status == "True")) {
			active = true
			return false
		}
		return true
	}, "status", "conditions")
	return active
}

func isRenderOrSourceErrToken(s string) bool {
	return strings.Contains(s, "artifactfailed") ||
		strings.Contains(s, "comparisonerror") ||
		strings.Contains(s, "sourceerror")
}

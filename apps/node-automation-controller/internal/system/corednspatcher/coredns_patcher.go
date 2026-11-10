// coredns_patcher.go — port of the coredns-topology-spread CronJob
// (infrastructure/base/scaling/coredns/coredns-topology-spread.yaml in
// passiontech-fluxcd, plus the cicd override single-zone-topology-patch.yaml).
//
// Keeps deployment kube-system/coredns at the pinned probe timeouts
// (incl. livenessProbe.failureThreshold=5), rollingUpdate
// maxUnavailable=1, resources and topologySpreadConstraints. The
// Deployment is owned by
// the k0s stack applier, which reverts it on every apply — its stock
// manifest carries a required hostname podAntiAffinity (max 1 pod
// kube-dns per node) so a surge pod can never schedule, and the 1s
// default probe timeouts mass-kill pods under node load.
//
// Spread policy (config-driven, was ZONE_WHEN/ZONE_MIN_DOMAINS):
// zone = DoNotSchedule + minDomains=2 on multi-zone clusters —
// guarantees >=1 DNS backend per zone so service topology keeps
// resolving locally during an inter-DC degrade; cicd (single zone)
// runs ScheduleAnyway with no minDomains — DoNotSchedule on a
// 1-domain cluster would wedge the rollout forever. hostname =
// ScheduleAnyway: ~1 pod/node steady state, surge still schedules.
// nodeTaintsPolicy/nodeAffinityPolicy=Honor keep tainted/drained
// nodes out of the domain calculation so DoNotSchedule can't lock
// the rollout. The watch patches drift back in <1s; the 15m requeue
// replaces the old hourly crontab.
//
// Proportional scaling (replaces cluster-proportional-autoscaler):
// when minReplicas>0 the reconciler also pins .spec.replicas to the
// CPA "linear" formula with includeUnschedulableNodes=true —
// max(minReplicas, ceil(totalNodes/nodesPerReplica)) — and a Node
// watch re-reconciles on every node add/remove. minReplicas<=0
// disables the pin (the Deployment keeps its own .spec.replicas) so
// a cluster can re-enable the standalone CPA without being fought.
//
// Corefile negative-cache guard (negative-cache-guard): the kube-system/coredns
// ConfigMap is k0s-managed and drifts back to a bare `cache 30`,
// which negative-caches NXDOMAIN for the full SOA TTL — a Job pod
// that outraces endpointslice-controller at deploy time eats a
// 30s-cached NXDOMAIN and dies on backoffLimit. The reconciler
// rewrites a denial-less cache directive to `cache 30 { success
// 9984 30; denial 9984 5 }`, capping negative caching at 5s while
// keeping the 30s positive cache.
package corednspatcher

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/system/pinnedworkload"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

var (
	corednsWantReq = corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse("25m"),
		corev1.ResourceMemory: resource.MustParse("64Mi"),
	}
	corednsWantLim = corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse("1000m"),
		corev1.ResourceMemory: resource.MustParse("256Mi"),
	}
)

type corednsPatcher struct {
	cs              kubernetes.Interface
	nodeReader      kube.CachedNodeReader
	reader          kube.CachedObjectReader
	zoneWhen        string
	minDomains      int
	minReplicas     int
	nodesPerReplica int
}

// The watch wiring below installs this package-level predicate
// verbatim — tests exercise the exact unit the controller runs
// instead of introspecting controller-runtime internals. The Node
// watch predicate is the shared pinnedworkload.NodeCountChanges.

// onlyCoreDNSDeployment pins the For() watch to kube-system/coredns —
// the informer sees every kube-system Deployment.
var onlyCoreDNSDeployment = pinnedworkload.OnlyNamespacedName("kube-system", "coredns")

// Setup reconciles only the coredns Deployment (the
// informer sees every kube-system Deployment — the predicate pins
// ns/name). Clusters without the module (COREDNS_PATCHER_ENABLED=
// false, resolved by setupModules into Deps.Disabled — e.g. ones
// managing coredns themselves) skip registration entirely.
//
// minReplicas/nodesPerReplica are the CPA-linear replica pin — see
// pinnedworkload.ReplicaPin. minReplicas<=0 disables the pin entirely.
func Setup(d shared.Deps) error {
	return shared.SetupWithConfig(d, configFromEnv, func(cfg corednsPatcherConfig) error {
		// zoneWhen lands verbatim in the whenUnsatisfiable field of the
		// rendered patch — a typo is not caught until the apiserver
		// rejects the invalid enum, at which point the Deployment
		// perpetually reads as drifted and every reconcile fails (eternal
		// error loop). Validate at boot instead — but disable only this
		// module: a returned error would propagate through setupModules
		// and abort ALL 32 modules for one ConfigMap typo. The error is
		// still loud: logged at Error level and counted on the queue's
		// error metric.
		switch corev1.UnsatisfiableConstraintAction(cfg.zoneWhen) {
		case corev1.DoNotSchedule, corev1.ScheduleAnyway:
		default:
			err := fmt.Errorf("invalid zoneWhen %q — must be %q or %q "+
				"(UnsatisfiableConstraintAction); module disabled",
				cfg.zoneWhen, corev1.DoNotSchedule, corev1.ScheduleAnyway)
			logf.Log.WithName(d.Name).Error(err, "setup failed")
			metrics.IncError(d.Name)
			return nil
		}
		logf.Log.WithName(d.Name).Info("registered",
			"zoneWhen", cfg.zoneWhen, "zoneMinDomains", cfg.zoneMinDomains,
			"minReplicas", cfg.minReplicas, "nodesPerReplica", cfg.nodesPerReplica)
		b := ctrl.NewControllerManagedBy(d.Mgr).
			Named(d.Name).
			For(&appsv1.Deployment{}, builder.WithPredicates(onlyCoreDNSDeployment))
		// Node add/remove changes the proportional replica total; the
		// watch is registered only while the pin is enabled — see
		// pinnedworkload.ReplicaPin.WatchNodes.
		b = pinnedworkload.ReplicaPin{
			MinReplicas:     cfg.minReplicas,
			NodesPerReplica: cfg.nodesPerReplica,
		}.WatchNodes(b, "coredns-patcher-sweep")
		r := &corednsPatcher{cs: d.CS, nodeReader: d.Mgr.GetClient(), zoneWhen: cfg.zoneWhen,
			minDomains: cfg.zoneMinDomains, minReplicas: cfg.minReplicas, nodesPerReplica: cfg.nodesPerReplica}
		if d.Mgr != nil {
			r.reader = d.Mgr.GetClient()
		}
		// CountReconcile owns the returned-error accounting — one
		// IncError per non-nil Reconcile return; the reconcile body
		// never IncErrors an error it returns.
		return b.Complete(shared.CountReconcile(d.Name, r.Reconcile))
	})
}

// corednsPatcherConfig is the module's env-resolved knob set — what
// the old moduleConfigFromEnv returned, now carried through
// SetupWithConfig's parse step.
type corednsPatcherConfig struct {
	zoneWhen        string
	zoneMinDomains  int
	minReplicas     int
	nodesPerReplica int
}

// configFromEnv resolves the COREDNS_* knobs. SetupWithConfig runs it
// BEFORE the Deps.Disabled gate — the old moduleConfigFromEnv
// resolved them at boot regardless of enabled state, so an
// unparseable COREDNS_* value still warns on a disabled module.
func configFromEnv() corednsPatcherConfig {
	return corednsPatcherConfig{
		zoneWhen:        envx.Getenv("COREDNS_PATCHER_ZONE_WHEN", "DoNotSchedule"),
		zoneMinDomains:  envx.GetenvInt("COREDNS_PATCHER_ZONE_MIN_DOMAINS", 2),
		minReplicas:     envx.GetenvInt("COREDNS_MIN_REPLICAS", 4),
		nodesPerReplica: envx.GetenvInt("COREDNS_NODES_PER_REPLICA", 1),
	}
}

// Reconcile delegates to the shared pinned-Deployment skeleton —
// this module only supplies the kube-system/coredns identity, the
// drift check and the patch body — then reconciles the Corefile's
// negative-cache cap on the same requeue cadence (the ConfigMap is
// not watched; the 15m requeue plus every Deployment reconcile is
// fresh enough for a drift k0s only re-applies on stack changes).
func (r *corednsPatcher) Reconcile(ctx context.Context, _ reconcile.Request) (ctrl.Result, error) {
	res, err := pinnedworkload.DeploymentSpec{
		CS:         r.cs,
		Reader:     r.reader,
		NodeReader: r.nodeReader,
		Namespace:  "kube-system",
		Name:       "coredns",
		Container:  "coredns",
		Replicas: pinnedworkload.ReplicaPin{
			MinReplicas:     r.minReplicas,
			NodesPerReplica: r.nodesPerReplica,
		},
		NoDriftLog: "probes/resources/topology/replicas already pinned - nothing to do",
		Drifted: func(d *appsv1.Deployment, wantReplicas int32) bool {
			return corednsNeedsPatch(d, r.zoneWhen, r.minDomains, wantReplicas)
		},
		PatchBody: func(wantReplicas int32) ([]byte, error) {
			return corednsPatchBody(r.zoneWhen, r.minDomains, wantReplicas)
		},
	}.Reconcile(ctx)
	if err != nil {
		return res, err
	}
	if err := r.reconcileCorefile(ctx); err != nil {
		return ctrl.Result{}, err
	}
	return res, nil
}

// corednsMinDomainsWanted gates minDomains onto DoNotSchedule only —
// the API rejects minDomains combined with ScheduleAnyway (the cicd
// override therefore runs ScheduleAnyway with minDomains disabled).
func corednsMinDomainsWanted(zoneWhen string, minDomains int) bool {
	return zoneWhen == string(corev1.DoNotSchedule) && minDomains > 0
}

// corednsNeedsPatch reports whether the Deployment lacks any pinned
// field — probe timeouts + liveness failure threshold, requests/
// limits, cleared affinity, the two wanted spread constraints, the
// rollingUpdate.maxUnavailable=1 strategy pin, or (when proportional
// scaling is on, wantReplicas>0) a drifted .spec.replicas. A missing
// coredns container counts as drifted (same as the shell's empty
// jsonpath probe).
func corednsNeedsPatch(d *appsv1.Deployment, zoneWhen string, minDomains int, wantReplicas int32) bool {
	// Replica drift only counts when the pin is enabled — a nil
	// .spec.replicas defaults to 1 at the API but still means "we
	// never pinned it", so it counts as drifted too.
	if pinnedworkload.ReplicaDrifted(d, wantReplicas) {
		return true
	}
	ps := d.Spec.Template.Spec
	for i := range ps.Containers {
		c := &ps.Containers[i]
		if c.Name != "coredns" {
			continue
		}
		if pinnedworkload.ProbeTimeoutsDrifted(c) ||
			corednsLivenessThresholdDrifted(c) ||
			pinnedworkload.ResourcesDrifted(c, corednsWantReq, corednsWantLim) ||
			corednsStrategyDrifted(d) {
			return true
		}
		if pinnedworkload.AffinitySet(ps) {
			return true
		}
		return !corednsTopologyOK(ps.TopologySpreadConstraints, zoneWhen, minDomains)
	}
	return true
}

// corednsLivenessThresholdDrifted requires the pinned
// livenessProbe.failureThreshold=5 — at the default 10s period a
// single slow /ready sync while the apiserver is loaded must not
// restart the pod (5 misses ≈ 50s of tolerance before kubelet acts).
// The readiness probe keeps its default threshold: unready is the
// correct signal there, only liveness needs the wider fuse.
func corednsLivenessThresholdDrifted(c *corev1.Container) bool {
	return c.LivenessProbe == nil || c.LivenessProbe.FailureThreshold != 5
}

// corednsStrategyDrifted requires the pinned
// strategy.rollingUpdate.maxUnavailable=1 — the k8s default 25%
// can take a quarter of a small fleet down in one rollout while the
// apiserver is already degraded (the W21-G4 post-mortem class).
// maxSurge stays unpinned: surge pods are what keep DNS answers
// flowing mid-rollout. A Recreate strategy is drift too — the pin
// only exists under RollingUpdate.
func corednsStrategyDrifted(d *appsv1.Deployment) bool {
	st := d.Spec.Strategy
	if st.Type == appsv1.RecreateDeploymentStrategyType {
		return true
	}
	ru := st.RollingUpdate
	return ru == nil || ru.MaxUnavailable == nil ||
		ru.MaxUnavailable.Type != intstr.Int || ru.MaxUnavailable.IntValue() != 1
}

// corednsTopologyOK requires both wanted constraints: zone per the
// configured whenUnsatisfiable/minDomains and hostname ScheduleAnyway,
// each selector k8s-app=kube-dns with Honor node-inclusion policies.
func corednsTopologyOK(tscs []corev1.TopologySpreadConstraint, zoneWhen string, minDomains int) bool {
	zoneOK, hostOK := false, false
	for _, c := range tscs {
		sel := c.LabelSelector != nil &&
			c.LabelSelector.MatchLabels["k8s-app"] == "kube-dns"
		if c.MaxSkew != 1 {
			continue
		}
		honor := c.NodeTaintsPolicy != nil &&
			*c.NodeTaintsPolicy == corev1.NodeInclusionPolicyHonor &&
			c.NodeAffinityPolicy != nil &&
			*c.NodeAffinityPolicy == corev1.NodeInclusionPolicyHonor
		switch c.TopologyKey {
		case "topology.kubernetes.io/zone":
			if c.WhenUnsatisfiable != corev1.UnsatisfiableConstraintAction(zoneWhen) ||
				!sel || !honor {
				continue
			}
			// minDomains can only exist under DoNotSchedule (API
			// validation), so the not-wanted case means nil.
			if corednsMinDomainsWanted(zoneWhen, minDomains) {
				zoneOK = c.MinDomains != nil && *c.MinDomains == int32(minDomains)
			} else {
				zoneOK = c.MinDomains == nil
			}
		case "kubernetes.io/hostname":
			if c.WhenUnsatisfiable == corev1.ScheduleAnyway && sel && honor {
				hostOK = true
			}
		}
	}
	return zoneOK && hostOK
}

// corednsPatchBody renders the strategic-merge patch — containers
// merge by name (k0s-owned args/labels are untouched), affinity:null
// drops the required hostname anti-affinity, and the constraints list
// merges on topologyKey. minDomains is set to the wanted value, or to
// explicit null when not wanted: the constraints list merges per
// topologyKey, so an omitted minDomains would SURVIVE from a previous
// DoNotSchedule patch — leaving minDomains on a ScheduleAnyway
// constraint that the API then rejects (the cicd shell override sent
// "minDomains": null for the same reason).
//
// spec.replicas is only sent when wantReplicas>0 — an omitted key
// keeps the Deployment's current replica count under strategic
// merge, so disabled scaling never fights an external autoscaler.
func corednsPatchBody(zoneWhen string, minDomains int, wantReplicas int32) ([]byte, error) {
	zone := map[string]any{
		"maxSkew":            1,
		"topologyKey":        "topology.kubernetes.io/zone",
		"whenUnsatisfiable":  zoneWhen,
		"nodeTaintsPolicy":   "Honor",
		"nodeAffinityPolicy": "Honor",
		"labelSelector":      map[string]any{"matchLabels": map[string]any{"k8s-app": "kube-dns"}},
	}
	if corednsMinDomainsWanted(zoneWhen, minDomains) {
		zone["minDomains"] = minDomains
	} else {
		zone["minDomains"] = nil // explicit null — deletes a stale value
	}
	spec := map[string]any{
		// The strategy pin merges field-wise: maxUnavailable=1 lands
		// while an existing maxSurge survives; "type" is pinned so a
		// Recreate drift cannot survive the patch (the drift check
		// treats it as drift, so leaving it would re-patch forever).
		"strategy": map[string]any{
			"type":          "RollingUpdate",
			"rollingUpdate": map[string]any{"maxUnavailable": 1},
		},
		"template": map[string]any{
			"spec": map[string]any{
				"affinity": nil,
				"containers": []any{map[string]any{
					"name": "coredns",
					"livenessProbe": map[string]any{
						"timeoutSeconds": 5, "failureThreshold": 5},
					"readinessProbe": map[string]any{"timeoutSeconds": 5},
					"resources": map[string]any{
						"requests": map[string]any{"cpu": "25m", "memory": "64Mi"},
						"limits":   map[string]any{"cpu": "1000m", "memory": "256Mi"},
					},
				}},
				"topologySpreadConstraints": []any{
					zone,
					map[string]any{
						"maxSkew":            1,
						"topologyKey":        "kubernetes.io/hostname",
						"whenUnsatisfiable":  "ScheduleAnyway",
						"nodeTaintsPolicy":   "Honor",
						"nodeAffinityPolicy": "Honor",
						"labelSelector":      map[string]any{"matchLabels": map[string]any{"k8s-app": "kube-dns"}},
					},
				},
			},
		},
	}
	if wantReplicas > 0 {
		spec["replicas"] = wantReplicas
	}
	return json.Marshal(map[string]any{"spec": spec})
}

// ---------------------------------------------------------------------------
// Corefile negative-cache reconcile (negative-cache-guard)
// ---------------------------------------------------------------------------

const (
	corednsConfigNS   = "kube-system"
	corednsConfigName = "coredns"
	corednsCorefile   = "Corefile"
	// corefileDenialDirective is the injected negative-cache cap —
	// 9984 entries at 5s TTL (a bare `cache 30` negative-caches
	// NXDOMAIN for the full SOA TTL and kills fresh-deploy Jobs).
	corefileDenialDirective = "denial 9984 5"
	corefileSuccessLine     = "success 9984 30"
)

// reconcileCorefile reads kube-system/coredns's Corefile and merge-
// patches it when a cache directive lacks a denial cap (see the
// header note). A missing ConfigMap/Corefile is tolerated — the k0s
// stack applier owns the object and re-creates it; a patch or get
// failure surfaces so the reconcile retries on the apiserver's
// backoff instead of silently leaving a 30s NXDOMAIN cache live.
func (r *corednsPatcher) reconcileCorefile(ctx context.Context) error {
	cm, err := r.cs.CoreV1().ConfigMaps(corednsConfigNS).
		Get(ctx, corednsConfigName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return nil
	case err != nil:
		return fmt.Errorf("get configmap %s/%s: %w",
			corednsConfigNS, corednsConfigName, err)
	}
	corefile := cm.Data[corednsCorefile]
	if corefile == "" {
		return nil
	}
	rewritten, changed := corefileDenialCap(corefile)
	if !changed {
		return nil
	}
	payload, err := json.Marshal(map[string]any{
		"data": map[string]any{corednsCorefile: rewritten},
	})
	if err != nil {
		return fmt.Errorf("marshal coredns corefile patch: %w", err)
	}
	if _, err := r.cs.CoreV1().ConfigMaps(corednsConfigNS).Patch(ctx,
		corednsConfigName, types.MergePatchType, payload,
		metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("patch configmap %s/%s: %w",
			corednsConfigNS, corednsConfigName, err)
	}
	logf.FromContext(ctx).Info("PATCH: Corefile cache directive gains a 5s denial cap " +
		"(NXDOMAIN no longer negative-caches for the full SOA TTL)")
	return nil
}

// corefileDenialCap rewrites every cache directive in the Corefile
// that carries no denial directive. Bare `cache 30` (optionally with
// zone args) expands to the success+denial block; an already-braced
// `cache 30 { ... }` block keeps its contents and only gains the
// denial line it lacks. A block that already declares denial is
// untouched — idempotent by construction. Returns (rewritten, changed).
//
// The parser is a line scan, not a Corefile grammar: `cache` is the
// only directive the rewrite touches, brace depth tracks the block
// it opens, and comment lines (#…) can never satisfy or break the
// denial check.
//
// Comments are stripped BEFORE any brace counting or slicing: a `#`
// inside a Corefile line comments out the rest of the line, so a
// brace (or a whole directive) inside a comment must never open,
// close, or depth-count a block — `cache 30 { # ops note }` opens a
// MULTI-line block (the `}` lives in the comment), and `# }` in a
// block body must not close it.
func corefileDenialCap(corefile string) (string, bool) {
	lines := strings.Split(corefile, "\n")
	changed := false
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		fields := strings.Fields(trimmed)
		if len(fields) == 0 || fields[0] != "cache" {
			continue
		}
		indent := lines[i][:len(lines[i])-len(strings.TrimLeft(lines[i], " \t"))]
		// Code-only view of the line: everything up to the first `#`.
		// A prefix of the original line, so indices into it index the
		// original too.
		code := strings.TrimSpace(stripCorefileComment(trimmed))
		open := strings.Index(code, "{")
		switch {
		case open < 0:
			// Bare form: `cache 30 [zones...]` → replace with the
			// braced success+denial block, keeping the args and the
			// line's own indentation. A trailing comment is carried
			// INSIDE the braces — appended after the `{` it would be
			// commented out of the Corefile entirely.
			comment := ""
			if hash := strings.Index(lines[i], "#"); hash >= 0 {
				if c := strings.TrimSpace(lines[i][hash:]); c != "" {
					comment = " " + c
				}
			}
			lines[i] = indent + code + " {" + comment + "\n" +
				indent + "    " + corefileSuccessLine + "\n" +
				indent + "    " + corefileDenialDirective + "\n" +
				indent + "}"
			changed = true
		case strings.LastIndex(code, "}") > open:
			// Inline single-line block `cache 30 { denial 9984 5 }`:
			// a denial inside already satisfies; without one, inject
			// before the closing brace. `code` is a prefix of
			// `lines[i]` minus the indent, so code indices shift by
			// len(indent) onto the original line — and a `}` inside a
			// trailing comment is never the injection point.
			inner := code[open+1 : strings.LastIndex(code, "}")]
			if !corefileBlockHasDenial(inner) {
				last := len(indent) + strings.LastIndex(code, "}")
				lines[i] = lines[i][:last] + " " + corefileDenialDirective + " }" +
					lines[i][last+len("}"):]
				changed = true
			}
		default:
			// Braced multi-line block: find the matching close and
			// inject denial before it when absent. Depth counts
			// comment-stripped braces only — `# }` never closes, and a
			// `{` or `}` inside a trailing comment never nests.
			depth := strings.Count(code, "{") - strings.Count(code, "}")
			hasDenial := false
			closeIdx := -1
			for j := i + 1; j < len(lines) && depth > 0; j++ {
				t := strings.TrimSpace(stripCorefileComment(lines[j]))
				depth += strings.Count(t, "{") - strings.Count(t, "}")
				if t != "" && strings.Fields(t)[0] == "denial" {
					hasDenial = true
				}
				if depth == 0 {
					closeIdx = j
				}
			}
			if !hasDenial && closeIdx >= 0 {
				lines[closeIdx] = indent + "    " + corefileDenialDirective +
					"\n" + lines[closeIdx]
				changed = true
				i = closeIdx // skip past the handled block
			} else if closeIdx >= 0 {
				i = closeIdx
			}
		}
	}
	if !changed {
		return corefile, false
	}
	return strings.Join(lines, "\n"), true
}

// stripCorefileComment cuts a Corefile line at its first `#` —
// everything from there on is a comment (coredns has no escape for a
// literal # in directive syntax, so the cut is unconditional).
func stripCorefileComment(line string) string {
	if i := strings.Index(line, "#"); i >= 0 {
		return line[:i]
	}
	return line
}

// corefileBlockHasDenial reports whether an inline cache block body
// already declares a denial directive. Separators inside the braces
// are optional (`{ success 9984 30  denial 9984 5 }` is what our own
// injector emits on a separator-less input), so the scan is for a
// bare `denial` token anywhere in the body — a zone arg such as
// `denial.example.com` lands as a single field and cannot collide.
func corefileBlockHasDenial(inner string) bool {
	for _, f := range strings.Fields(inner) {
		if f == "denial" {
			return true
		}
	}
	return false
}

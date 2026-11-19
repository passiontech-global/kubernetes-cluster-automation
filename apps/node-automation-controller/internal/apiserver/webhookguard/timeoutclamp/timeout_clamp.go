// Package timeoutclamp audits and clamps excessive admission webhook
// timeouts (#2b): fail-closed (failurePolicy!=Ignore) webhooks targeting core
// control-plane resources with timeoutSeconds > maxTimeout (default 10s) emit
// node_automation_webhook_excessive_timeout=1 and, unless opted out via
// AnnoWebhookNeverFailOpen=="true", are clamped to 5s via FluxPatchGate.
// CRD spec.conversion.webhook.timeoutSeconds > maxTimeout is audited into the
// same gauge with kind="crd".
package timeoutclamp

import (
	"context"
	json "encoding/json/v2"
	"fmt"
	"strings"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

const (
	defaultMaxTimeoutSeconds int32 = 10
	clampedTimeoutSeconds    int32 = 5
)

// coreResourceGroups maps a control-plane resource to the API groups
// that actually own it. Matching on the resource name ALONE was the
// CRD clamp bug: every third-party CRD conversion webhook spells its
// rules as apiGroups:[example.com], resources:["*"], so a bare
// `"*" == true` match clamped and disabled third-party webhooks.
// The pair must match: a wildcard resource only counts in the core
// group (or a global "*" group), never in a CRD's own group.
var coreResourceGroups = map[string][]string{
	"pods":                      {""},
	"nodes":                     {""},
	"endpointslices":            {"", "discovery.k8s.io"},
	"leases":                    {"coordination.k8s.io"},
	"tokenreviews":              {"authentication.k8s.io"},
	"subjectaccessreviews":      {"authorization.k8s.io"},
	"selfsubjectaccessreviews":  {"authorization.k8s.io"},
	"localsubjectaccessreviews": {"authorization.k8s.io"},
	// A wildcard resource ("*") in one of the in-tree control-plane
	// groups is still a core-resource webhook and must be clamped just
	// like an explicit "pods"/"leases" rule. Leaving these out let a
	// fail-closed discovery/coordination/authn/authz webhook keep a
	// 30s timeout while holding the whole apiserver hostage.
	"*": {"", "discovery.k8s.io", "coordination.k8s.io", "authentication.k8s.io", "authorization.k8s.io"},
}

type timeoutKey struct {
	kind, config, webhook string
}

// Sweeper holds the gauge ledger for WebhookExcessiveTimeout across sweeps.
type Sweeper struct {
	emitted state.GaugeLedger[timeoutKey]
}

// Sweep audits all admission webhook configurations and CRDs for excessive
// timeouts and clamps eligible fail-closed core-resource entries down to 5s.
func (s *Sweeper) Sweep(ctx context.Context, snap *guardstate.Snapshot) error {
	s.emitted.Begin()
	log := logf.FromContext(ctx)
	g := snap.G
	now := g.Now.Now()

	maxTimeout := g.MaxWebhookTimeoutSeconds
	if maxTimeout <= 0 {
		maxTimeout = defaultMaxTimeoutSeconds
	}
	// The configured ceiling is authoritative: never clamp to a value
	// ABOVE what the operator considers the maximum.
	target := min(clampedTimeoutSeconds, maxTimeout)

	if snap.MWCErr != nil {
		s.carryKindForward(guardstate.KindMutating)
	}
	if snap.VWCErr != nil {
		s.carryKindForward(guardstate.KindValidating)
	}

	var failed []string
	snap.ForEachWebhookConfig(func(cfg guardstate.WebhookConfigView) {
		neverFailOpen := kube.EffectiveAnnos(ctx, cfg.Object)[kube.AnnoWebhookNeverFailOpen] == "true"
		var merges []map[string]any
		var excessive []timeoutKey
		for _, h := range cfg.Hooks {
			if !guardstate.FailClosed(h.FailurePolicy) || h.TimeoutSeconds == nil ||
				*h.TimeoutSeconds <= maxTimeout || !touchesCoreResource(h.Rules) {
				continue
			}
			excessive = append(excessive, timeoutKey{kind: cfg.Kind, config: cfg.Name, webhook: h.Name})
			if g.TimeoutClampEnabled && !neverFailOpen {
				merges = append(merges, map[string]any{
					"name":           h.Name,
					"timeoutSeconds": target,
				})
			}
		}
		if len(excessive) == 0 {
			return
		}
		clamped := false
		if len(merges) > 0 {
			// Its OWN FluxPatchGate key: the circuit breaker's
			// failurePolicy flips on the same config ride a different
			// duty — sharing a key let a policy ping-pong block the
			// timeout clamp (and vice versa) for the whole window.
			if !heal.FluxPatchGate("webhook-timeout-clamp", cfg.Object,
				"timeoutclamp/"+cfg.Kind+"/"+cfg.Name, now) {
				log.Info("skip heal: Flux Heal-Revert Loop detected — webhook timeout clamp deferred",
					"kind", cfg.Kind, "config", cfg.Name)
			} else {
				payload, err := json.Marshal(map[string]any{"webhooks": merges})
				if err != nil {
					metrics.IncError(g.Queue)
					log.Error(err, "marshal webhook timeout clamp patch", "config", cfg.Name)
				} else if err := cfg.Patch(ctx, types.StrategicMergePatchType, payload); err != nil {
					if apierrors.IsNotFound(err) {
						return // config deleted mid-sweep — nothing left to audit
					}
					log.Error(err, "webhook timeout clamp patch failed",
						"kind", cfg.Kind, "config", cfg.Name)
					failed = append(failed, cfg.Kind+"/"+cfg.Name)
				} else {
					clamped = true
					log.Info("CLAMP-TIMEOUT: lowered excessive fail-closed webhook timeoutSeconds",
						"kind", cfg.Kind, "config", cfg.Name, "entries", len(merges),
						"timeoutSeconds", target)
				}
			}
		}
		// The gauge is a DEBT signal: hold it only while the timeout is
		// still excessive AND unclamped (opted out, disabled, gated, or
		// a failed patch). A delivered clamp clears the debt —
		// re-emitting 1 here pinned a page on an already-fixed webhook.
		if clamped {
			return
		}
		for _, tk := range excessive {
			s.emitted.Set(metrics.WebhookExcessiveTimeout, 1, tk,
				tk.kind, tk.config, tk.webhook)
		}
	})

	if snap.CRDErr != nil {
		s.carryKindForward("crd")
	} else {
		s.auditCRDs(snap.CRDs, maxTimeout)
	}

	s.emitted.Prune(metrics.WebhookExcessiveTimeout.DeleteLabelValues)
	if len(failed) > 0 {
		return fmt.Errorf("webhook timeout clamp failed for: %s", strings.Join(failed, ", "))
	}
	return nil
}

func (s *Sweeper) auditCRDs(crds []unstructured.Unstructured, maxTimeout int32) {
	for i := range crds {
		crd := &crds[i]
		strategy, _ := kube.NestedString(crd.Object, "spec", "conversion", "strategy")
		if strategy != "Webhook" {
			continue
		}
		timeout, ok := readCRDConversionTimeout(crd.Object)
		if !ok || timeout <= int64(maxTimeout) {
			continue
		}
		name := crd.GetName()
		tk := timeoutKey{kind: "crd", config: name, webhook: name}
		s.emitted.Set(metrics.WebhookExcessiveTimeout, 1, tk, "crd", name, name)
	}
}

func (s *Sweeper) carryKindForward(kind string) {
	for k, lv := range s.emitted.Last() {
		if k.kind == kind {
			s.emitted.Emit(k, lv...)
		}
	}
}

func touchesCoreResource(rules []admissionv1.RuleWithOperations) bool {
	for i := range rules {
		for _, group := range rules[i].APIGroups {
			g := strings.ToLower(group)
			for _, res := range rules[i].Resources {
				base, _, _ := strings.Cut(strings.ToLower(res), "/")
				wantGroups, known := coreResourceGroups[base]
				if !known {
					continue
				}
				for _, want := range wantGroups {
					if g == want || g == "*" {
						return true
					}
				}
			}
		}
		// An omitted apiGroups on a SPECIFIC resource is the legacy
		// core-group spelling — still audit it. A wildcard resource
		// ("*") with no group, however, is only the core group and is
		// handled by coreResourceGroups["*"] above; a CRD webhook's
		// group+["*"] can never reach this branch.
		if len(rules[i].APIGroups) == 0 {
			for _, res := range rules[i].Resources {
				base, _, _ := strings.Cut(strings.ToLower(res), "/")
				if _, known := coreResourceGroups[base]; known && base != "*" {
					return true
				}
			}
		}
	}
	return false
}

func readCRDConversionTimeout(obj map[string]any) (int64, bool) {
	if v, ok := kube.NestedInt64(obj, "spec", "conversion", "webhook", "timeoutSeconds"); ok {
		return v, true
	}
	raw, found, err := unstructured.NestedFieldNoCopy(obj, "spec", "conversion", "webhook", "timeoutSeconds")
	if err != nil || !found {
		return 0, false
	}
	switch v := raw.(type) {
	case int:
		return int64(v), true
	case int32:
		return int64(v), true
	case int64:
		return v, true
	case float64:
		return int64(v), true
	default:
		return 0, false
	}
}

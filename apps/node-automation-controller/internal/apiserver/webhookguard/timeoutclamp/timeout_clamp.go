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
	"encoding/json"
	"fmt"
	"strings"

	admissionv1 "k8s.io/api/admissionregistration/v1"
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

var coreResources = map[string]bool{
	"pods":                 true,
	"nodes":                true,
	"leases":               true,
	"endpointslices":       true,
	"tokenreviews":         true,
	"subjectaccessreviews": true,
	"*":                    true,
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

	if snap.MWCErr != nil {
		s.carryKindForward(guardstate.KindMutating)
	}
	if snap.VWCErr != nil {
		s.carryKindForward(guardstate.KindValidating)
	}

	var failed []string
	snap.ForEachWebhookConfig(func(cfg guardstate.WebhookConfigView) {
		neverFailOpen := cfg.Annotations[kube.AnnoWebhookNeverFailOpen] == "true"
		var merges []map[string]any
		for _, h := range cfg.Hooks {
			if !guardstate.FailClosed(h.FailurePolicy) || h.TimeoutSeconds == nil ||
				*h.TimeoutSeconds <= maxTimeout || !touchesCoreResource(h.Rules) {
				continue
			}
			tk := timeoutKey{kind: cfg.Kind, config: cfg.Name, webhook: h.Name}
			s.emitted.Set(metrics.WebhookExcessiveTimeout, 1, tk, cfg.Kind, cfg.Name, h.Name)
			if g.TimeoutClampEnabled && !neverFailOpen {
				merges = append(merges, map[string]any{
					"name":           h.Name,
					"timeoutSeconds": clampedTimeoutSeconds,
				})
			}
		}
		if len(merges) == 0 {
			return
		}
		if !heal.FluxPatchGate(cfg.Kind, cfg.Object, cfg.Kind+"/"+cfg.Name, now) {
			log.Info("skip heal: Flux Heal-Revert Loop detected — webhook timeout clamp deferred",
				"kind", cfg.Kind, "config", cfg.Name)
			return
		}
		payload, err := json.Marshal(map[string]any{"webhooks": merges})
		if err != nil {
			metrics.IncError(g.Queue)
			log.Error(err, "marshal webhook timeout clamp patch", "config", cfg.Name)
			return
		}
		if err := cfg.Patch(ctx, types.StrategicMergePatchType, payload); err != nil {
			log.Error(err, "webhook timeout clamp patch failed",
				"kind", cfg.Kind, "config", cfg.Name)
			failed = append(failed, cfg.Kind+"/"+cfg.Name)
			return
		}
		log.Info("CLAMP-TIMEOUT: lowered excessive fail-closed webhook timeoutSeconds",
			"kind", cfg.Kind, "config", cfg.Name, "entries", len(merges),
			"timeoutSeconds", clampedTimeoutSeconds)
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
		for _, res := range rules[i].Resources {
			base, _, _ := strings.Cut(strings.ToLower(res), "/")
			if coreResources[base] {
				return true
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

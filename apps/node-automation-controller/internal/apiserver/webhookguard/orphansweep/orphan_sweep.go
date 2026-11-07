// orphan_sweep.go — the orphan-admission-webhook sweep, the first of
// the four independent duties behind the admission-webhook-guard run:
// it drops Mutating/Validating webhook entries whose backend Service
// lives in a namespace that no longer exists. The sweep is stateless —
// every cluster input arrives through the shared guardstate.Snapshot
// and the guard's clients are reached via snap.G.
package orphansweep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// webhookPatch is one queued strategic-merge patch on a single
// config's /webhooks list (bash did per-index removes; the merge-key
// patch is the equivalent that cannot shift indices mid-patch AND
// cannot revert a concurrent writer's entries — see collect).
type webhookPatch struct {
	mutating bool
	name     string
	payload  []byte
}

// Sweep removes orphan admission-webhook entries — see doc.go. It is
// a plain function: the duty keeps no per-run state, so the facade
// needs no struct for it.
func Sweep(ctx context.Context, snap *guardstate.Snapshot) error {
	g := snap.G
	log := logf.FromContext(ctx)

	// Namespace snapshot — the ONLY source of "deleted" truth. Any error
	// or a missing kube-system means API flap: abort, patch nothing.
	if snap.NSErr != nil {
		return fmt.Errorf("list namespaces (API flap) — abort: %w", snap.NSErr)
	}
	namespaces := make(map[string]bool, len(snap.NS.Items))
	for _, ns := range snap.NS.Items {
		namespaces[ns.Name] = true
	}
	if !namespaces["kube-system"] {
		return errors.New("kube-system absent from namespace list (API flap) — abort")
	}

	// Service snapshot feeds only the WARN branch — a failure here
	// degrades to namespace-only checking, it must not block orphans.
	// Paged like every cluster-wide list in this module.
	haveSvc := true
	services := map[string]bool{}
	err := kube.ListEach(ctx,
		metav1.ListOptions{Limit: guardstate.ListPageSize},
		kube.Services(g.CS, metav1.NamespaceAll),
		func(items []corev1.Service) error {
			for i := range items {
				services[items[i].Namespace+"/"+items[i].Name] = true
			}
			return nil
		})
	if err != nil {
		metrics.IncError(g.Queue)
		log.Info("WARN: cannot list services — skipping service check (namespace check still runs)", "error", err)
		haveSvc = false
	}

	if snap.MWCErr != nil {
		return fmt.Errorf("list mutatingwebhookconfigurations (API flap) — abort: %w", snap.MWCErr)
	}
	if snap.VWCErr != nil {
		return fmt.Errorf("list validatingwebhookconfigurations (API flap) — abort: %w", snap.VWCErr)
	}
	mwc, vwc := snap.MWC, snap.VWC

	var patches []webhookPatch
	// collect queues ONE strategic-merge patch per config listing every
	// orphan entry as {"name": X, "$patch": "delete"}: the webhooks
	// list is patchMergeKey=name + patchStrategy=merge (and
	// +listType=map), so each removal deletes by merge key instead of
	// re-serializing the whole array from our List snapshot. A
	// concurrent writer's entry — cainjector rotating caBundle, GitOps
	// adding a webhook — is merged around, never silently reverted.
	collect := func(mutating bool, cfgName string, removed []string) {
		if len(removed) == 0 {
			return
		}
		dels := make([]map[string]any, 0, len(removed))
		for _, name := range removed {
			dels = append(dels, map[string]any{"name": name, "$patch": "delete"})
		}
		payload, err := json.Marshal(map[string]any{"webhooks": dels})
		if err != nil {
			// Absorbed sub-failure: the sweep logs and continues —
			// metered so the dropped work is still counted.
			metrics.IncError(g.Queue)
			log.Error(err, "marshal webhook patch",
				"config", cfgName, "mutating", mutating)
			return
		}
		patches = append(patches, webhookPatch{mutating: mutating, name: cfgName, payload: payload})
	}

	for _, cfg := range mwc.Items {
		var removed []string
		for i, w := range cfg.Webhooks {
			if orphanEntry(ctx, g, log, "mutatingwebhookconfigurations", cfg.Name, i, w.ClientConfig.Service, namespaces, services, haveSvc) {
				removed = append(removed, w.Name)
			}
		}
		collect(true, cfg.Name, removed)
	}
	for _, cfg := range vwc.Items {
		var removed []string
		for i, w := range cfg.Webhooks {
			if orphanEntry(ctx, g, log, "validatingwebhookconfigurations", cfg.Name, i, w.ClientConfig.Service, namespaces, services, haveSvc) {
				removed = append(removed, w.Name)
			}
		}
		collect(false, cfg.Name, removed)
	}

	// CRD conversion webhooks get the same warn-only treatment: a
	// backend Service deleted under a live namespace — or its whole
	// namespace pruned — leaves the apiserver erroring every CR read
	// for that API group. Unlike an admission webhook ENTRY there is
	// no entry to drop (the CRD object IS the config, and deleting a
	// CRD is catastrophic), so this sweep only warns; the
	// backend-health sweep emits the
	// node_automation_crd_conversion_webhook_unhealthy gauge.
	if snap.CRDErr == nil {
		for i := range snap.CRDs {
			crd := &snap.CRDs[i]
			svcKey, ns, _, ok := guardstate.CRDConversionServiceKey(crd)
			if !ok {
				continue
			}
			switch {
			case !namespaces[ns]:
				log.Info("ORPHAN: CRD conversion webhook backend namespace gone — warn only, the CRD itself is never touched",
					"crd", crd.GetName(), "service", svcKey)
			case haveSvc && !services[svcKey]:
				log.Info("WARN: CRD conversion webhook backend Service missing — warn only",
					"crd", crd.GetName(), "service", svcKey)
			}
		}
	}

	if len(patches) == 0 {
		log.Info("sweep done: no orphan admission webhooks")
		return nil
	}

	failed := false
	for _, p := range patches {
		kind := guardstate.KindValidating
		if p.mutating {
			kind = guardstate.KindMutating
		}
		log.Info("PATCH: drop orphan entries by merge key",
			"kind", kind, "config", p.name)
		var err error
		if p.mutating {
			var patched *admissionv1.MutatingWebhookConfiguration
			patched, err = g.CS.AdmissionregistrationV1().MutatingWebhookConfigurations().Patch(ctx, p.name, types.StrategicMergePatchType, p.payload, metav1.PatchOptions{})
			if err == nil {
				// Keep the shared snapshot current — the circuit
				// breaker and the unmeshed audit run later on the
				// same snap and must see the dropped entries gone.
				snap.SetMWC(patched)
			}
		} else {
			var patched *admissionv1.ValidatingWebhookConfiguration
			patched, err = g.CS.AdmissionregistrationV1().ValidatingWebhookConfigurations().Patch(ctx, p.name, types.StrategicMergePatchType, p.payload, metav1.PatchOptions{})
			if err == nil {
				snap.SetVWC(patched)
			}
		}
		if err != nil {
			log.Error(err, "webhook config patch failed",
				"kind", kind, "config", p.name)
			failed = true
		}
	}
	if failed {
		return errors.New("some webhook config patches failed — orphan webhooks may remain")
	}
	log.Info("sweep done: removed orphan webhook entries (namespace deleted)",
		"configsPatched", len(patches))
	return nil
}

// orphanEntry classifies one webhook entry. Returns true only when the
// backend Service's namespace is gone (→ caller drops the entry).
// A missing Service in a still-live namespace warns and is never patched.
//
// The snapshot's namespace census can lag the apiserver: TakeSnapshot
// lists Namespaces BEFORE the webhook-config lists, so an operator
// creating namespace+webhook between the two lands a live entry whose
// svcRef.Namespace is absent from the census — swept as "orphan" with
// no further check (the TOCTOU the apiservice-guard orphan pass already
// guards). A namespace-verdict removal therefore live-confirms with a
// Namespaces().Get first: only an apiserver NotFound counts as orphan
// (fail closed on any other error — inconclusive keeps the entry).
func orphanEntry(ctx context.Context, g *guardstate.Guard, log logr.Logger,
	kind, cfg string, idx int, svcRef *admissionv1.ServiceReference,
	namespaces, services map[string]bool, haveSvc bool) bool {

	if svcRef == nil || svcRef.Namespace == "" {
		return false // malformed/no-service entry — not an orphan
	}
	if !namespaces[svcRef.Namespace] {
		_, getErr := g.CS.CoreV1().Namespaces().Get(ctx, svcRef.Namespace, metav1.GetOptions{})
		gone, err := kube.ConfirmAbsent(getErr)
		if err != nil {
			log.Info("WARN: namespace confirm failed — webhook entry kept (fail closed)",
				"kind", kind, "config", cfg, "webhookIndex", idx,
				"namespace", svcRef.Namespace, "error", err)
			metrics.IncError(g.Queue)
			return false
		}
		if !gone {
			return false // namespace exists — the census was stale
		}
		log.Info("ORPHAN: namespace gone — removing entry",
			"kind", kind, "config", cfg, "webhookIndex", idx,
			"service", svcRef.Namespace+"/"+svcRef.Name)
		return true
	}
	if haveSvc && !services[svcRef.Namespace+"/"+svcRef.Name] {
		log.Info("WARN: Service missing — warn only, not patched",
			"kind", kind, "config", cfg, "webhookIndex", idx,
			"service", svcRef.Namespace+"/"+svcRef.Name)
	}
	return false
}

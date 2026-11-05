// orphan_sweep.go — the orphan-admission-webhook sweep, the first of
// the three independent duties behind webhookGuard.run: it drops
// Mutating/Validating webhook entries whose backend Service lives in
// a namespace that no longer exists. The sweep is stateless — every
// cluster input arrives through the shared sweepSnapshot and the
// guard's clients are reached via snap.g.
package webhookguard

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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// orphanSweep owns the orphan-entry sweep — embedded in webhookGuard
// so the facade's method set (and every in-package test fixture built
// on it) is unchanged by the split. The sweep keeps no per-run state:
// every cluster input arrives through the shared sweepSnapshot and the
// guard's clients are reached via snap.g.
type orphanSweep struct{}

// webhookPatch is one queued strategic-merge patch on a single
// config's /webhooks list (bash did per-index removes; the merge-key
// patch is the equivalent that cannot shift indices mid-patch AND
// cannot revert a concurrent writer's entries — see collect).
type webhookPatch struct {
	mutating bool
	name     string
	payload  []byte
}

func (o *orphanSweep) sweepOrphans(ctx context.Context, snap *sweepSnapshot) error {
	g := snap.g
	log := logf.FromContext(ctx)

	// Namespace snapshot — the ONLY source of "deleted" truth. Any error
	// or a missing kube-system means API flap: abort, patch nothing.
	if snap.nsErr != nil {
		return fmt.Errorf("list namespaces (API flap) — abort: %w", snap.nsErr)
	}
	namespaces := make(map[string]bool, len(snap.ns.Items))
	for _, ns := range snap.ns.Items {
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
		metav1.ListOptions{Limit: listPageSize},
		kube.Services(g.cs, metav1.NamespaceAll),
		func(items []corev1.Service) error {
			for i := range items {
				services[items[i].Namespace+"/"+items[i].Name] = true
			}
			return nil
		})
	if err != nil {
		metrics.IncError(g.queue)
		log.Info("WARN: cannot list services — skipping service check (namespace check still runs)", "error", err)
		haveSvc = false
	}

	if snap.mwcErr != nil {
		return fmt.Errorf("list mutatingwebhookconfigurations (API flap) — abort: %w", snap.mwcErr)
	}
	if snap.vwcErr != nil {
		return fmt.Errorf("list validatingwebhookconfigurations (API flap) — abort: %w", snap.vwcErr)
	}
	mwc, vwc := snap.mwc, snap.vwc

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
			metrics.IncError(g.queue)
			log.Error(err, "marshal webhook patch",
				"config", cfgName, "mutating", mutating)
			return
		}
		patches = append(patches, webhookPatch{mutating: mutating, name: cfgName, payload: payload})
	}

	for _, cfg := range mwc.Items {
		var removed []string
		for i, w := range cfg.Webhooks {
			if orphanEntry(log, "mutatingwebhookconfigurations", cfg.Name, i, w.ClientConfig.Service, namespaces, services, haveSvc) {
				removed = append(removed, w.Name)
			}
		}
		collect(true, cfg.Name, removed)
	}
	for _, cfg := range vwc.Items {
		var removed []string
		for i, w := range cfg.Webhooks {
			if orphanEntry(log, "validatingwebhookconfigurations", cfg.Name, i, w.ClientConfig.Service, namespaces, services, haveSvc) {
				removed = append(removed, w.Name)
			}
		}
		collect(false, cfg.Name, removed)
	}

	if len(patches) == 0 {
		log.Info("sweep done: no orphan admission webhooks")
		return nil
	}

	failed := false
	for _, p := range patches {
		kind := webhookKindValidating
		if p.mutating {
			kind = webhookKindMutating
		}
		log.Info("PATCH: drop orphan entries by merge key",
			"kind", kind, "config", p.name)
		var err error
		if p.mutating {
			_, err = g.cs.AdmissionregistrationV1().MutatingWebhookConfigurations().Patch(ctx, p.name, types.StrategicMergePatchType, p.payload, metav1.PatchOptions{})
		} else {
			_, err = g.cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().Patch(ctx, p.name, types.StrategicMergePatchType, p.payload, metav1.PatchOptions{})
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
func orphanEntry(log logr.Logger, kind, cfg string, idx int, svcRef *admissionv1.ServiceReference, namespaces, services map[string]bool, haveSvc bool) bool {
	if svcRef == nil || svcRef.Namespace == "" {
		return false // malformed/no-service entry — not an orphan
	}
	if !namespaces[svcRef.Namespace] {
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

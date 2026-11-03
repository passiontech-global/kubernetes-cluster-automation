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
package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

const webhookGuardQueue = "admission-webhook-guard"

type webhookGuard struct {
	cs kubernetes.Interface
}

// SetupWebhookGuard registers the 5-minute sweep (was crontab */5).
func SetupWebhookGuard(mgr ctrl.Manager, cs kubernetes.Interface) error {
	g := &webhookGuard{cs: cs}
	return addPeriodic(mgr, webhookGuardQueue, 5*time.Minute, g.run)
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

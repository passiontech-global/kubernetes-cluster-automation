// argocd_app_stuck_heal.go — the heal half of the argocd-app-stuck
// check: the refresh=hard Application patch, its persisted first-seen
// enumeration, and the >=2-ComparisonError argocd-repo-server restart.
//
// split from argocd_app_stuck.go (see its header for the module contract).
package gitops

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// refreshArgoCDApp patches argocd.argoproj.io/refresh=hard on a
// stuck Application — the shared heal preamble gates it like every
// other heal (Deps.HealAllowedPersisted → heal.AllowedVPersisted):
// the 30m per-app cooldown is the wider of the in-RAM ledger and the
// passiontech.dev/last-argocd-app-refresh stamp persisted on the
// Application itself (a restart re-firing refresh=hard for every
// stuck app is the churn the persisted half exists to stop), then
// the maintenance mutex + global heal budget (a refresh patch during
// a drain re-triggers reconciliation churn exactly like a pod delete;
// "cannot verify" fails closed). The cooldown stamp rides the SAME
// merge patch as the refresh annotation — kube.MergePatchAnnos is
// RFC 7386, so sibling annotation keys survive, and one write lands
// the heal and its persisted cooldown together. ArgoCD consumes the
// refresh key once processed; the last-* stamp stays.
func (p *argoCDAppStuckCheck) refreshArgoCDApp(ctx context.Context,
	log logr.Logger, app *unstructured.Unstructured, now time.Time) {

	ck := probefw.SelfHealKey(CheckNameArgoCDAppStuck,
		"refresh/"+app.GetNamespace()+"/"+app.GetName())
	proceed, unverifiable := p.HealAllowedPersisted(ctx, log, &p.Heals,
		app, argoCDRefreshHealAnno, ck, argocdRefreshCooldown, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return
	}
	if !proceed {
		return
	}
	payload, err := kube.MergePatchAnnos(map[string]any{
		argocdRefreshAnno:     "hard",
		argoCDRefreshHealAnno: now.UTC().Format(time.RFC3339),
	})
	if err != nil {
		log.Error(err, "marshal argocd refresh patch failed",
			"application", app.GetNamespace()+"/"+app.GetName())
		return
	}
	if _, err := p.Dyn.Resource(argocdAppGVR).
		Namespace(app.GetNamespace()).Patch(ctx, app.GetName(),
		types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		log.Error(err, "argocd refresh patch failed",
			"application", app.GetNamespace()+"/"+app.GetName())
		return
	}
	p.Heals.Stamp(ck, now)
	log.Info("PATCH: argocd application refresh=hard",
		"application", app.GetNamespace()+"/"+app.GetName())
}

// argoPersistedFirstSeen returns the first-seen keys persisted on
// this Application — the annotation map is per-object, so every
// entry is one of this app's signatures. Absent/unparseable reads
// as empty (same "unparseable = absent" posture as
// kube.ParseAnnoTime); the in-RAM half needs no enumeration —
// p.seen.Prune drops non-live keys at sweep end.
func argoPersistedFirstSeen(app *unstructured.Unstructured) map[string]bool {
	sigs := map[string]bool{}
	raw := app.GetAnnotations()[kube.AnnoFirstSeenArgoCDAppStuck]
	if raw == "" {
		return sigs
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return sigs
	}
	for k := range m {
		sigs[k] = true
	}
	return sigs
}

// restartArgoCDRepoServer deletes the OLDEST argocd-repo-server
// pod — repo-server caches repo state; >=2 ComparisonErrors at once
// is the stale-cache signature and one restart flushes it. The
// primary list filters server-side on the operator's canonical
// app.kubernetes.io/name label; a repo-server pod missing the label
// can never reach that list, so an empty result re-lists
// unfiltered and matches the argocd-repo-server- name prefix (the
// helm-vs-operator label drift fallback).
func (p *argoCDAppStuckCheck) restartArgoCDRepoServer(ctx context.Context,
	log logr.Logger, now time.Time) {

	oldest := p.oldestRepoServerPod(ctx, log,
		"app.kubernetes.io/name=argocd-repo-server")
	if oldest == nil {
		oldest = p.oldestRepoServerPod(ctx, log, "")
	}
	if oldest == nil {
		log.Info("argocd repo-server restart requested but no repo-server pod found")
		return
	}
	// Only a controller-owned pod is restartable — the owner
	// recreates it. A lone, controller-less pod would be deleted
	// PERMANENTLY (repo-server gone until manual redeploy), so the
	// heal skips it.
	if metav1.GetControllerOf(oldest) == nil {
		log.Info("SKIP: repo-server pod has no controller owner — delete would not be recreated",
			"pod", oldest.Namespace+"/"+oldest.Name)
		return
	}
	// The heal cooldown keys on the pod's controller so the
	// replacement pod the restart spawns inherits the 30m window
	// instead of re-arming it under a fresh pod name
	// (kube.PodControllerKey).
	p.DeletePodHeal(ctx, log, CheckNameArgoCDAppStuck,
		kube.PodControllerKey(oldest), oldest, argocdRepoServerCool, now)
}

// oldestRepoServerPod returns the oldest non-terminating
// argocd-repo-server pod cluster-wide. selector=="" is the
// label-less fallback pass that matches on the name prefix plus the
// component label (an install shape where the canonical
// app.kubernetes.io/name label is absent entirely).
func (p *argoCDAppStuckCheck) oldestRepoServerPod(ctx context.Context,
	log logr.Logger, selector string) *corev1.Pod {

	pods, err := p.PodsMatching(ctx, metav1.NamespaceAll, selector)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: list pods failed — repo-server restart deferred",
			"error", err)
		return nil
	}
	var oldest *corev1.Pod
	for i := range pods {
		pod := pods[i]
		if pod.DeletionTimestamp != nil {
			continue
		}
		// A non-Running repo-server pod (Pending/PodInitializing or
		// a phase-stuck remnant) has no cache to flush — restarting
		// it spends the heal on a pod that cannot hold stale repo
		// state.
		if pod.Status.Phase != corev1.PodRunning {
			continue
		}
		if selector == "" &&
			pod.Labels["app.kubernetes.io/name"] != "argocd-repo-server" &&
			pod.Labels["app.kubernetes.io/component"] != "repo-server" &&
			!strings.HasPrefix(pod.Name, "argocd-repo-server-") {
			continue
		}
		if oldest == nil ||
			pod.CreationTimestamp.Before(&oldest.CreationTimestamp) {
			oldest = pod
		}
	}
	return oldest
}

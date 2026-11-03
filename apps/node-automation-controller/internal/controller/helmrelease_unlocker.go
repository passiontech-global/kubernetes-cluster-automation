// helmrelease-unlocker — breaks the HelmRelease "another operation in
// progress" deadlock (fluxcd/helm-controller#149, #644): the newest
// helm release secret sits in a pending-* state because the helm run
// that created it was killed mid-operation, so helm-controller refuses
// every subsequent reconcile ("another operation ... in progress") and
// the HR stays Ready=False forever.
//
// Detection: HR Ready=False whose message contains "in progress"
// continuously for >30m (first-seen tracked in memory — a healthy
// upgrade legitimately shows that message for minutes).
//
// Confirmation before touching anything: the release's own secrets
// (type helm.sh/release.v1, label name=<release>) in the target ns
// must show the NEWEST revision as pending-* AND an older deployed/
// superseded revision must exist — that is a safe rollback target;
// deleting the pending secret restores the previous state instead of
// orphaning a first-install release with nothing to roll back to.
//
// Action: delete that newest pending-* secret + merge-patch the HR
// annotation reconcile.fluxcd.io/requestedAt=<now> (flux's "reconcile
// now" signal) so helm-controller retries immediately.
//
// Guards:
//   - max one unlock per HR per 24h (in-memory);
//   - skip+warn while a helm-controller pod (flux-system,
//     app.kubernetes.io/name=helm-controller) is CrashLoopBackOff —
//     deleting secrets cannot converge without a working controller;
//   - an HR stuck again inside the 24h cooldown means the previous
//     unlock did NOT fix it → IncError (alert) instead of churn.
package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

const (
	helmUnlockQueue    = "helmrelease-unlocker"
	helmUnlockInterval = 10 * time.Minute
	helmStuckThreshold = 30 * time.Minute // first-seen window before acting
	helmUnlockCooldown = 24 * time.Hour   // max 1 unlock/HR inside this window
	helmSecretType     = "helm.sh/release.v1"
	helmControllerNS   = "flux-system"
	helmControllerSel  = "app.kubernetes.io/name=helm-controller"
	fluxReconcileAnno  = "reconcile.fluxcd.io/requestedAt"
)

// helmReleaseGVRs tried in order — v2 on current flux, v2beta2 on
// installs that have not bumped the CRDs yet. The first listable GVR
// wins and is reused for the requestedAt patches.
var helmReleaseGVRs = []schema.GroupVersionResource{
	{Group: "helm.toolkit.fluxcd.io", Version: "v2", Resource: "helmreleases"},
	{Group: "helm.toolkit.fluxcd.io", Version: "v2beta2", Resource: "helmreleases"},
}

type helmReleaseUnlocker struct {
	cs  kubernetes.Interface
	dyn dynamic.Interface
	mu  sync.Mutex
	// firstSeen: ns/name → first tick that saw the HR stuck on
	// "in progress". Pruned when the HR recovers; an operator restart
	// re-arms it, biasing conservative.
	firstSeen map[string]time.Time
	// unlocked: ns/name → last successful unlock — enforces the
	// 1-unlock/24h cap and detects "stuck again after unlock".
	// Pruned each sweep once past the cooldown or when the HR
	// vanished.
	unlocked map[string]time.Time
}

// SetupHelmReleaseUnlocker registers the 10-minute sweep.
func SetupHelmReleaseUnlocker(mgr ctrl.Manager, cs kubernetes.Interface, dyn dynamic.Interface) error {
	u := &helmReleaseUnlocker{
		cs:        cs,
		dyn:       dyn,
		firstSeen: map[string]time.Time{},
		unlocked:  map[string]time.Time{},
	}
	return addPeriodic(mgr, helmUnlockQueue, helmUnlockInterval, u.run)
}

func (u *helmReleaseUnlocker) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	u.mu.Lock()
	defer u.mu.Unlock()

	list, gvr, err := u.listHelmReleases(ctx)
	if err != nil {
		return err
	}

	now := time.Now()
	stuck := map[string]*unstructured.Unstructured{}
	present := map[string]bool{} // every listed HR, stuck or not
	for i := range list.Items {
		hr := &list.Items[i]
		present[hr.GetNamespace()+"/"+hr.GetName()] = true
		if !hrStuckInProgress(hr) {
			continue
		}
		key := hr.GetNamespace() + "/" + hr.GetName()
		stuck[key] = hr
		if _, ok := u.firstSeen[key]; !ok {
			u.firstSeen[key] = now
			log.Info("HR shows 'in progress' — tracking first-seen", "hr", key)
		}
	}
	// Prune HRs that recovered (or vanished) so a later stall re-arms
	// the 30m window from scratch.
	for key := range u.firstSeen {
		if _, ok := stuck[key]; !ok {
			delete(u.firstSeen, key)
		}
	}
	// Same prune for the unlock ledger: entries past the 24h cooldown
	// are dead weight and entries for HRs that vanished would pile up
	// forever — the map is otherwise append-only per unlocked HR.
	for key, last := range u.unlocked {
		if !present[key] || now.Sub(last) >= helmUnlockCooldown {
			delete(u.unlocked, key)
		}
	}

	var due []string
	for key := range stuck {
		if now.Sub(u.firstSeen[key]) >= helmStuckThreshold {
			due = append(due, key)
		}
	}
	if len(due) == 0 {
		log.Info("sweep done", "stuck", len(stuck))
		return nil
	}
	sort.Strings(due)

	// helm-controller crashlooping → the unlock cannot converge
	// (someone must finish the rollback after the pending secret is
	// deleted). Warn and abort; the next tick re-evaluates.
	down, err := u.helmControllerDown(ctx)
	if err != nil {
		return err
	}
	if down {
		log.Info("SKIP: helm-controller pod CrashLoopBackOff — unlock would not converge", "due", due)
		return nil
	}

	unlocked := 0
	for _, key := range due {
		hr := stuck[key]
		if last, ok := u.unlocked[key]; ok && now.Sub(last) < helmUnlockCooldown {
			// Still/again stuck inside the cooldown: the previous
			// unlock did NOT resolve it — page instead of churning
			// secrets every tick.
			metrics.IncError(helmUnlockQueue)
			log.Info("ALERT: HR still stuck after unlock — not retrying inside cooldown",
				"hr", key, "unlockedAgo", now.Sub(last).Truncate(time.Minute))
			continue
		}
		if err := u.unlock(ctx, gvr, hr); err != nil {
			log.Error(err, "helmrelease unlock failed", "hr", key)
			continue // per-HR failures must not starve the rest
		}
		u.unlocked[key] = now
		unlocked++
	}
	log.Info("sweep done", "due", len(due), "unlocked", unlocked)
	return nil
}

// listHelmReleases returns the HR list and the GVR that answered — v2
// first, v2beta2 when the v2 CRDs are absent.
func (u *helmReleaseUnlocker) listHelmReleases(ctx context.Context) (*unstructured.UnstructuredList, schema.GroupVersionResource, error) {
	var lastErr error
	for _, gvr := range helmReleaseGVRs {
		list, err := u.dyn.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err == nil {
			return list, gvr, nil
		}
		lastErr = err
	}
	return nil, schema.GroupVersionResource{}, lastErr
}

// hrStuckInProgress reports whether the HR's Ready condition is False
// with a "…in progress" message — the deadlock signature. A missing or
// non-False Ready never counts.
func hrStuckInProgress(hr *unstructured.Unstructured) bool {
	status, msg := readyCond(hr)
	return status == "False" && strings.Contains(msg, "in progress")
}

// helmControllerDown reports whether any helm-controller pod is
// CrashLoopBackOff. A list error is a real error for the caller.
func (u *helmReleaseUnlocker) helmControllerDown(ctx context.Context) (bool, error) {
	pods, err := u.cs.CoreV1().Pods(helmControllerNS).List(ctx,
		metav1.ListOptions{LabelSelector: helmControllerSel})
	if err != nil {
		return false, err
	}
	for i := range pods.Items {
		statuses := append([]corev1.ContainerStatus{},
			pods.Items[i].Status.InitContainerStatuses...)
		statuses = append(statuses, pods.Items[i].Status.ContainerStatuses...)
		for _, s := range statuses {
			if s.State.Waiting != nil && s.State.Waiting.Reason == "CrashLoopBackOff" {
				return true, nil
			}
		}
	}
	return false, nil
}

// unlock deletes the newest pending-* release secret and stamps
// reconcile.fluxcd.io/requestedAt on the HR. Only acts when an older
// deployed/superseded revision exists to roll back to.
func (u *helmReleaseUnlocker) unlock(ctx context.Context, gvr schema.GroupVersionResource, hr *unstructured.Unstructured) error {
	log := logf.FromContext(ctx)
	key := hr.GetNamespace() + "/" + hr.GetName()
	release := hrReleaseName(hr)

	// Restrict server-side to this release's own secrets: helm
	// release secrets embed the full compressed chart, so an
	// unfiltered list hauls every release in the namespace across
	// the wire. owner=helm + name=<release> is the same label pair
	// the revision scan below matches on.
	secrets, err := u.cs.CoreV1().Secrets(hrTargetNS(hr)).List(ctx,
		metav1.ListOptions{LabelSelector: "owner=helm,name=" + release})
	if err != nil {
		return fmt.Errorf("list release secrets: %w", err)
	}

	var pending *corev1.Secret
	pendingRev := -1
	var safeRevs []int // deployed/superseded revisions = rollback targets
	for i := range secrets.Items {
		s := &secrets.Items[i]
		if s.Type != corev1.SecretType(helmSecretType) || s.Labels["name"] != release {
			continue
		}
		rev, err := strconv.Atoi(s.Labels["version"])
		if err != nil {
			continue
		}
		switch st := s.Labels["status"]; {
		case strings.HasPrefix(st, "pending-"):
			if rev > pendingRev {
				pending, pendingRev = s, rev
			}
		case st == "deployed" || st == "superseded":
			safeRevs = append(safeRevs, rev)
		}
	}
	if pending == nil {
		log.Info("skip: no pending-* release secret — not the pending deadlock", "hr", key, "release", release)
		return nil
	}
	olderSafe := false
	for _, r := range safeRevs {
		if r < pendingRev {
			olderSafe = true
			break
		}
	}
	if !olderSafe {
		// pending-install with no prior revision: deleting it orphans
		// the release — refuse (helm-controller#644 class).
		log.Info("skip: pending revision has no deployed/superseded predecessor — refusing",
			"hr", key, "release", release, "pendingRev", pendingRev)
		return nil
	}

	log.Info("ACTION: delete stuck pending release secret",
		"hr", key, "secret", pending.Name, "status", pending.Labels["status"], "rev", pendingRev)
	if err := u.cs.CoreV1().Secrets(pending.Namespace).Delete(ctx, pending.Name,
		metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("delete pending secret %s/%s: %w", pending.Namespace, pending.Name, err)
	}

	// reconcile.fluxcd.io/requestedAt is flux's "reconcile now" hint —
	// only the value changing matters; RFC3339 is the convention.
	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"annotations": map[string]string{
			fluxReconcileAnno: time.Now().UTC().Format(time.RFC3339),
		}},
	})
	if err != nil {
		return err
	}
	if _, err := u.dyn.Resource(gvr).Namespace(hr.GetNamespace()).Patch(ctx, hr.GetName(),
		types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("annotate helmrelease %s: %w", key, err)
	}
	log.Info("ACTION: requested HR reconcile", "hr", key)
	return nil
}

// hrReleaseName is spec.releaseName, falling back to the object name —
// the label helm puts on its release secrets.
func hrReleaseName(hr *unstructured.Unstructured) string {
	if n, _, _ := unstructured.NestedString(hr.Object, "spec", "releaseName"); n != "" {
		return n
	}
	return hr.GetName()
}

// hrTargetNS is spec.targetNamespace (where the release secrets live),
// falling back to the HR's own namespace.
func hrTargetNS(hr *unstructured.Unstructured) string {
	if ns, _, _ := unstructured.NestedString(hr.Object, "spec", "targetNamespace"); ns != "" {
		return ns
	}
	return hr.GetNamespace()
}

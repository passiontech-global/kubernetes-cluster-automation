// volumesnapshot_lifecycle_guard.go — health check
// "volumesnapshot-lifecycle-guard" (R6-K2): detects VolumeSnapshots and
// VolumeSnapshotContents stuck not-ready, carrying status.error, or stuck
// terminating with remaining finalizers past min age (default 15m via
// NODE_AUTOMATION_VOLUMESNAPSHOT_MIN_AGE).
//
// Emits node_automation_volumesnapshot_stuck{kind,namespace,name,reason} and
// cooldown-deduped Warning Events (VolumeSnapshotStuck), and lazily bounces at
// most one hung CSI snapshot-controller pod per sweep (excluding webhooks)
// when NODE_AUTOMATION_VOLUMESNAPSHOT_HEAL_ENABLED=true (default true).
// Auto-skips cleanly when snapshot.storage.k8s.io/v1 CRDs are absent.
package pvc

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	// CheckNameVolumeSnapshotLifecycleGuard is the registry check name for R6-K2.
	CheckNameVolumeSnapshotLifecycleGuard = "volumesnapshot-lifecycle-guard"

	volumeSnapshotStuckDefaultMinAge = 15 * time.Minute
	volumeSnapshotEventCooldown      = 30 * time.Minute
	volumeSnapshotControllerCooldown = 30 * time.Minute
	volumeSnapshotEventReason        = "VolumeSnapshotStuck"

	vsReasonNotReady         = "not_ready"
	vsReasonStatusError      = "status_error"
	vsReasonTerminatingStuck = "terminating_stuck"
)

var volumeSnapshotStuckGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_volumesnapshot_stuck",
	Help: "1 while a VolumeSnapshot or VolumeSnapshotContent is stuck not-ready, errored, or terminating past min age.",
}, []string{"kind", "namespace", "name", "reason"})

func init() {
	ctrlmetrics.Registry.MustRegister(volumeSnapshotStuckGauge)
}

type volumeSnapshotLifecycleGuardCheck struct {
	*probefw.Deps

	minAge      time.Duration
	healEnabled bool

	firstSeen     state.FirstSeenLedger
	emitted       state.GaugeLedger[string]
	eventCooldown state.CooldownSet
}

// NewVolumeSnapshotLifecycleGuardCheck constructs the
// volumesnapshot-lifecycle-guard check, resolving env knobs once at startup.
func NewVolumeSnapshotLifecycleGuardCheck(d *probefw.Deps) probefw.Check {
	minAge := envx.GetenvDuration("NODE_AUTOMATION_VOLUMESNAPSHOT_MIN_AGE", volumeSnapshotStuckDefaultMinAge)
	if minAge <= 0 {
		minAge = volumeSnapshotStuckDefaultMinAge
	}
	return &volumeSnapshotLifecycleGuardCheck{
		Deps:        d,
		minAge:      minAge,
		healEnabled: envx.Gate("NODE_AUTOMATION_VOLUMESNAPSHOT_HEAL_ENABLED", true),
	}
}

func (c *volumeSnapshotLifecycleGuardCheck) Run(ctx context.Context) probefw.Result {
	if r := c.RequireDyn("volumesnapshot lifecycle guard"); r != nil {
		return *r
	}

	log := logf.FromContext(ctx)
	now := c.Now()
	minAge := c.minAge
	if minAge <= 0 {
		minAge = volumeSnapshotStuckDefaultMinAge
	}
	c.eventCooldown.PruneExpired(now, volumeSnapshotEventCooldown)

	var rep probefw.SweepReport
	liveFirstSeen := map[string]bool{}
	carriedKinds := map[string]bool{}

	vsStuck, vsWedge := c.scanSnapshotKind(ctx, log, now, minAge, kube.GVRVolumeSnapshot, "VolumeSnapshot", &rep, liveFirstSeen, carriedKinds)
	vscStuck, vscWedge := c.scanSnapshotKind(ctx, log, now, minAge, kube.GVRVolumeSnapshotContent, "VolumeSnapshotContent", &rep, liveFirstSeen, carriedKinds)

	c.firstSeen.Prune(func(k string) bool {
		if liveFirstSeen[k] {
			return true
		}
		for kind := range carriedKinds {
			if strings.HasPrefix(k, kind+"/") {
				return true
			}
		}
		return false
	})

	if c.healEnabled && vsStuck+vscStuck > 0 {
		c.maybeBounceSnapshotController(ctx, log, now, vsWedge+vscWedge > 0)
	}

	return rep.Result(&c.emitted, volumeSnapshotStuckGauge.DeleteLabelValues,
		"volumesnapshot lifecycle guard: ", ", ")
}

func (c *volumeSnapshotLifecycleGuardCheck) scanSnapshotKind(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	minAge time.Duration,
	gvr schema.GroupVersionResource,
	kind string,
	rep *probefw.SweepReport,
	liveFirstSeen map[string]bool,
	carriedKinds map[string]bool,
) (int, int) {
	items, err := c.AllUnstructured(ctx, gvr)
	switch {
	case kube.IsCRDAbsent(err):
		return 0, 0
	case apierrors.IsForbidden(err):
		log.V(1).Info("snapshot resource list skipped (403)", "kind", kind, "error", err)
		carriedKinds[kind] = true
		c.carryKindTuples(kind, rep)
		return 0, 0
	case err != nil:
		rep.InfraErr(fmt.Errorf("list %s: %w", gvr.Resource, err))
		carriedKinds[kind] = true
		c.carryKindTuples(kind, rep)
		return 0, 0
	}

	stuckCount := 0
	wedgeCount := 0
	for i := range items {
		obj := &items[i]
		ns, name := obj.GetNamespace(), obj.GetName()
		objID := name
		if ns != "" {
			objID = ns + "/" + name
		}

		delTS := obj.GetDeletionTimestamp()
		var reason string
		var persisted bool

		if delTS != nil {
			if len(obj.GetFinalizers()) == 0 {
				continue
			}
			reason = vsReasonTerminatingStuck
			fsKey := kind + "/" + objID + "/" + reason
			if !delTS.Time.IsZero() {
				persisted = now.Sub(delTS.Time) >= minAge
			} else {
				liveFirstSeen[fsKey] = true
				persisted = probefw.Persisted(&c.firstSeen, fsKey, now, minAge, log)
			}
		} else {
			readyToUse, _ := kube.NestedBool(obj.Object, "status", "readyToUse")
			errMap, hasErrMap := kube.NestedMap(obj.Object, "status", "error")
			errStr, hasErrStr := kube.NestedString(obj.Object, "status", "error")
			hasErr := (hasErrMap && len(errMap) > 0) || (hasErrStr && errStr != "")
			if readyToUse && !hasErr {
				continue
			}
			if hasErr {
				reason = vsReasonStatusError
			} else {
				reason = vsReasonNotReady
			}
			fsKey := kind + "/" + objID + "/" + reason
			ct := obj.GetCreationTimestamp().Time
			if !ct.IsZero() {
				persisted = now.Sub(ct) >= minAge
			} else {
				liveFirstSeen[fsKey] = true
				persisted = probefw.Persisted(&c.firstSeen, fsKey, now, minAge, log)
			}
		}

		if !persisted {
			continue
		}

		stuckCount++
		// A VolumeSnapshot with status.error is typically a tenant config
		// mistake (missing PVC / invalid VolumeSnapshotClass) where the
		// controller IS reconciling. Do not treat it alone as a controller
		// wedge — only not_ready/terminating_stuck or cluster-scoped VSC
		// stalls indicate a wedged snapshot-controller.
		if kind == "VolumeSnapshotContent" || reason != vsReasonStatusError {
			wedgeCount++
		}
		tupleKey := kind + "/" + objID + "/" + reason
		rep.Emit(volumeSnapshotStuckGauge, tupleKey,
			[]string{kind, ns, name, reason},
			fmt.Sprintf("%s/%s (%s)", kind, objID, reason))
		c.emitStuckEvent(ctx, log, now, kind, obj, objID, reason)
	}
	return stuckCount, wedgeCount
}

func (c *volumeSnapshotLifecycleGuardCheck) carryKindTuples(kind string, rep *probefw.SweepReport) {
	for k, lv := range c.emitted.Last() {
		if len(lv) == 4 && lv[0] == kind {
			rep.Carry(k, lv)
		}
	}
}

func (c *volumeSnapshotLifecycleGuardCheck) emitStuckEvent(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	kind string,
	obj *unstructured.Unstructured,
	objID, reason string,
) {
	ns, name := obj.GetNamespace(), obj.GetName()
	cooldownKey := "vsstuck." + kind + "." + ns + "." + name + "." + reason
	evNS := ns
	if evNS == "" {
		evNS = "default"
	}
	probefw.EmitWarningDeduped(ctx, c.CS, log, &c.eventCooldown, cooldownKey, volumeSnapshotEventCooldown, now, kube.WarningEvent{
		Namespace: evNS,
		Regarding: corev1.ObjectReference{
			APIVersion: "snapshot.storage.k8s.io/v1",
			Kind:       kind,
			Namespace:  ns,
			Name:       name,
			UID:        obj.GetUID(),
		},
		Reason:            volumeSnapshotEventReason,
		Note:              fmt.Sprintf("%s %s stuck (%s)", kind, objID, reason),
		ReportingInstance: c.Name,
	})
}

func (c *volumeSnapshotLifecycleGuardCheck) maybeBounceSnapshotController(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	hasWedgeSignal bool,
) {
	pods, err := c.AllPods(ctx)
	if err != nil {
		metrics.IncError(c.Name)
		log.Error(err, "volumesnapshot controller pod list failed")
		return
	}

	var candidates []*corev1.Pod
	for i := range pods {
		pod := &pods[i]
		if isSnapshotControllerPod(pod) {
			candidates = append(candidates, pod)
		}
	}
	if len(candidates) == 0 {
		return
	}

	slices.SortFunc(candidates, func(a, b *corev1.Pod) int {
		aReady := kube.PodReadyCond(a)
		bReady := kube.PodReadyCond(b)
		if aReady != bReady {
			if !aReady {
				return -1
			}
			return 1
		}
		if !a.CreationTimestamp.Equal(&b.CreationTimestamp) {
			if a.CreationTimestamp.Before(&b.CreationTimestamp) {
				return -1
			}
			return 1
		}
		if d := cmp.Compare(a.Namespace, b.Namespace); d != 0 {
			return d
		}
		return cmp.Compare(a.Name, b.Name)
	})

	pod := candidates[0]
	// If only tenant VolumeSnapshot status_error exists and the
	// snapshot-controller itself is Ready, skip eviction so a single
	// tenant's broken snapshot cannot churn the cluster-wide controller.
	if !hasWedgeSignal && kube.PodReadyCond(pod) {
		return
	}
	podKey := pod.Namespace + "/" + pod.Name
	ck := probefw.SelfHealKey(CheckNameVolumeSnapshotLifecycleGuard, kube.PodControllerKey(pod))
	proceed, unverifiable := c.HealAllowed(ctx, log, &c.Heals, ck, volumeSnapshotControllerCooldown, now)
	if unverifiable {
		metrics.IncError(c.Name)
		return
	}
	if !proceed {
		return
	}

	ctrl := metav1.GetControllerOf(pod)
	targetKey := pod.Namespace + "." + ctrl.Name
	allowed, reason, _ := heal.WithTargetBreaker(CheckNameVolumeSnapshotLifecycleGuard, targetKey, now, func() (bool, error) {
		evicted, refused, notFound, err := heal.EvictPodNotFound(ctx, c.CS, &c.Heals, ck, pod, now)
		switch {
		case err != nil:
			metrics.IncError(c.Name)
			log.Error(err, "snapshot-controller eviction failed", "pod", podKey)
		case refused:
			heal.RefundGrant(now)
			if notFound {
				log.V(1).Info("DEFER: snapshot-controller pod vanished before eviction", "pod", podKey)
			} else {
				log.Info("DEFER: snapshot-controller eviction refused (PDB/hold/quorum)", "pod", podKey)
			}
			return false, nil
		case evicted:
			metrics.ControlPlanePodHealsTotal.WithLabelValues(CheckNameVolumeSnapshotLifecycleGuard).Inc()
			log.Info("EVICT: hung CSI snapshot-controller pod evicted for reschedule", "pod", podKey)
		}
		return true, nil
	})
	if !allowed {
		heal.RefundGrant(now)
		log.Info("DEFER: snapshot-controller target circuit open",
			"pod", podKey, "target", targetKey, "reason", reason)
	}
}

// isTrustedSnapshotControllerNS restricts snapshot-controller pod discovery
// to system/storage infrastructure namespaces so a tenant pod carrying
// app=snapshot-controller cannot hijack or suppress controller healing.
func isTrustedSnapshotControllerNS(ns string) bool {
	switch ns {
	case "kube-system", "storage-system", "csi-system", "openebs",
		"ceph-csi", "rook-ceph", "longhorn-system", "democratic-csi",
		"trident", "snapshot-controller":
		return true
	default:
		return false
	}
}

func isSnapshotControllerPod(pod *corev1.Pod) bool {
	if !isTrustedSnapshotControllerNS(pod.Namespace) {
		return false
	}
	if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
		return false
	}
	if metav1.GetControllerOf(pod) == nil {
		return false
	}
	nameLower := strings.ToLower(pod.Name)
	if strings.Contains(nameLower, "webhook") || strings.Contains(nameLower, "validation") {
		return false
	}
	for _, lbl := range []string{
		pod.Labels["app.kubernetes.io/name"],
		pod.Labels["app.kubernetes.io/component"],
		pod.Labels["app"],
	} {
		l := strings.ToLower(lbl)
		if strings.Contains(l, "webhook") || strings.Contains(l, "validation") {
			return false
		}
	}

	for _, lbl := range []string{
		pod.Labels["app.kubernetes.io/name"],
		pod.Labels["app"],
		pod.Labels["app.kubernetes.io/component"],
	} {
		if lbl == "snapshot-controller" || lbl == "csi-snapshot-controller" {
			return true
		}
	}
	if strings.HasPrefix(nameLower, "snapshot-controller-") || strings.HasPrefix(nameLower, "csi-snapshot-controller-") {
		return true
	}
	for i := range pod.Spec.Containers {
		if strings.Contains(strings.ToLower(pod.Spec.Containers[i].Image), "snapshot-controller") {
			return true
		}
	}
	return false
}

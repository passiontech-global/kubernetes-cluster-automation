// workload_admission_block_guard_test.go — coverage for workload-admission-block-guard (#73):
// 5m persistence hysteresis, all 5 reason buckets across ReplicaSet/StatefulSet/DaemonSet,
// 15m FailedCreate event window & CrashLoopBackOff exclusion, downscaled/terminating skips,
// GaugeLedger cleanup on recovery, and deduped RFC 1123 Warning Events.
package watchdogs

import (
	"errors"
	"net/http"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func admissionBlockedSeries(t *testing.T, ns, kind, name, reason string) (float64, bool) {
	t.Helper()
	return testutil.GaugeSeriesValue(t, "node_automation_workload_admission_blocked",
		map[string]string{"namespace": ns, "kind": kind, "name": name, "reason": reason})
}

func makeBlockedRS(ns, name, msg string) *appsv1.ReplicaSet {
	return &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID("uid-rs-" + name)},
		Spec:       appsv1.ReplicaSetSpec{Replicas: ptr.To(int32(2))},
		Status: appsv1.ReplicaSetStatus{
			Conditions: []appsv1.ReplicaSetCondition{{
				Type:    appsv1.ReplicaSetReplicaFailure,
				Status:  corev1.ConditionTrue,
				Message: msg,
			}},
		},
	}
}

func makeFailedCreateEvent(ns, kind, name, msg string, at time.Time) *corev1.Event {
	return &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Namespace: ns, Name: "ev-" + kind + "-" + name + "-" + at.Format("150405")},
		InvolvedObject: corev1.ObjectReference{Kind: kind, Namespace: ns, Name: name},
		Reason:         "FailedCreate",
		Message:        msg,
		LastTimestamp:  metav1.NewTime(at),
	}
}

func TestWorkloadAdmissionBlockGuardAllKindsReasonsAndRecovery(t *testing.T) {
	now := time.Now()
	rsQuota := makeBlockedRS("team-a", "rs-quota", "pods \"rs-quota-abc\" is forbidden: exceeded quota: compute-quota")
	rsPSA := makeBlockedRS("team-a", "rs-psa", "violates PodSecurity \"restricted:latest\": allowPrivilegeEscalation != false")
	rsOther := makeBlockedRS("team-a", "rs-other", "some unexpected api rejection")

	stsLimit := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "sts-limit", UID: types.UID("uid-sts-limit")},
		Spec:       appsv1.StatefulSetSpec{Replicas: ptr.To(int32(3))},
		Status:     appsv1.StatefulSetStatus{CurrentReplicas: 1},
	}
	evSTSLimit := makeFailedCreateEvent("team-a", "StatefulSet", "sts-limit",
		"pods \"sts-limit-1\" is forbidden: maximum cpu usage per Container is 500m, but limit is 1", now.Add(-2*time.Minute))

	dsWebhook := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "ds-webhook", UID: types.UID("uid-ds-webhook")},
		Status:     appsv1.DaemonSetStatus{DesiredNumberScheduled: 4, CurrentNumberScheduled: 2},
	}
	evDSWebhook := makeFailedCreateEvent("team-a", "DaemonSet", "ds-webhook",
		"admission webhook \"deny.example.com\" denied the request: missing owner label", now.Add(-3*time.Minute))

	// CrashLoopBackOff STS: under-replicated WITHOUT FailedCreate event -> must NOT flag.
	stsCrashLoop := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "sts-crashloop"},
		Spec:       appsv1.StatefulSetSpec{Replicas: ptr.To(int32(2))},
		Status:     appsv1.StatefulSetStatus{CurrentReplicas: 1},
	}

	// Stale FailedCreate event (>15m) -> must NOT count for STS.
	stsStaleEv := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "sts-stale-ev"},
		Spec:       appsv1.StatefulSetSpec{Replicas: ptr.To(int32(2))},
		Status:     appsv1.StatefulSetStatus{CurrentReplicas: 1},
	}
	evStale := makeFailedCreateEvent("team-a", "StatefulSet", "sts-stale-ev",
		"exceeded quota", now.Add(-20*time.Minute))

	// Downscaled RS (replicas=0 with downscaler annotation) and terminating RS -> skipped.
	rsDownscaled := makeBlockedRS("team-a", "rs-downscaled", "exceeded quota")
	rsDownscaled.Spec.Replicas = ptr.To(int32(0))
	rsDownscaled.Annotations = map[string]string{"downscaler/uptime": "never"}
	rsTerm := makeBlockedRS("team-a", "rs-term", "exceeded quota")
	rsTerm.DeletionTimestamp = &metav1.Time{Time: now.Add(-time.Minute)}

	cs := fake.NewSimpleClientset(
		rsQuota, rsPSA, rsOther,
		stsLimit, evSTSLimit,
		dsWebhook, evDSWebhook,
		stsCrashLoop, stsStaleEv, evStale,
		rsDownscaled, rsTerm,
	)
	p := testProber(cs)
	chk := probetest.MustCheck[*workloadAdmissionBlockGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("t=0s must arm inside 5m hysteresis, got %+v", res)
	}

	probetest.FreezeNow(p.Deps, now.Add(6*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatal("t=6m expected failure after 5m persistence")
	}

	for _, tc := range []struct {
		kind, name, reason string
	}{
		{"ReplicaSet", "rs-quota", admissionReasonQuotaExceeded},
		{"ReplicaSet", "rs-psa", admissionReasonPodSecurityDenied},
		{"ReplicaSet", "rs-other", admissionReasonOther},
		{"StatefulSet", "sts-limit", admissionReasonLimitRangeViolation},
		{"DaemonSet", "ds-webhook", admissionReasonWebhookRejected},
	} {
		if v, ok := admissionBlockedSeries(t, "team-a", tc.kind, tc.name, tc.reason); !ok || v != 1 {
			t.Fatalf("missing series for %+v: v=%v ok=%v", tc, v, ok)
		}
	}

	for _, tc := range []struct {
		kind, name, reason string
	}{
		{"StatefulSet", "sts-crashloop", admissionReasonOther},
		{"StatefulSet", "sts-stale-ev", admissionReasonQuotaExceeded},
		{"ReplicaSet", "rs-downscaled", admissionReasonQuotaExceeded},
		{"ReplicaSet", "rs-term", admissionReasonQuotaExceeded},
	} {
		if _, ok := admissionBlockedSeries(t, "team-a", tc.kind, tc.name, tc.reason); ok {
			t.Fatalf("unexpected series for %+v", tc)
		}
	}

	assertValidRFC1123EventNames(t, cs, "team-a")
	evsBefore, _ := cs.EventsV1().Events("team-a").List(ctx, metav1.ListOptions{})
	if len(evsBefore.Items) != 5 {
		t.Fatalf("expected 5 Warning Events (1 per blocked workload), got %d", len(evsBefore.Items))
	}

	// Repeat sweep inside cooldown -> no duplicate events emitted.
	probetest.FreezeNow(p.Deps, now.Add(7*time.Minute))
	evSTSLimit2 := makeFailedCreateEvent("team-a", "StatefulSet", "sts-limit",
		"maximum cpu usage", now.Add(6*time.Minute))
	_, _ = cs.CoreV1().Events("team-a").Create(ctx, evSTSLimit2, metav1.CreateOptions{})
	evDSWebhook2 := makeFailedCreateEvent("team-a", "DaemonSet", "ds-webhook",
		"admission webhook denied the request", now.Add(6*time.Minute))
	_, _ = cs.CoreV1().Events("team-a").Create(ctx, evDSWebhook2, metav1.CreateOptions{})

	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	evsAfter, _ := cs.EventsV1().Events("team-a").List(ctx, metav1.ListOptions{})
	if len(evsAfter.Items) != len(evsBefore.Items) {
		t.Fatalf("expected event cooldown dedup (%d -> %d)", len(evsBefore.Items), len(evsAfter.Items))
	}

	// Recover all workloads -> stale gauge tuples must be deleted.
	for _, name := range []string{"rs-quota", "rs-psa", "rs-other"} {
		u, _ := cs.AppsV1().ReplicaSets("team-a").Get(ctx, name, metav1.GetOptions{})
		u.Status.Conditions = nil
		_, _ = cs.AppsV1().ReplicaSets("team-a").UpdateStatus(ctx, u, metav1.UpdateOptions{})
	}
	uSTS, _ := cs.AppsV1().StatefulSets("team-a").Get(ctx, "sts-limit", metav1.GetOptions{})
	uSTS.Status.CurrentReplicas = 3
	_, _ = cs.AppsV1().StatefulSets("team-a").UpdateStatus(ctx, uSTS, metav1.UpdateOptions{})
	uDS, _ := cs.AppsV1().DaemonSets("team-a").Get(ctx, "ds-webhook", metav1.GetOptions{})
	uDS.Status.CurrentNumberScheduled = 4
	_, _ = cs.AppsV1().DaemonSets("team-a").UpdateStatus(ctx, uDS, metav1.UpdateOptions{})

	probetest.FreezeNow(p.Deps, now.Add(10*time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("recovered sweep must pass: %+v", res)
	}
	for _, tc := range []struct {
		kind, name, reason string
	}{
		{"ReplicaSet", "rs-quota", admissionReasonQuotaExceeded},
		{"ReplicaSet", "rs-psa", admissionReasonPodSecurityDenied},
		{"ReplicaSet", "rs-other", admissionReasonOther},
		{"StatefulSet", "sts-limit", admissionReasonLimitRangeViolation},
		{"DaemonSet", "ds-webhook", admissionReasonWebhookRejected},
	} {
		if _, ok := admissionBlockedSeries(t, "team-a", tc.kind, tc.name, tc.reason); ok {
			t.Fatalf("stale series not deleted for %+v", tc)
		}
	}
}

func TestWorkloadAdmissionBlockGuardSkipsEventsAndPodsOnEmptyCluster(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("pods must not be listed")
	})
	cs.PrependReactor("list", "events", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("events must not be listed when no candidates")
	})
	p := testProber(cs)
	chk := probetest.MustCheck[*workloadAdmissionBlockGuardCheck](t, p)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass || res.Infra != nil {
		t.Fatalf("empty cluster must pass without touching pods/events: %+v", res)
	}
}

func TestWorkloadAdmissionBlockGuardPreExistingTimestampsAndRecovery(t *testing.T) {
	now := time.Now()

	rsOld := makeBlockedRS("team-b", "rs-old", "pods \"rs-old-1\" is forbidden: exceeded quota: q1")
	rsOld.Status.Conditions[0].LastTransitionTime = metav1.NewTime(now.Add(-10 * time.Minute))

	stsRecurring := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "team-b",
			Name:              "sts-recurring",
			UID:               types.UID("uid-sts-recurring"),
			CreationTimestamp: metav1.NewTime(now.Add(-20 * time.Minute)),
		},
		Spec:   appsv1.StatefulSetSpec{Replicas: ptr.To(int32(2))},
		Status: appsv1.StatefulSetStatus{CurrentReplicas: 0},
	}
	evSTSRecurring := &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Namespace: "team-b", Name: "ev-sts-recurring"},
		InvolvedObject: corev1.ObjectReference{Kind: "StatefulSet", Namespace: "team-b", Name: "sts-recurring"},
		Reason:         "FailedCreate",
		Message:        "violates PodSecurity \"restricted:latest\"",
		FirstTimestamp: metav1.NewTime(now.Add(-10 * time.Minute)),
		LastTimestamp:  metav1.NewTime(now.Add(-1 * time.Minute)),
	}

	dsRecurring := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "team-b",
			Name:              "ds-recurring",
			UID:               types.UID("uid-ds-recurring"),
			CreationTimestamp: metav1.NewTime(now.Add(-20 * time.Minute)),
		},
		Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, CurrentNumberScheduled: 1},
	}
	evDSRecurring := &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Namespace: "team-b", Name: "ev-ds-recurring"},
		InvolvedObject: corev1.ObjectReference{Kind: "DaemonSet", Namespace: "team-b", Name: "ds-recurring"},
		Reason:         "FailedCreate",
		Message:        "admission webhook denied the request",
		FirstTimestamp: metav1.NewTime(now.Add(-6 * time.Minute)),
		LastTimestamp:  metav1.NewTime(now.Add(-1 * time.Minute)),
	}

	rsFresh := makeBlockedRS("team-b", "rs-fresh", "exceeded quota: q2")
	rsFresh.CreationTimestamp = metav1.NewTime(now.Add(-20 * time.Minute))
	rsFresh.Status.Conditions[0].LastTransitionTime = metav1.NewTime(now.Add(-2 * time.Minute))

	rsNoTS := makeBlockedRS("team-b", "rs-no-ts", "exceeded quota: q3")
	rsNoTS.CreationTimestamp = metav1.NewTime(now.Add(-20 * time.Minute))

	cs := fake.NewSimpleClientset(
		rsOld,
		stsRecurring, evSTSRecurring,
		dsRecurring, evDSRecurring,
		rsFresh, rsNoTS,
	)
	p := testProber(cs)
	chk := probetest.MustCheck[*workloadAdmissionBlockGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatal("t=0s expected failure for pre-existing >=5m blocked workloads")
	}

	for _, tc := range []struct {
		kind, name, reason string
	}{
		{"ReplicaSet", "rs-old", admissionReasonQuotaExceeded},
		{"StatefulSet", "sts-recurring", admissionReasonPodSecurityDenied},
		{"DaemonSet", "ds-recurring", admissionReasonWebhookRejected},
	} {
		if v, ok := admissionBlockedSeries(t, "team-b", tc.kind, tc.name, tc.reason); !ok || v != 1 {
			t.Fatalf("t=0s missing series for %+v: v=%v ok=%v", tc, v, ok)
		}
	}
	for _, name := range []string{"rs-fresh", "rs-no-ts"} {
		if _, ok := admissionBlockedSeries(t, "team-b", "ReplicaSet", name, admissionReasonQuotaExceeded); ok {
			t.Fatalf("t=0s %s must not flag prematurely (no creationTimestamp fallback)", name)
		}
	}

	// Timestamped workloads must stay out of firstSeen; only untimestamped rs-no-ts enters.
	for _, k := range []string{
		"ReplicaSet/team-b/rs-old",
		"StatefulSet/team-b/sts-recurring",
		"DaemonSet/team-b/ds-recurring",
		"ReplicaSet/team-b/rs-fresh",
	} {
		if _, tracked := chk.firstSeen.Seen(k, now); tracked {
			t.Fatalf("timestamped workload %s must not enter firstSeen", k)
		}
	}
	if _, tracked := chk.firstSeen.Seen("ReplicaSet/team-b/rs-no-ts", now); !tracked {
		t.Fatal("untimestamped rs-no-ts must enter firstSeen fallback")
	}

	// Advance +4m: rs-fresh (2m+4m=6m >= 5m) now flags, while rs-no-ts (4m < 5m) remains armed.
	probetest.FreezeNow(p.Deps, now.Add(4*time.Minute))
	res = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatal("t=4m expected failure")
	}
	if v, ok := admissionBlockedSeries(t, "team-b", "ReplicaSet", "rs-fresh", admissionReasonQuotaExceeded); !ok || v != 1 {
		t.Fatalf("t=4m expected rs-fresh to flag: v=%v ok=%v", v, ok)
	}
	if _, ok := admissionBlockedSeries(t, "team-b", "ReplicaSet", "rs-no-ts", admissionReasonQuotaExceeded); ok {
		t.Fatal("t=4m rs-no-ts must stay inside 5m firstSeen window")
	}

	// Recover all -> Pass=true, GaugeLedger series deleted, firstSeen pruned.
	for _, name := range []string{"rs-old", "rs-fresh", "rs-no-ts"} {
		u, _ := cs.AppsV1().ReplicaSets("team-b").Get(ctx, name, metav1.GetOptions{})
		u.Status.Conditions = nil
		_, _ = cs.AppsV1().ReplicaSets("team-b").UpdateStatus(ctx, u, metav1.UpdateOptions{})
	}
	uSTS, _ := cs.AppsV1().StatefulSets("team-b").Get(ctx, "sts-recurring", metav1.GetOptions{})
	uSTS.Status.CurrentReplicas = 2
	_, _ = cs.AppsV1().StatefulSets("team-b").UpdateStatus(ctx, uSTS, metav1.UpdateOptions{})
	uDS, _ := cs.AppsV1().DaemonSets("team-b").Get(ctx, "ds-recurring", metav1.GetOptions{})
	uDS.Status.CurrentNumberScheduled = 3
	_, _ = cs.AppsV1().DaemonSets("team-b").UpdateStatus(ctx, uDS, metav1.UpdateOptions{})

	probetest.FreezeNow(p.Deps, now.Add(6*time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("recovered sweep must pass: %+v", res)
	}
	for _, tc := range []struct {
		kind, name, reason string
	}{
		{"ReplicaSet", "rs-old", admissionReasonQuotaExceeded},
		{"StatefulSet", "sts-recurring", admissionReasonPodSecurityDenied},
		{"DaemonSet", "ds-recurring", admissionReasonWebhookRejected},
		{"ReplicaSet", "rs-fresh", admissionReasonQuotaExceeded},
		{"ReplicaSet", "rs-no-ts", admissionReasonQuotaExceeded},
	} {
		if _, ok := admissionBlockedSeries(t, "team-b", tc.kind, tc.name, tc.reason); ok {
			t.Fatalf("stale series not deleted for %+v", tc)
		}
	}
	if _, tracked := chk.firstSeen.Seen("ReplicaSet/team-b/rs-no-ts", now.Add(6*time.Minute)); tracked {
		t.Fatal("firstSeen entry for recovered rs-no-ts must be pruned")
	}
}

func TestWorkloadAdmissionBlockGuard403GracefulSkipAndHoldSeries(t *testing.T) {
	now := time.Now()
	forbiddenErr := &apierrors.StatusError{ErrStatus: metav1.Status{
		Status: metav1.StatusFailure, Reason: metav1.StatusReasonForbidden, Code: http.StatusForbidden,
	}}

	// Subtest 1: individual 403 on each of replicasets, statefulsets, daemonsets, events
	// after seeding an active series, verifying Pass: true, Infra: nil, 0 error delta,
	// and held series preservation (plus clean recovery once 403 lifts).
	for _, tc := range []struct {
		name     string
		resource string
		setup    func() []runtime.Object
		kind     string
		objName  string
		reason   string
		recover  func(cs *fake.Clientset)
	}{
		{
			name:     "replicasets_403",
			resource: "replicasets",
			setup: func() []runtime.Object {
				rs := makeBlockedRS("team-403-rs", "rs-403", "pods \"rs-403-1\" is forbidden: exceeded quota: q1")
				rs.Status.Conditions[0].LastTransitionTime = metav1.NewTime(now.Add(-10 * time.Minute))
				return []runtime.Object{rs}
			},
			kind:    "ReplicaSet",
			objName: "rs-403",
			reason:  admissionReasonQuotaExceeded,
			recover: func(cs *fake.Clientset) {
				u, _ := cs.AppsV1().ReplicaSets("team-403-rs").Get(ctx, "rs-403", metav1.GetOptions{})
				u.Status.Conditions = nil
				_, _ = cs.AppsV1().ReplicaSets("team-403-rs").UpdateStatus(ctx, u, metav1.UpdateOptions{})
			},
		},
		{
			name:     "statefulsets_403",
			resource: "statefulsets",
			setup: func() []runtime.Object {
				sts := &appsv1.StatefulSet{
					ObjectMeta: metav1.ObjectMeta{Namespace: "team-403-sts", Name: "sts-403", UID: types.UID("uid-sts-403")},
					Spec:       appsv1.StatefulSetSpec{Replicas: ptr.To(int32(2))},
					Status:     appsv1.StatefulSetStatus{CurrentReplicas: 0},
				}
				ev := &corev1.Event{
					ObjectMeta:     metav1.ObjectMeta{Namespace: "team-403-sts", Name: "ev-sts-403"},
					InvolvedObject: corev1.ObjectReference{Kind: "StatefulSet", Namespace: "team-403-sts", Name: "sts-403"},
					Reason:         "FailedCreate",
					Message:        "violates PodSecurity \"restricted:latest\"",
					FirstTimestamp: metav1.NewTime(now.Add(-10 * time.Minute)),
					LastTimestamp:  metav1.NewTime(now.Add(-1 * time.Minute)),
				}
				return []runtime.Object{sts, ev}
			},
			kind:    "StatefulSet",
			objName: "sts-403",
			reason:  admissionReasonPodSecurityDenied,
			recover: func(cs *fake.Clientset) {
				u, _ := cs.AppsV1().StatefulSets("team-403-sts").Get(ctx, "sts-403", metav1.GetOptions{})
				u.Status.CurrentReplicas = 2
				_, _ = cs.AppsV1().StatefulSets("team-403-sts").UpdateStatus(ctx, u, metav1.UpdateOptions{})
			},
		},
		{
			name:     "daemonsets_403",
			resource: "daemonsets",
			setup: func() []runtime.Object {
				ds := &appsv1.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{Namespace: "team-403-ds", Name: "ds-403", UID: types.UID("uid-ds-403")},
					Status:     appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, CurrentNumberScheduled: 1},
				}
				ev := &corev1.Event{
					ObjectMeta:     metav1.ObjectMeta{Namespace: "team-403-ds", Name: "ev-ds-403"},
					InvolvedObject: corev1.ObjectReference{Kind: "DaemonSet", Namespace: "team-403-ds", Name: "ds-403"},
					Reason:         "FailedCreate",
					Message:        "admission webhook denied the request",
					FirstTimestamp: metav1.NewTime(now.Add(-8 * time.Minute)),
					LastTimestamp:  metav1.NewTime(now.Add(-1 * time.Minute)),
				}
				return []runtime.Object{ds, ev}
			},
			kind:    "DaemonSet",
			objName: "ds-403",
			reason:  admissionReasonWebhookRejected,
			recover: func(cs *fake.Clientset) {
				u, _ := cs.AppsV1().DaemonSets("team-403-ds").Get(ctx, "ds-403", metav1.GetOptions{})
				u.Status.CurrentNumberScheduled = 3
				_, _ = cs.AppsV1().DaemonSets("team-403-ds").UpdateStatus(ctx, u, metav1.UpdateOptions{})
			},
		},
		{
			name:     "events_403",
			resource: "events",
			setup: func() []runtime.Object {
				sts := &appsv1.StatefulSet{
					ObjectMeta: metav1.ObjectMeta{Namespace: "team-403-ev", Name: "sts-ev403", UID: types.UID("uid-sts-ev403")},
					Spec:       appsv1.StatefulSetSpec{Replicas: ptr.To(int32(2))},
					Status:     appsv1.StatefulSetStatus{CurrentReplicas: 0},
				}
				ev := &corev1.Event{
					ObjectMeta:     metav1.ObjectMeta{Namespace: "team-403-ev", Name: "ev-sts-ev403"},
					InvolvedObject: corev1.ObjectReference{Kind: "StatefulSet", Namespace: "team-403-ev", Name: "sts-ev403"},
					Reason:         "FailedCreate",
					Message:        "exceeded quota: q-ev",
					FirstTimestamp: metav1.NewTime(now.Add(-8 * time.Minute)),
					LastTimestamp:  metav1.NewTime(now.Add(-1 * time.Minute)),
				}
				return []runtime.Object{sts, ev}
			},
			kind:    "StatefulSet",
			objName: "sts-ev403",
			reason:  admissionReasonQuotaExceeded,
			recover: func(cs *fake.Clientset) {
				u, _ := cs.AppsV1().StatefulSets("team-403-ev").Get(ctx, "sts-ev403", metav1.GetOptions{})
				u.Status.CurrentReplicas = 2
				_, _ = cs.AppsV1().StatefulSets("team-403-ev").UpdateStatus(ctx, u, metav1.UpdateOptions{})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs := tc.setup()
			ns := objs[0].(metav1.Object).GetNamespace()
			cs := fake.NewSimpleClientset(objs...)
			p := testProber(cs)
			chk := probetest.MustCheck[*workloadAdmissionBlockGuardCheck](t, p)

			probetest.FreezeNow(p.Deps, now)
			resSeed := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
			if resSeed.Pass {
				t.Fatalf("expected seeded failure before 403, got %+v", resSeed)
			}
			if v, ok := admissionBlockedSeries(t, ns, tc.kind, tc.objName, tc.reason); !ok || v != 1 {
				t.Fatalf("missing seeded series: v=%v ok=%v", v, ok)
			}

			// Transition target list call to 403 Forbidden.
			cs.PrependReactor("list", tc.resource, func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, forbiddenErr
			})

			probetest.FreezeNow(p.Deps, now.Add(2*time.Minute))
			beforeErrs := probetest.CounterSnapshot(t, p.Name)
			res403 := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
			if !res403.Pass || res403.Infra != nil {
				t.Fatalf("403 on %s must pass cleanly with nil Infra, got %+v", tc.resource, res403)
			}
			probetest.AssertCounterDelta(t, p.Name, beforeErrs, 0)
			if v, ok := admissionBlockedSeries(t, ns, tc.kind, tc.objName, tc.reason); !ok || v != 1 {
				t.Fatalf("403 on %s must carry held series forward: v=%v ok=%v", tc.resource, v, ok)
			}

			// Lift 403 and recover workload -> held series prunes cleanly.
			cs.ReactionChain = cs.ReactionChain[1:]
			tc.recover(cs)
			probetest.FreezeNow(p.Deps, now.Add(4*time.Minute))
			resRec := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
			if !resRec.Pass || resRec.Infra != nil {
				t.Fatalf("recovery sweep must pass: %+v", resRec)
			}
			if _, ok := admissionBlockedSeries(t, ns, tc.kind, tc.objName, tc.reason); ok {
				t.Fatal("stale held series not pruned after 403 cleared and workload recovered")
			}
		})
	}

	// Subtest 2: partial 403 on replicasets still checks statefulsets/daemonsets AND preserves
	// untimestamped RS firstSeen timers across the 403 flap; total 403 holds all series.
	t.Run("partial_and_total_403_with_firstSeen_hold", func(t *testing.T) {
		rsNoTS := makeBlockedRS("team-403-mix", "rs-nots", "exceeded quota: q-mix")
		stsMix := &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: "team-403-mix", Name: "sts-mix", UID: types.UID("uid-sts-mix")},
			Spec:       appsv1.StatefulSetSpec{Replicas: ptr.To(int32(2))},
			Status:     appsv1.StatefulSetStatus{CurrentReplicas: 0},
		}
		evMix := &corev1.Event{
			ObjectMeta:     metav1.ObjectMeta{Namespace: "team-403-mix", Name: "ev-sts-mix"},
			InvolvedObject: corev1.ObjectReference{Kind: "StatefulSet", Namespace: "team-403-mix", Name: "sts-mix"},
			Reason:         "FailedCreate",
			Message:        "limitrange minimum cpu",
			FirstTimestamp: metav1.NewTime(now.Add(-10 * time.Minute)),
			LastTimestamp:  metav1.NewTime(now.Add(-1 * time.Minute)),
		}

		cs := fake.NewSimpleClientset(rsNoTS, stsMix, evMix)
		p := testProber(cs)
		chk := probetest.MustCheck[*workloadAdmissionBlockGuardCheck](t, p)

		// t=0s: rs-nots enters firstSeen; sts-mix flags immediately.
		probetest.FreezeNow(p.Deps, now)
		if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Pass {
			t.Fatal("expected sts-mix failure at t=0s")
		}
		if _, tracked := chk.firstSeen.Seen("ReplicaSet/team-403-mix/rs-nots", now); !tracked {
			t.Fatal("expected rs-nots in firstSeen at t=0s")
		}

		// t=2m: replicasets returns 403 -> sts-mix still checked & flags, rs-nots firstSeen preserved.
		cs.PrependReactor("list", "replicasets", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, forbiddenErr
		})
		probetest.FreezeNow(p.Deps, now.Add(2*time.Minute))
		beforeErrs := probetest.CounterSnapshot(t, p.Name)
		resPartial := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if resPartial.Pass || resPartial.Infra != nil {
			t.Fatalf("partial 403 on replicasets must still flag sts-mix with nil Infra, got %+v", resPartial)
		}
		probetest.AssertCounterDelta(t, p.Name, beforeErrs, 0)
		if _, tracked := chk.firstSeen.Seen("ReplicaSet/team-403-mix/rs-nots", now.Add(2*time.Minute)); !tracked {
			t.Fatal("replicasets 403 must preserve ReplicaSet firstSeen entry")
		}

		// t=4m: all list calls return 403 -> Pass: true, Infra: nil, sts-mix carried.
		cs.PrependReactor("list", "statefulsets", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, forbiddenErr
		})
		cs.PrependReactor("list", "daemonsets", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, forbiddenErr
		})
		cs.PrependReactor("list", "events", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, forbiddenErr
		})
		probetest.FreezeNow(p.Deps, now.Add(4*time.Minute))
		beforeAllErrs := probetest.CounterSnapshot(t, p.Name)
		resAll := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if !resAll.Pass || resAll.Infra != nil {
			t.Fatalf("total 403 must pass cleanly with nil Infra, got %+v", resAll)
		}
		probetest.AssertCounterDelta(t, p.Name, beforeAllErrs, 0)
		if v, ok := admissionBlockedSeries(t, "team-403-mix", "StatefulSet", "sts-mix", admissionReasonLimitRangeViolation); !ok || v != 1 {
			t.Fatalf("total 403 must carry sts-mix series: v=%v ok=%v", v, ok)
		}

		// t=6m: lift all 403s -> rs-nots flags immediately because firstSeen was preserved from t=0s.
		cs.ReactionChain = cs.ReactionChain[4:]
		probetest.FreezeNow(p.Deps, now.Add(6*time.Minute))
		resLift := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if resLift.Pass || resLift.Infra != nil {
			t.Fatalf("expected failure after 403 lifted, got %+v", resLift)
		}
		if v, ok := admissionBlockedSeries(t, "team-403-mix", "ReplicaSet", "rs-nots", admissionReasonQuotaExceeded); !ok || v != 1 {
			t.Fatalf("preserved firstSeen should flag rs-nots at t=6m: v=%v ok=%v", v, ok)
		}
	})
}

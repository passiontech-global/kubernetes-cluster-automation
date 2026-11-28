package watchdogs

import (
	"fmt"
	"strings"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

func initWedgeProber(cs *fake.Clientset) *probetest.Prober {
	return probetest.NewCheckProber(cs, nil, NewInitContainerWedgeGuardCheck)
}

func initWedgePod(ns, name, uid string, phase corev1.PodPhase, createdAt time.Time, initSpecs []corev1.Container, initStatuses []corev1.ContainerStatus) *corev1.Pod {
	var creation metav1.Time
	if !createdAt.IsZero() {
		creation = metav1.NewTime(createdAt)
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			UID:               types.UID(uid),
			CreationTimestamp: creation,
		},
		Spec: corev1.PodSpec{
			InitContainers: initSpecs,
			Containers:     []corev1.Container{{Name: "app"}},
		},
		Status: corev1.PodStatus{
			Phase:                 phase,
			InitContainerStatuses: initStatuses,
		},
	}
}

func TestInitContainerWedgeGuard(t *testing.T) {
	base := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)

	t.Run("Init:CrashLoopBackOff >= 30m flagged and emits event + metric", func(t *testing.T) {
		initWedgeWedgedGauge.Reset()
		pod := initWedgePod("apps", "wedged-crash", "u1", corev1.PodPending, base.Add(-45*time.Minute),
			[]corev1.Container{{Name: "init-migrate"}},
			[]corev1.ContainerStatus{{
				Name: "init-migrate",
				State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
					Reason:  "CrashLoopBackOff",
					Message: "back-off 5m0s restarting failed container",
				}},
			}},
		)
		cs := fake.NewSimpleClientset(pod)
		p := initWedgeProber(cs)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*initWedgeGuardCheck](t, p)

		res := probetest.RunCheck(ctx, chk.Deps, chk)
		if res.Pass || res.Infra != nil {
			t.Fatalf("Run = %+v, want Pass=false Infra=nil", res)
		}
		if !strings.Contains(res.Why, "apps/wedged-crash (init-migrate: init_crash_loop)") {
			t.Fatalf("Why = %q, missing expected reason", res.Why)
		}
		if v := ptestutil.ToFloat64(initWedgeWedgedGauge.WithLabelValues("apps", "wedged-crash", "init-migrate", initWedgeReasonCrashLoop)); v != 1 {
			t.Fatalf("gauge = %v, want 1", v)
		}
		evs, err := cs.EventsV1().Events("apps").List(ctx, metav1.ListOptions{})
		if err != nil || len(evs.Items) != 1 || evs.Items[0].Reason != initWedgeEventReason {
			t.Fatalf("events = %+v (err=%v), want 1 %s", evs.Items, err, initWedgeEventReason)
		}

		// Repeat within cooldown: no duplicate event.
		probetest.FreezeNow(p.Deps, base.Add(10*time.Minute))
		_ = probetest.RunCheck(ctx, chk.Deps, chk)
		evs2, _ := cs.EventsV1().Events("apps").List(ctx, metav1.ListOptions{})
		if len(evs2.Items) != 1 {
			t.Fatalf("expected cooldown dedup, got %d events", len(evs2.Items))
		}
	})

	t.Run("long-running init >= 30m flagged; opt-out annotation skipped", func(t *testing.T) {
		initWedgeWedgedGauge.Reset()
		stuck := initWedgePod("apps", "slow-init", "u2", corev1.PodPending, base.Add(-40*time.Minute),
			[]corev1.Container{{Name: "load-data"}},
			[]corev1.ContainerStatus{{
				Name: "load-data",
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{
					StartedAt: metav1.NewTime(base.Add(-35 * time.Minute)),
				}},
			}},
		)
		optedOut := stuck.DeepCopy()
		optedOut.Name = "intentional-loader"
		optedOut.UID = "u3"
		optedOut.Annotations = map[string]string{initWedgeIgnoreAnnotation: "true"}

		cs := fake.NewSimpleClientset(stuck, optedOut)
		p := initWedgeProber(cs)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*initWedgeGuardCheck](t, p)

		res := probetest.RunCheck(ctx, chk.Deps, chk)
		if res.Pass {
			t.Fatalf("expected slow-init to fail check")
		}
		if strings.Contains(res.Why, "intentional-loader") {
			t.Fatalf("opted-out pod falsely flagged: %q", res.Why)
		}
		if v := ptestutil.ToFloat64(initWedgeWedgedGauge.WithLabelValues("apps", "slow-init", "load-data", initWedgeReasonLongRunning)); v != 1 {
			t.Fatalf("slow-init gauge = %v, want 1", v)
		}
		if v := ptestutil.ToFloat64(initWedgeWedgedGauge.WithLabelValues("apps", "intentional-loader", "load-data", initWedgeReasonLongRunning)); v != 0 {
			t.Fatalf("opted-out gauge = %v, want 0", v)
		}
	})

	t.Run("fresh < 30m and zero timestamp skipped", func(t *testing.T) {
		initWedgeWedgedGauge.Reset()
		fresh := initWedgePod("apps", "fresh-init", "u4", corev1.PodPending, base.Add(-15*time.Minute),
			[]corev1.Container{{Name: "init-x"}},
			[]corev1.ContainerStatus{{
				Name: "init-x",
				State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
					Reason: "ImagePullBackOff",
				}},
			}},
		)
		zeroTS := initWedgePod("apps", "zero-ts", "u5", corev1.PodPending, time.Time{},
			[]corev1.Container{{Name: "init-y"}},
			[]corev1.ContainerStatus{{
				Name: "init-y",
				State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
					Reason: "CrashLoopBackOff",
				}},
			}},
		)
		zeroRunning := initWedgePod("apps", "zero-run", "u6", corev1.PodPending, time.Time{},
			[]corev1.Container{{Name: "init-z"}},
			[]corev1.ContainerStatus{{
				Name:  "init-z",
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}},
		)
		cs := fake.NewSimpleClientset(fresh, zeroTS, zeroRunning)
		p := initWedgeProber(cs)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*initWedgeGuardCheck](t, p)

		res := probetest.RunCheck(ctx, chk.Deps, chk)
		if !res.Pass || res.Infra != nil {
			t.Fatalf("fresh/zero-timestamp pods falsely flagged: %+v", res)
		}
	})

	t.Run("running K8s 1.29+ native sidecar alongside healthy main container NOT falsely flagged", func(t *testing.T) {
		initWedgeWedgedGauge.Reset()
		always := corev1.ContainerRestartPolicyAlways
		nativeHealthy := initWedgePod("apps", "native-sidecar-ok", "u7", corev1.PodRunning, base.Add(-2*time.Hour),
			[]corev1.Container{{Name: "istio-proxy", RestartPolicy: &always}},
			[]corev1.ContainerStatus{{
				Name: "istio-proxy",
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{
					StartedAt: metav1.NewTime(base.Add(-2 * time.Hour)),
				}},
			}},
		)
		nativeHealthy.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name: "app",
			State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{
				StartedAt: metav1.NewTime(base.Add(-2 * time.Hour)),
			}},
		}}
		nativeHealthy.Status.Conditions = []corev1.PodCondition{{
			Type:   corev1.PodInitialized,
			Status: corev1.ConditionTrue,
		}}

		// Even if Pod is still Pending (e.g. main container starting), a native
		// sidecar with restartPolicy: Always must NEVER be flagged.
		nativeStarting := initWedgePod("apps", "native-sidecar-pending", "u8", corev1.PodPending, base.Add(-2*time.Hour),
			[]corev1.Container{{Name: "istio-proxy", RestartPolicy: &always}},
			[]corev1.ContainerStatus{{
				Name: "istio-proxy",
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{
					StartedAt: metav1.NewTime(base.Add(-2 * time.Hour)),
				}},
			}},
		)

		cs := fake.NewSimpleClientset(nativeHealthy, nativeStarting)
		p := initWedgeProber(cs)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*initWedgeGuardCheck](t, p)

		res := probetest.RunCheck(ctx, chk.Deps, chk)
		if !res.Pass || res.Infra != nil {
			t.Fatalf("K8s 1.29+ native sidecar falsely flagged: %+v", res)
		}
	})

	t.Run("custom NODE_AUTOMATION_INIT_WEDGE_MIN_AGE and event cap", func(t *testing.T) {
		initWedgeWedgedGauge.Reset()
		t.Setenv("NODE_AUTOMATION_INIT_WEDGE_MIN_AGE", "10m")

		var objs []runtime.Object
		for i := 0; i < initWedgeMaxEventsPerSweep+3; i++ {
			objs = append(objs, initWedgePod("apps", fmt.Sprintf("pod-%02d", i), fmt.Sprintf("uid-%02d", i),
				corev1.PodPending, base.Add(-15*time.Minute),
				[]corev1.Container{{Name: "init-cfg"}},
				[]corev1.ContainerStatus{{
					Name: "init-cfg",
					State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
						Reason: "CreateContainerConfigError",
					}},
				}},
			))
		}
		cs := fake.NewSimpleClientset(objs...)
		p := initWedgeProber(cs)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*initWedgeGuardCheck](t, p)

		res := probetest.RunCheck(ctx, chk.Deps, chk)
		if res.Pass {
			t.Fatal("expected check to fail with custom 10m minAge")
		}
		evs, err := cs.EventsV1().Events("apps").List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(evs.Items) != initWedgeMaxEventsPerSweep {
			t.Fatalf("events = %d, want cap %d", len(evs.Items), initWedgeMaxEventsPerSweep)
		}
	})
}

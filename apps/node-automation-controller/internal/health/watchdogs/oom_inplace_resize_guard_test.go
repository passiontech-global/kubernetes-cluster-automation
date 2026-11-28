// oom_inplace_resize_guard_test.go — coverage for oom-inplace-resize-guard:
// detection-only default, cross-sweep restart baseline & nil/zero timestamp
// safety, curated infra allowlist + env opt-in, annotation opt-in/opt-out,
// +25%/min +64Mi & 2x cap, node Allocatable headroom gate, 404/403/422 graceful
// skip with budget refund, and 1h per-pod cooldown.
//
// SYMBOL HYGIENE: every package-private symbol uses the oomResize* prefix.
package watchdogs

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

type oomResizePatchRecord struct {
	ns    string
	name  string
	patch string
}

func oomResizeTestProber(cs *fake.Clientset) *probetest.Prober {
	return probetest.NewCheckProber(cs, probetest.OpDyn(), NewOOMInplaceResizeGuardCheck)
}

func oomResizeRunSweep(chk probefw.Check, d *probefw.Deps) probefw.Result {
	sctx := probetest.SweepCtx(ctx, d)
	res := chk.Run(sctx)
	probetest.VerifySweep(sctx)
	return res
}

func oomResizeMakeNode(name, allocMem string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{
			Allocatable: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse(allocMem),
			},
		},
	}
}

func oomResizeMakePod(
	ns, name, nodeName, container, reqMem, limMem string,
	restarts int32,
	createdAt, finishedAt time.Time,
	annos map[string]string,
) *corev1.Pod {
	ctrlTrue := true
	res := corev1.ResourceRequirements{
		Limits: corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse(limMem),
		},
	}
	if reqMem != "" {
		res.Requests = corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse(reqMem),
		}
	}
	cs := corev1.ContainerStatus{
		Name:         container,
		RestartCount: restarts,
	}
	if restarts > 0 {
		cs.LastTerminationState = corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{
				Reason:     "OOMKilled",
				FinishedAt: metav1.NewTime(finishedAt),
			},
		}
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			UID:               types.UID("uid-" + ns + "-" + name),
			CreationTimestamp: metav1.NewTime(createdAt),
			Annotations:       annos,
			OwnerReferences: []metav1.OwnerReference{{
				Kind:       "ReplicaSet",
				Name:       name + "-rs",
				UID:        types.UID("rs-" + ns + "-" + name),
				Controller: &ctrlTrue,
			}},
		},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
			Containers: []corev1.Container{{
				Name:      container,
				Resources: res,
			}},
		},
		Status: corev1.PodStatus{
			Phase:             corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{cs},
		},
	}
}

func oomResizeCapturePatches(
	cs *fake.Clientset,
	react func(subresource string, pa ktesting.PatchAction) (bool, error),
) *[]oomResizePatchRecord {
	var patches []oomResizePatchRecord
	cs.PrependReactor("patch", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
		if action.GetSubresource() != "resize" {
			return false, nil, nil
		}
		pa := action.(ktesting.PatchAction)
		if react != nil {
			if handled, err := react(action.GetSubresource(), pa); handled {
				return true, nil, err
			}
		}
		patches = append(patches, oomResizePatchRecord{
			ns:    pa.GetNamespace(),
			name:  pa.GetName(),
			patch: string(pa.GetPatch()),
		})
		return true, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: pa.GetNamespace(), Name: pa.GetName()}}, nil
	})
	return &patches
}

func TestOOMResizeDetectionOnlyDefaultAndBaselines(t *testing.T) {
	base := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

	t.Run("detection-only default alerts on >=3 recent OOMs and performs zero resize patches", func(t *testing.T) {
		oomResizeBurstGauge.Reset()
		node := oomResizeMakeNode("n1", "4Gi")
		pod := oomResizeMakePod("kube-system", "coredns-abc", "n1", "coredns", "128Mi", "128Mi",
			3, base.Add(-5*time.Minute), base.Add(-1*time.Minute), nil)
		// Zero-timestamp pod must not panic or falsely alert.
		zeroPod := oomResizeMakePod("apps", "zero-ts", "n1", "app", "128Mi", "128Mi",
			5, time.Time{}, time.Time{}, nil)

		cs := fake.NewSimpleClientset(node, pod, zeroPod)
		patches := oomResizeCapturePatches(cs, nil)
		p := oomResizeTestProber(cs)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*oomResizeGuardCheck](t, p)

		res := oomResizeRunSweep(chk, p.Deps)
		if res.Pass {
			t.Fatalf("expected failure on >=3 OOM restarts: %+v", res)
		}
		if !strings.Contains(res.Why, "kube-system/coredns-abc[coredns]") {
			t.Fatalf("Why missing coredns finding: %q", res.Why)
		}
		if strings.Contains(res.Why, "zero-ts") {
			t.Fatalf("zero timestamp pod falsely triggered: %q", res.Why)
		}
		if v, ok := testutil.GaugeSeriesValue(t, "node_automation_oom_inplace_resize_burst",
			map[string]string{"namespace": "kube-system", "pod": "coredns-abc", "container": "coredns"}); !ok || v != 1 {
			t.Fatalf("gauge = %v,%v want 1,true", v, ok)
		}
		if len(*patches) != 0 {
			t.Fatalf("detection-only default issued resize patches: %+v", *patches)
		}
		evs, err := cs.EventsV1().Events("kube-system").List(ctx, metav1.ListOptions{})
		if err != nil || len(evs.Items) != 1 || evs.Items[0].Reason != oomResizeEventReason {
			t.Fatalf("expected 1 OOMResizeBurst event, got err=%v items=%+v", err, evs.Items)
		}
	})

	t.Run("old pod tracks restart delta across sweeps inside 15m window", func(t *testing.T) {
		oomResizeBurstGauge.Reset()
		node := oomResizeMakeNode("n1", "4Gi")
		// Old pod created 3h ago with 10 historical restarts -> 1 recent OOM on sweep 1.
		pod := oomResizeMakePod("apps", "worker-0", "n1", "app", "128Mi", "128Mi",
			10, base.Add(-3*time.Hour), base.Add(-1*time.Minute), nil)
		cs := fake.NewSimpleClientset(node, pod)
		p := oomResizeTestProber(cs)
		chk := probetest.MustCheck[*oomResizeGuardCheck](t, p)

		probetest.FreezeNow(p.Deps, base)
		if res := oomResizeRunSweep(chk, p.Deps); !res.Pass {
			t.Fatalf("sweep 1 (only 1 proven recent OOM) must pass: %+v", res)
		}

		// Sweep 2 (+4m): +2 OOM restarts -> 3 total inside 15m -> alerts!
		probetest.FreezeNow(p.Deps, base.Add(4*time.Minute))
		u, _ := cs.CoreV1().Pods("apps").Get(ctx, "worker-0", metav1.GetOptions{})
		u.Status.ContainerStatuses[0].RestartCount = 12
		u.Status.ContainerStatuses[0].LastTerminationState.Terminated.FinishedAt = metav1.NewTime(base.Add(3 * time.Minute))
		_, _ = cs.CoreV1().Pods("apps").UpdateStatus(ctx, u, metav1.UpdateOptions{})

		if res := oomResizeRunSweep(chk, p.Deps); res.Pass {
			t.Fatal("sweep 2 reaching 3 OOMs within 15m must fail")
		}
	})
}

func TestOOMResizeInfraAllowlistAndAnnotationOptIn(t *testing.T) {
	base := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

	t.Run("env opt-in resizes curated infra allowlist only and skips opt-out false", func(t *testing.T) {
		oomResizeBurstGauge.Reset()
		t.Setenv("NODE_AUTOMATION_OOM_INPLACE_RESIZE_HEAL_ENABLED", "true")

		node := oomResizeMakeNode("n1", "16Gi")
		// Allowlisted via container name "linkerd-proxy"
		proxyPod := oomResizeMakePod("apps", "web-0", "n1", "linkerd-proxy", "64Mi", "128Mi",
			3, base.Add(-5*time.Minute), base.Add(-1*time.Minute), nil)
		// Allowlisted via namespace "flux-system"
		fluxPod := oomResizeMakePod("flux-system", "helm-controller-0", "n1", "manager", "512Mi", "512Mi",
			3, base.Add(-5*time.Minute), base.Add(-1*time.Minute), nil)
		// Allowlisted coredns but explicitly opted out via annotation "false"
		corednsOptOut := oomResizeMakePod("kube-system", "coredns-optout", "n1", "coredns", "128Mi", "128Mi",
			3, base.Add(-5*time.Minute), base.Add(-1*time.Minute), map[string]string{
				oomResizeAnnoOptIn: "false",
			})
		// Non-allowlisted user app -> skipped
		userPod := oomResizeMakePod("apps", "api-0", "n1", "api", "256Mi", "256Mi",
			3, base.Add(-5*time.Minute), base.Add(-1*time.Minute), nil)

		cs := fake.NewSimpleClientset(node, proxyPod, fluxPod, corednsOptOut, userPod)
		patches := oomResizeCapturePatches(cs, nil)
		p := oomResizeTestProber(cs)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*oomResizeGuardCheck](t, p)

		_ = oomResizeRunSweep(chk, p.Deps)
		if len(*patches) != 2 {
			t.Fatalf("patches = %+v, want 2 (linkerd-proxy and flux-system)", *patches)
		}
		// proxyPod: 128Mi + min 64Mi = 192Mi (requests stay <= limits; burstable omits requests)
		// fluxPod: 512Mi + 25% = 640Mi (guaranteed: requests bumped too)
		if (*patches)[0].name != "web-0" || !strings.Contains((*patches)[0].patch, `"192Mi"`) {
			t.Fatalf("unexpected web-0 resize patch: %+v", (*patches)[0])
		}
		if (*patches)[1].name != "helm-controller-0" ||
			!strings.Contains((*patches)[1].patch, `"limits":{"memory":"640Mi"}`) ||
			!strings.Contains((*patches)[1].patch, `"requests":{"memory":"640Mi"}`) {
			t.Fatalf("unexpected fluxPod resize patch: %+v", (*patches)[1])
		}
	})

	t.Run("annotation opt-in works on arbitrary pod when env is false", func(t *testing.T) {
		oomResizeBurstGauge.Reset()
		t.Setenv("NODE_AUTOMATION_OOM_INPLACE_RESIZE_HEAL_ENABLED", "false")

		node := oomResizeMakeNode("n1", "8Gi")
		pod := oomResizeMakePod("apps", "custom-0", "n1", "app", "128Mi", "256Mi",
			4, base.Add(-5*time.Minute), base.Add(-1*time.Minute), map[string]string{
				oomResizeAnnoOptIn: "true",
			})
		cs := fake.NewSimpleClientset(node, pod)
		patches := oomResizeCapturePatches(cs, nil)
		p := oomResizeTestProber(cs)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*oomResizeGuardCheck](t, p)

		_ = oomResizeRunSweep(chk, p.Deps)
		if len(*patches) != 1 || !strings.Contains((*patches)[0].patch, `"320Mi"`) {
			t.Fatalf("expected 256Mi->320Mi resize via annotation opt-in, got %+v", *patches)
		}
	})
}

func TestOOMResizeCapHeadroomErrorsAndCooldown(t *testing.T) {
	base := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

	t.Run("2x cap enforced via orig-limit annotation and in-RAM tracking", func(t *testing.T) {
		oomResizeBurstGauge.Reset()
		t.Setenv("NODE_AUTOMATION_OOM_INPLACE_RESIZE_HEAL_ENABLED", "true")

		node := oomResizeMakeNode("n1", "8Gi")
		// Already at 256Mi with orig limit 128Mi -> 2x cap reached, skip!
		atCap := oomResizeMakePod("kube-system", "coredns-cap", "n1", "coredns", "128Mi", "256Mi",
			3, base.Add(-5*time.Minute), base.Add(-1*time.Minute), map[string]string{
				oomResizeAnnoOrigLimit: `{"coredns":"128Mi"}`,
			})
		// At 200Mi with orig 128Mi -> +25% (50Mi) < min +64Mi = 264Mi -> clamped to 256Mi!
		nearCap := oomResizeMakePod("kube-system", "coredns-near", "n1", "coredns", "128Mi", "200Mi",
			3, base.Add(-5*time.Minute), base.Add(-1*time.Minute), map[string]string{
				oomResizeAnnoOrigLimit: "128Mi",
			})
		cs := fake.NewSimpleClientset(node, atCap, nearCap)
		patches := oomResizeCapturePatches(cs, nil)
		p := oomResizeTestProber(cs)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*oomResizeGuardCheck](t, p)

		_ = oomResizeRunSweep(chk, p.Deps)
		if len(*patches) != 1 || (*patches)[0].name != "coredns-near" || !strings.Contains((*patches)[0].patch, `"256Mi"`) {
			t.Fatalf("2x cap clamping failed, patches=%+v", *patches)
		}
	})

	t.Run("node Allocatable headroom gate skips when node memory is full", func(t *testing.T) {
		oomResizeBurstGauge.Reset()
		t.Setenv("NODE_AUTOMATION_OOM_INPLACE_RESIZE_HEAL_ENABLED", "true")

		node := oomResizeMakeNode("tight-node", "1Gi")
		neighbor := oomResizeMakePod("apps", "heavy", "tight-node", "heavy", "850Mi", "900Mi",
			0, base.Add(-1*time.Hour), time.Time{}, nil)
		target := oomResizeMakePod("kube-system", "coredns-tight", "tight-node", "coredns", "128Mi", "128Mi",
			3, base.Add(-5*time.Minute), base.Add(-1*time.Minute), nil)
		// Used = 850 + 128 = 978Mi; Allocatable = 1024Mi; headroom = 46Mi < needed 64Mi -> skip!
		cs := fake.NewSimpleClientset(node, neighbor, target)
		patches := oomResizeCapturePatches(cs, nil)
		p := oomResizeTestProber(cs)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*oomResizeGuardCheck](t, p)

		_ = oomResizeRunSweep(chk, p.Deps)
		if len(*patches) != 0 {
			t.Fatalf("headroom gate allowed resize on tight node: %+v", *patches)
		}
	})

	t.Run("403/404/422 gracefully skip without IncError and refund budget", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			err  error
		}{
			{"403", apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "p", http.ErrBodyNotAllowed)},
			{"404", apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "p")},
			{"422", apierrors.NewGenericServerResponse(http.StatusUnprocessableEntity, "patch", schema.GroupResource{Resource: "pods"}, "p", "unsupported", 0, false)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				oomResizeBurstGauge.Reset()
				t.Setenv("NODE_AUTOMATION_OOM_INPLACE_RESIZE_HEAL_ENABLED", "true")
				heal.ConfigureBudget(1, time.Hour)
				t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

				node := oomResizeMakeNode("n1", "8Gi")
				pod := oomResizeMakePod("kube-system", "coredns-err", "n1", "coredns", "128Mi", "128Mi",
					3, base.Add(-5*time.Minute), base.Add(-1*time.Minute), nil)
				cs := fake.NewSimpleClientset(node, pod)
				_ = oomResizeCapturePatches(cs, func(string, ktesting.PatchAction) (bool, error) {
					return true, tc.err
				})

				p := oomResizeTestProber(cs)
				probetest.FreezeNow(p.Deps, base)
				chk := probetest.MustCheck[*oomResizeGuardCheck](t, p)

				before := probetest.CounterSnapshot(t, p.Deps.Name)
				sctx := probetest.SweepCtx(ctx, chk.Deps)
				_ = chk.Run(sctx)
				probetest.VerifySweep(sctx)
				probetest.AssertCounterDelta(t, p.Deps.Name, before, 0)

				if proceed, _ := chk.HealAllowed(sctx, logr.Discard(), nil, "other", time.Minute, base); !proceed {
					t.Fatalf("%s did not refund fleet budget grant", tc.name)
				}
			})
		}
	})

	t.Run("1h per-pod cooldown suppresses repeat resize", func(t *testing.T) {
		oomResizeBurstGauge.Reset()
		t.Setenv("NODE_AUTOMATION_OOM_INPLACE_RESIZE_HEAL_ENABLED", "true")

		node := oomResizeMakeNode("n1", "8Gi")
		pod := oomResizeMakePod("kube-system", "coredns-cd", "n1", "coredns", "128Mi", "128Mi",
			3, base.Add(-5*time.Minute), base.Add(-1*time.Minute), nil)
		cs := fake.NewSimpleClientset(node, pod)
		patches := oomResizeCapturePatches(cs, nil)
		p := oomResizeTestProber(cs)
		chk := probetest.MustCheck[*oomResizeGuardCheck](t, p)

		probetest.FreezeNow(p.Deps, base)
		_ = oomResizeRunSweep(chk, p.Deps)
		if len(*patches) != 1 {
			t.Fatalf("expected 1 patch on sweep 1, got %d", len(*patches))
		}

		// Simulate another OOM 20m later -> inside 1h cooldown, must not resize.
		probetest.FreezeNow(p.Deps, base.Add(20*time.Minute))
		u, _ := cs.CoreV1().Pods("kube-system").Get(ctx, "coredns-cd", metav1.GetOptions{})
		u.Status.ContainerStatuses[0].RestartCount = 6
		u.Status.ContainerStatuses[0].LastTerminationState.Terminated.FinishedAt = metav1.NewTime(base.Add(19 * time.Minute))
		_, _ = cs.CoreV1().Pods("kube-system").UpdateStatus(ctx, u, metav1.UpdateOptions{})

		_ = oomResizeRunSweep(chk, p.Deps)
		if len(*patches) != 1 {
			t.Fatalf("1h cooldown did not suppress repeat resize, patches=%d", len(*patches))
		}

		// +61m: cooldown expired -> resizes again!
		probetest.FreezeNow(p.Deps, base.Add(61*time.Minute))
		u2, _ := cs.CoreV1().Pods("kube-system").Get(ctx, "coredns-cd", metav1.GetOptions{})
		u2.Status.ContainerStatuses[0].RestartCount = 9
		u2.Status.ContainerStatuses[0].LastTerminationState.Terminated.FinishedAt = metav1.NewTime(base.Add(60 * time.Minute))
		_, _ = cs.CoreV1().Pods("kube-system").UpdateStatus(ctx, u2, metav1.UpdateOptions{})

		_ = oomResizeRunSweep(chk, p.Deps)
		if len(*patches) != 2 {
			t.Fatalf("post-cooldown resize failed, patches=%d", len(*patches))
		}
	})

	t.Run("skips pods with active/pending resize, counts native sidecar initContainers in headroom, and resets origLimit on UID change", func(t *testing.T) {
		oomResizeBurstGauge.Reset()
		t.Setenv("NODE_AUTOMATION_OOM_INPLACE_RESIZE_HEAL_ENABLED", "true")

		node := oomResizeMakeNode("n1", "1Gi")
		// Native sidecar consumes 800Mi + target consumes 128Mi = 928Mi; headroom = 96Mi < needed 64Mi? Wait:
		// make sidecar 850Mi -> used = 850 + 128 = 978Mi; headroom = 46Mi < 64Mi -> must skip!
		always := corev1.ContainerRestartPolicyAlways
		sidecarPod := oomResizeMakePod("apps", "sidecar-holder", "n1", "app", "128Mi", "128Mi",
			0, base.Add(-1*time.Hour), time.Time{}, nil)
		sidecarPod.Spec.InitContainers = []corev1.Container{{
			Name:          "istio-proxy",
			RestartPolicy: &always,
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("850Mi")},
			},
		}}
		sidecarPod.Spec.Containers[0].Resources.Requests[corev1.ResourceMemory] = resource.MustParse("0")
		sidecarPod.Spec.Containers[0].Resources.Limits[corev1.ResourceMemory] = resource.MustParse("0")

		tightTarget := oomResizeMakePod("kube-system", "coredns-tight-sc", "n1", "coredns", "128Mi", "128Mi",
			3, base.Add(-5*time.Minute), base.Add(-1*time.Minute), nil)

		// Active resize on another node -> must skip.
		node2 := oomResizeMakeNode("n2", "8Gi")
		resizingPod := oomResizeMakePod("kube-system", "coredns-resizing", "n2", "coredns", "128Mi", "128Mi",
			3, base.Add(-5*time.Minute), base.Add(-1*time.Minute), nil)
		resizingPod.Status.Conditions = []corev1.PodCondition{{
			Type:   corev1.PodResizePending,
			Status: corev1.ConditionTrue,
			Reason: corev1.PodReasonDeferred,
		}}

		cs := fake.NewSimpleClientset(node, node2, sidecarPod, tightTarget, resizingPod)
		patches := oomResizeCapturePatches(cs, nil)
		p := oomResizeTestProber(cs)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*oomResizeGuardCheck](t, p)

		_ = oomResizeRunSweep(chk, p.Deps)
		if len(*patches) != 0 {
			t.Fatalf("expected active-resize pod and sidecar-headroom-tight pod skipped, got %+v", *patches)
		}

		// Recreate pod with same name but new UID and smaller limit -> origLimits must not inherit old UID cap.
		recreated := oomResizeMakePod("kube-system", "coredns-recreate", "n2", "coredns", "128Mi", "128Mi",
			3, base.Add(-5*time.Minute), base.Add(-1*time.Minute), nil)
		recreated.UID = "uid-old"
		chk.origLimits[oomResizeBaselineKey(recreated, "coredns")] = resource.MustParse("64Mi")
		recreated.UID = "uid-new"
		_, _ = cs.CoreV1().Pods("kube-system").Create(ctx, recreated, metav1.CreateOptions{})
		_ = oomResizeRunSweep(chk, p.Deps)
		if len(*patches) != 1 || (*patches)[0].name != "coredns-recreate" || !strings.Contains((*patches)[0].patch, `"192Mi"`) {
			t.Fatalf("recreated pod UID should use its own 128Mi origLimit (not old 64Mi 2x cap), got %+v", *patches)
		}
	})
}

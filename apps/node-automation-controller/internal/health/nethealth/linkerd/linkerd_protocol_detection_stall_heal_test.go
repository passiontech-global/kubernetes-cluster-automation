// linkerd_protocol_detection_stall_heal_test.go — table-driven unit
// tests for restartStalePod (OnDelete STS ready-sibling guard,
// EvictPod/DeletePod paths, PDB/quorum/L1-hold RefundGrant, API error
// non-refund, best-effort pod anno patch) and healLinkerdOpaquePorts
// gates (cooldown, maintenance hold/unverifiable, global heal budget).
package linkerd

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

func stsWithStrategy(ns, name string, strategy appsv1.StatefulSetUpdateStrategyType) *appsv1.StatefulSet {
	sts := emptyStatefulSet(ns, name)
	sts.UID = types.UID("uid-sts-" + name)
	sts.Spec.UpdateStrategy.Type = strategy
	sts.Spec.Template.Annotations = map[string]string{
		linkerdOpaquePortsAnno: "5432",
	}
	return sts
}

func ownedPod(ns, name, ownerKind, ownerName string, ownerUID types.UID, ready bool) *corev1.Pod {
	pod := probetest.PodWithPhase(ns, name, corev1.PodRunning, ready, time.Hour)
	pod.UID = types.UID("uid-" + ns + "-" + name)
	pod.Spec.Containers = []corev1.Container{
		{Name: "app", Ports: []corev1.ContainerPort{{ContainerPort: 5432, Protocol: corev1.ProtocolTCP}}},
		{Name: "linkerd-proxy"},
	}
	pod.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "apps/v1",
		Kind:       ownerKind,
		Name:       ownerName,
		UID:        ownerUID,
		Controller: ptr.To(true),
	}}
	return pod
}

func hasEvictionAction(cs *fake.Clientset, ns, name string, wantUID types.UID) bool {
	for _, a := range cs.Actions() {
		ca, ok := a.(ktesting.CreateAction)
		if !ok || a.GetVerb() != "create" || a.GetResource().Resource != "pods" || a.GetSubresource() != "eviction" {
			continue
		}
		ev, ok := ca.GetObject().(*policyv1.Eviction)
		if !ok {
			continue
		}
		if ev.Namespace == ns && ev.Name == name &&
			ev.DeleteOptions != nil && ev.DeleteOptions.Preconditions != nil &&
			ev.DeleteOptions.Preconditions.UID != nil && *ev.DeleteOptions.Preconditions.UID == wantUID {
			return true
		}
	}
	return false
}

func hasPodOpaqueAnnoPatch(cs *fake.Clientset, ns, name string) bool {
	for _, a := range cs.Actions() {
		pa, ok := a.(ktesting.PatchAction)
		if !ok || a.GetVerb() != "patch" || a.GetResource().Resource != "pods" {
			continue
		}
		if pa.GetNamespace() != ns || pa.GetName() != name {
			continue
		}
		var body map[string]any
		if err := json.Unmarshal(pa.GetPatch(), &body); err != nil {
			continue
		}
		meta, _ := body["metadata"].(map[string]any)
		annos, _ := meta["annotations"].(map[string]any)
		if v, ok := annos[linkerdOpaquePortsAnno].(string); ok && v != "" {
			return true
		}
	}
	return false
}

// TestRestartStalePod exercises every branch of restartStalePod (plus
// podOnDeleteStatefulSet, bookkeepRestart, and patchLinkerdPodAnno).
// Non-parallel: mutates global heal.ConfigureBudget and shared metric counters.
func TestRestartStalePod(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	missing := []int{5432}

	type testCase struct {
		name              string
		configureBudget   bool
		setup             func() (cs *fake.Clientset, target *corev1.Pod, pods []corev1.Pod, sctxFn func(*probefw.Deps) context.Context)
		wantPodSurvives   bool
		wantEvictAction   bool
		wantDeleteAction  bool
		wantPodAnnoPatch  bool
		wantCooldownStamp bool
		wantHealDelta     float64
		wantErrDelta      float64
		wantGrantRefunded bool
	}

	cases := []testCase{
		{
			name:            "ondelete_sts_no_ready_sibling",
			configureBudget: true,
			setup: func() (*fake.Clientset, *corev1.Pod, []corev1.Pod, func(*probefw.Deps) context.Context) {
				sts := stsWithStrategy("apps", "db", appsv1.OnDeleteStatefulSetStrategyType)
				target := ownedPod("apps", "db-0", "StatefulSet", "db", sts.UID, true)
				unreadySib := ownedPod("apps", "db-1", "StatefulSet", "db", sts.UID, false)
				cs := fake.NewSimpleClientset(sts, target, unreadySib)
				testutil.EmulateEviction(cs)
				return cs, target, []corev1.Pod{*target, *unreadySib}, nil
			},
			wantPodSurvives:   true,
			wantGrantRefunded: true,
		},
		{
			name:            "ondelete_sts_evict_success",
			configureBudget: true,
			setup: func() (*fake.Clientset, *corev1.Pod, []corev1.Pod, func(*probefw.Deps) context.Context) {
				sts := stsWithStrategy("apps", "db", appsv1.OnDeleteStatefulSetStrategyType)
				target := ownedPod("apps", "db-0", "StatefulSet", "db", sts.UID, true)
				readySib := ownedPod("apps", "db-1", "StatefulSet", "db", sts.UID, true)
				cs := fake.NewSimpleClientset(sts, target, readySib)
				testutil.EmulateEviction(cs)
				return cs, target, []corev1.Pod{*target, *readySib}, nil
			},
			wantPodSurvives:   false,
			wantEvictAction:   true,
			wantPodAnnoPatch:  true,
			wantCooldownStamp: true,
			wantHealDelta:     1,
			wantGrantRefunded: false,
		},
		{
			name:            "ondelete_sts_pdb_429_refunds_grant",
			configureBudget: true,
			setup: func() (*fake.Clientset, *corev1.Pod, []corev1.Pod, func(*probefw.Deps) context.Context) {
				sts := stsWithStrategy("apps", "db", appsv1.OnDeleteStatefulSetStrategyType)
				target := ownedPod("apps", "db-0", "StatefulSet", "db", sts.UID, true)
				readySib := ownedPod("apps", "db-1", "StatefulSet", "db", sts.UID, true)
				cs := fake.NewSimpleClientset(sts, target, readySib)
				cs.PrependReactor("create", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
					if a.GetSubresource() == "eviction" {
						return true, nil, apierrors.NewTooManyRequests("pdb busy", 1)
					}
					return false, nil, nil
				})
				return cs, target, []corev1.Pod{*target, *readySib}, nil
			},
			wantPodSurvives:   true,
			wantEvictAction:   true,
			wantGrantRefunded: true,
		},
		{
			name:            "ondelete_sts_quorum_reserved_refunds_grant",
			configureBudget: true,
			setup: func() (*fake.Clientset, *corev1.Pod, []corev1.Pod, func(*probefw.Deps) context.Context) {
				sts := stsWithStrategy("apps", "db", appsv1.OnDeleteStatefulSetStrategyType)
				target := ownedPod("apps", "db-0", "StatefulSet", "db", sts.UID, true)
				readySib := ownedPod("apps", "db-1", "StatefulSet", "db", sts.UID, true)
				cs := fake.NewSimpleClientset(sts, target, readySib)
				testutil.EmulateEviction(cs)
				return cs, target, []corev1.Pod{*target, *readySib}, func(d *probefw.Deps) context.Context {
					sctx := probetest.SweepCtx(ctx, d)
					if !kube.TryReserveWorkloadDisruption(sctx, readySib) {
						t.Fatal("pre-reserve workload disruption failed")
					}
					return sctx
				}
			},
			wantPodSurvives:   true,
			wantGrantRefunded: true,
		},
		{
			name:            "ondelete_sts_l1_hold_refunds_grant",
			configureBudget: true,
			setup: func() (*fake.Clientset, *corev1.Pod, []corev1.Pod, func(*probefw.Deps) context.Context) {
				sts := stsWithStrategy("apps", "db", appsv1.OnDeleteStatefulSetStrategyType)
				target := ownedPod("apps", "db-0", "StatefulSet", "db", sts.UID, true)
				target.Annotations = map[string]string{
					nodecond.AnnoLastPodHealedAt: now.Add(-time.Minute).UTC().Format(time.RFC3339),
				}
				readySib := ownedPod("apps", "db-1", "StatefulSet", "db", sts.UID, true)
				cs := fake.NewSimpleClientset(sts, target, readySib)
				testutil.EmulateEviction(cs)
				return cs, target, []corev1.Pod{*target, *readySib}, nil
			},
			wantPodSurvives:   true,
			wantGrantRefunded: true,
		},
		{
			name:            "ondelete_sts_evict_api_error_no_refund",
			configureBudget: true,
			setup: func() (*fake.Clientset, *corev1.Pod, []corev1.Pod, func(*probefw.Deps) context.Context) {
				sts := stsWithStrategy("apps", "db", appsv1.OnDeleteStatefulSetStrategyType)
				target := ownedPod("apps", "db-0", "StatefulSet", "db", sts.UID, true)
				readySib := ownedPod("apps", "db-1", "StatefulSet", "db", sts.UID, true)
				cs := fake.NewSimpleClientset(sts, target, readySib)
				cs.PrependReactor("create", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
					if a.GetSubresource() == "eviction" {
						return true, nil, errors.New("apiserver timeout")
					}
					return false, nil, nil
				})
				return cs, target, []corev1.Pod{*target, *readySib}, nil
			},
			wantPodSurvives:   true,
			wantEvictAction:   true,
			wantErrDelta:      1,
			wantGrantRefunded: false,
		},
		{
			name:            "rolling_update_sts_deletes_pod",
			configureBudget: true,
			setup: func() (*fake.Clientset, *corev1.Pod, []corev1.Pod, func(*probefw.Deps) context.Context) {
				sts := stsWithStrategy("apps", "cache", appsv1.RollingUpdateStatefulSetStrategyType)
				target := ownedPod("apps", "cache-0", "StatefulSet", "cache", sts.UID, true)
				cs := fake.NewSimpleClientset(sts, target)
				return cs, target, []corev1.Pod{*target}, nil
			},
			wantPodSurvives:   false,
			wantDeleteAction:  true,
			wantPodAnnoPatch:  true,
			wantCooldownStamp: true,
			wantHealDelta:     1,
			wantGrantRefunded: false,
		},
		{
			name:            "deployment_owner_deletes_pod",
			configureBudget: true,
			setup: func() (*fake.Clientset, *corev1.Pod, []corev1.Pod, func(*probefw.Deps) context.Context) {
				dep := emptyDeployment("apps", "web", nil, nil)
				dep.UID = "uid-dep-web"
				target := ownedPod("apps", "web-abc", "Deployment", "web", dep.UID, true)
				cs := fake.NewSimpleClientset(dep, target)
				return cs, target, []corev1.Pod{*target}, nil
			},
			wantPodSurvives:   false,
			wantDeleteAction:  true,
			wantPodAnnoPatch:  true,
			wantCooldownStamp: true,
			wantHealDelta:     1,
			wantGrantRefunded: false,
		},
		{
			name:            "sts_list_error_falls_back_to_delete",
			configureBudget: true,
			setup: func() (*fake.Clientset, *corev1.Pod, []corev1.Pod, func(*probefw.Deps) context.Context) {
				sts := stsWithStrategy("apps", "db", appsv1.OnDeleteStatefulSetStrategyType)
				target := ownedPod("apps", "db-0", "StatefulSet", "db", sts.UID, true)
				cs := fake.NewSimpleClientset(sts, target)
				cs.PrependReactor("list", "statefulsets", func(ktesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("sts list failed")
				})
				return cs, target, []corev1.Pod{*target}, nil
			},
			wantPodSurvives:   false,
			wantDeleteAction:  true,
			wantPodAnnoPatch:  true,
			wantCooldownStamp: true,
			wantHealDelta:     1,
			wantGrantRefunded: false,
		},
		{
			name:            "delete_pod_quorum_denied_refunds_grant",
			configureBudget: true,
			setup: func() (*fake.Clientset, *corev1.Pod, []corev1.Pod, func(*probefw.Deps) context.Context) {
				dep := emptyDeployment("apps", "web", nil, nil)
				dep.UID = "uid-dep-web"
				target := ownedPod("apps", "web-1", "Deployment", "web", dep.UID, true)
				sib := ownedPod("apps", "web-2", "Deployment", "web", dep.UID, true)
				cs := fake.NewSimpleClientset(dep, target, sib)
				return cs, target, []corev1.Pod{*target, *sib}, func(d *probefw.Deps) context.Context {
					sctx := probetest.SweepCtx(ctx, d)
					if !kube.TryReserveWorkloadDisruption(sctx, sib) {
						t.Fatal("pre-reserve workload disruption failed")
					}
					return sctx
				}
			},
			wantPodSurvives:   true,
			wantGrantRefunded: true,
		},
		{
			name:            "delete_pod_api_error_no_refund",
			configureBudget: true,
			setup: func() (*fake.Clientset, *corev1.Pod, []corev1.Pod, func(*probefw.Deps) context.Context) {
				dep := emptyDeployment("apps", "web", nil, nil)
				dep.UID = "uid-dep-web"
				target := ownedPod("apps", "web-1", "Deployment", "web", dep.UID, true)
				cs := fake.NewSimpleClientset(dep, target)
				cs.PrependReactor("delete", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("rbac denied")
				})
				return cs, target, []corev1.Pod{*target}, nil
			},
			wantPodSurvives:   true,
			wantDeleteAction:  true,
			wantErrDelta:      1,
			wantGrantRefunded: false,
		},
		{
			name:            "pod_anno_patch_not_found_error",
			configureBudget: false,
			setup: func() (*fake.Clientset, *corev1.Pod, []corev1.Pod, func(*probefw.Deps) context.Context) {
				dep := emptyDeployment("apps", "web", nil, nil)
				dep.UID = "uid-dep-web"
				target := ownedPod("apps", "web-1", "Deployment", "web", dep.UID, true)
				cs := fake.NewSimpleClientset(dep, target)
				cs.PrependReactor("patch", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, target.Name)
				})
				return cs, target, []corev1.Pod{*target}, nil
			},
			wantPodSurvives:   false,
			wantDeleteAction:  true,
			wantPodAnnoPatch:  true,
			wantCooldownStamp: true,
			wantHealDelta:     1,
		},
		{
			name:            "pod_anno_patch_rbac_error",
			configureBudget: false,
			setup: func() (*fake.Clientset, *corev1.Pod, []corev1.Pod, func(*probefw.Deps) context.Context) {
				dep := emptyDeployment("apps", "web", nil, nil)
				dep.UID = "uid-dep-web"
				target := ownedPod("apps", "web-1", "Deployment", "web", dep.UID, true)
				cs := fake.NewSimpleClientset(dep, target)
				cs.PrependReactor("patch", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, target.Name, errors.New("rbac"))
				})
				return cs, target, []corev1.Pod{*target}, nil
			},
			wantPodSurvives:   false,
			wantDeleteAction:  true,
			wantPodAnnoPatch:  true,
			wantCooldownStamp: true,
			wantHealDelta:     1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(func() { heal.ConfigureBudget(0, 0) })
			if tc.configureBudget {
				heal.ConfigureBudget(1, time.Hour)
			} else {
				heal.ConfigureBudget(0, 0)
			}

			cs, target, pods, sctxFn := tc.setup()
			p := testProber(cs)
			probetest.FreezeNow(p.Deps, now)
			chk := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p)

			var runCtx context.Context
			if sctxFn != nil {
				runCtx = sctxFn(p.Deps)
			} else {
				runCtx = probetest.SweepCtx(ctx, p.Deps)
			}

			// Consume 1 grant upfront via AllowedV when budget is configured
			// so restartStalePod runs under the exact HealAllowed -> restartStalePod contract.
			if tc.configureBudget {
				proceed, unverifiable := heal.AllowedV(runCtx, logr.Discard(), p.Maintenance,
					p.CS, p.Dyn, nil, "pre-grant", time.Minute, now)
				if !proceed || unverifiable {
					t.Fatalf("pre-grant AllowedV failed: proceed=%v unverifiable=%v", proceed, unverifiable)
				}
			}

			ck := probefw.SelfHealKey(CheckNameLinkerdOpaqueStall, kube.PodControllerKey(target))
			errBefore := probetest.CounterSnapshot(t, p.Name)
			healBefore := promtestutil.ToFloat64(metrics.ControlPlanePodHealsTotal.WithLabelValues(CheckNameLinkerdOpaqueStall))

			chk.restartStalePod(runCtx, logr.Discard(), target, missing, now, pods, ck)

			probetest.AssertCounterDelta(t, p.Name, errBefore, tc.wantErrDelta)
			healDelta := promtestutil.ToFloat64(metrics.ControlPlanePodHealsTotal.WithLabelValues(CheckNameLinkerdOpaqueStall)) - healBefore
			if healDelta != tc.wantHealDelta {
				t.Fatalf("ControlPlanePodHealsTotal delta = %v, want %v", healDelta, tc.wantHealDelta)
			}

			_, podErr := cs.CoreV1().Pods(target.Namespace).Get(ctx, target.Name, metav1.GetOptions{})
			if tc.wantPodSurvives && podErr != nil {
				t.Fatalf("expected pod %s/%s to survive, got err=%v", target.Namespace, target.Name, podErr)
			}
			if !tc.wantPodSurvives && !apierrors.IsNotFound(podErr) {
				t.Fatalf("expected pod %s/%s to be removed, got err=%v", target.Namespace, target.Name, podErr)
			}

			if tc.wantEvictAction && !hasEvictionAction(cs, target.Namespace, target.Name, target.UID) {
				t.Fatalf("expected Eviction create action with UIDDeleteOptions(%s)", target.UID)
			}
			if !tc.wantEvictAction && hasEvictionAction(cs, target.Namespace, target.Name, target.UID) {
				t.Fatalf("unexpected Eviction create action")
			}

			hasDelete := false
			for _, a := range cs.Actions() {
				if a.GetVerb() == "delete" && a.GetResource().Resource == "pods" && a.GetSubresource() == "" {
					hasDelete = true
				}
			}
			if hasDelete != tc.wantDeleteAction {
				t.Fatalf("pod delete action = %v, want %v", hasDelete, tc.wantDeleteAction)
			}

			if tc.wantPodAnnoPatch != hasPodOpaqueAnnoPatch(cs, target.Namespace, target.Name) {
				t.Fatalf("pod opaque-ports patch = %v, want %v", !tc.wantPodAnnoPatch, tc.wantPodAnnoPatch)
			}

			_, stamped := chk.Heals.Last(ck)
			if stamped != tc.wantCooldownStamp {
				t.Fatalf("Heals.Last(%q) stamped = %v, want %v", ck, stamped, tc.wantCooldownStamp)
			}

			if tc.configureBudget {
				postProceed, _ := heal.AllowedV(runCtx, logr.Discard(), p.Maintenance,
					p.CS, p.Dyn, nil, "post-check", time.Minute, now.Add(time.Second))
				if postProceed != tc.wantGrantRefunded {
					t.Fatalf("post-check AllowedV = %v (budget refunded), want %v", postProceed, tc.wantGrantRefunded)
				}
			}
		})
	}
}

// TestHealLinkerdOpaquePortsGates verifies the cooldown, maintenance hold,
// maintenance unverifiable, and exhausted-budget gates in healLinkerdOpaquePorts.
// Non-parallel: mutates global heal.ConfigureBudget and shared error counters.
func TestHealLinkerdOpaquePortsGates(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	missing := []int{5432}

	cases := []struct {
		name         string
		setup        func(t *testing.T) (*probetest.Prober, *linkerdProtocolDetectionStallCheck, *corev1.Pod, []corev1.Pod, *fake.Clientset)
		wantErrDelta float64
	}{
		{
			name: "cooldown_gate_skips_restart",
			setup: func(t *testing.T) (*probetest.Prober, *linkerdProtocolDetectionStallCheck, *corev1.Pod, []corev1.Pod, *fake.Clientset) {
				sts := stsWithStrategy("apps", "cache", appsv1.RollingUpdateStatefulSetStrategyType)
				pod := ownedPod("apps", "cache-0", "StatefulSet", "cache", sts.UID, true)
				cs := fake.NewSimpleClientset(sts, pod)
				p := testProber(cs)
				probetest.FreezeNow(p.Deps, now)
				chk := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p)
				ck := probefw.SelfHealKey(CheckNameLinkerdOpaqueStall, kube.PodControllerKey(pod))
				chk.Heals.Stamp(ck, now.Add(-5*time.Minute))
				return p, chk, pod, []corev1.Pod{*pod}, cs
			},
		},
		{
			name: "maintenance_hold_skips_restart",
			setup: func(t *testing.T) (*probetest.Prober, *linkerdProtocolDetectionStallCheck, *corev1.Pod, []corev1.Pod, *fake.Clientset) {
				sts := stsWithStrategy("apps", "cache", appsv1.RollingUpdateStatefulSetStrategyType)
				pod := ownedPod("apps", "cache-0", "StatefulSet", "cache", sts.UID, true)
				kured := emptyDaemonSet("kube-system", "kured")
				kured.Annotations = map[string]string{"weave.works/kured-node-lock": `{"nodeID":"w1"}`}
				cs := fake.NewSimpleClientset(sts, pod, kured)
				p := testProber(cs)
				probetest.FreezeNow(p.Deps, now)
				chk := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p)
				return p, chk, pod, []corev1.Pod{*pod}, cs
			},
		},
		{
			name: "maintenance_unverifiable_inc_error",
			setup: func(t *testing.T) (*probetest.Prober, *linkerdProtocolDetectionStallCheck, *corev1.Pod, []corev1.Pod, *fake.Clientset) {
				sts := stsWithStrategy("apps", "cache", appsv1.RollingUpdateStatefulSetStrategyType)
				pod := ownedPod("apps", "cache-0", "StatefulSet", "cache", sts.UID, true)
				cs := fake.NewSimpleClientset(sts, pod)
				p := testProber(cs)
				p.Dyn = nil // triggers unverifiable maintenance mutex
				probetest.FreezeNow(p.Deps, now)
				chk := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p)
				return p, chk, pod, []corev1.Pod{*pod}, cs
			},
			wantErrDelta: 1,
		},
		{
			name: "budget_exhausted_skips_restart",
			setup: func(t *testing.T) (*probetest.Prober, *linkerdProtocolDetectionStallCheck, *corev1.Pod, []corev1.Pod, *fake.Clientset) {
				t.Cleanup(func() { heal.ConfigureBudget(0, 0) })
				heal.ConfigureBudget(1, time.Hour)
				sts := stsWithStrategy("apps", "cache", appsv1.RollingUpdateStatefulSetStrategyType)
				pod := ownedPod("apps", "cache-0", "StatefulSet", "cache", sts.UID, true)
				cs := fake.NewSimpleClientset(sts, pod)
				p := testProber(cs)
				probetest.FreezeNow(p.Deps, now)
				chk := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p)
				// Spend the sole grant upfront.
				if ok, _ := heal.AllowedV(ctx, logr.Discard(), p.Maintenance, p.CS, p.Dyn, nil, "spent", time.Minute, now); !ok {
					t.Fatal("failed to spend initial budget grant")
				}
				return p, chk, pod, []corev1.Pod{*pod}, cs
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, chk, pod, pods, cs := tc.setup(t)
			errBefore := probetest.CounterSnapshot(t, p.Name)
			rep := &probefw.SweepReport{}
			driftNow := map[string][]string{}

			chk.healLinkerdOpaquePorts(probetest.SweepCtx(ctx, p.Deps), logr.Discard(),
				pod, missing, now, pods, rep, driftNow)

			probetest.AssertCounterDelta(t, p.Name, errBefore, tc.wantErrDelta)
			if _, err := cs.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
				t.Fatalf("expected pod to survive gated heal, got err=%v", err)
			}
			for _, a := range cs.Actions() {
				if a.GetResource().Resource == "pods" && (a.GetVerb() == "delete" || a.GetSubresource() == "eviction") {
					t.Fatalf("unexpected pod mutation action: %+v", a)
				}
			}
		})
	}
}

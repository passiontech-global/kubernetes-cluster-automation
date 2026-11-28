// pvc_auto_expand_test.go — coverage for pvc-auto-expand: detection-only
// default, env/annotation opt-in, explicit opt-out, +25%/min +1Gi sizing,
// 2x cap & custom max annotation, allowVolumeExpansion=false skip, active
// resize condition skip, 6h cooldown, runaway fill-rate pause, FluxPatchGate,
// and maintenance hold.
package pvc

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func pvcAutoExpandProber(cs *fake.Clientset) *probetest.Prober {
	return probetest.NewCheckProber(cs, probetest.OpDyn(), NewPVCAutoExpandCheck)
}

func makeExpandableSC(name string, allow bool) *storagev1.StorageClass {
	return &storagev1.StorageClass{
		ObjectMeta:           metav1.ObjectMeta{Name: name},
		Provisioner:          "csi.example.com",
		AllowVolumeExpansion: ptr.To(allow),
	}
}

func makeBoundPVC(ns, name, scName, reqSize, capSize string, annos map[string]string) *corev1.PersistentVolumeClaim {
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   ns,
			Name:        name,
			UID:         types.UID("uid-" + ns + "-" + name),
			Annotations: annos,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			StorageClassName: ptr.To(scName),
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse(reqSize),
				},
			},
		},
		Status: corev1.PersistentVolumeClaimStatus{
			Phase: corev1.ClaimBound,
		},
	}
	if capSize != "" {
		pvc.Status.Capacity = corev1.ResourceList{
			corev1.ResourceStorage: resource.MustParse(capSize),
		}
	}
	return pvc
}

func mockPromLowFreeServer(t *testing.T, samples ...[3]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var parts []string
		for _, s := range samples {
			parts = append(parts, fmt.Sprintf(
				`{"metric":{"namespace":%q,"persistentvolumeclaim":%q},"value":[1,%q]}`,
				s[0], s[1], s[2]))
		}
		_, _ = fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[%s]}}`,
			strings.Join(parts, ","))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func pvcLowFreeSeries(t *testing.T, ns, pvc string) (float64, bool) {
	t.Helper()
	return testutil.GaugeSeriesValue(t, "node_automation_pvc_low_free_space",
		map[string]string{"namespace": ns, "pvc": pvc})
}

func pvcReqStorage(pvc *corev1.PersistentVolumeClaim) resource.Quantity {
	return pvc.Spec.Resources.Requests[corev1.ResourceStorage]
}

func runAutoExpandSweep(chk probefw.Check, d *probefw.Deps) probefw.Result {
	sctx := probetest.SweepCtx(ctx, d)
	res := chk.Run(sctx)
	probetest.VerifySweep(sctx)
	return res
}

func TestPVCAutoExpandPromUnavailableNoOp(t *testing.T) {
	pvcLowFreeSpaceGauge.Reset()
	cs := fake.NewSimpleClientset(makeBoundPVC("apps", "data-0", "fast-csi", "10Gi", "10Gi", nil))
	p := pvcAutoExpandProber(cs)
	chk := probetest.MustCheck[*pvcAutoExpandCheck](t, p)

	res := runAutoExpandSweep(chk, p.Deps)
	if !res.Pass || res.Infra != nil {
		t.Fatalf("prom unavailable must gracefully pass, got %+v", res)
	}
}

func TestPVCAutoExpandDetectionOnlyDefault(t *testing.T) {
	pvcLowFreeSpaceGauge.Reset()
	base := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	sc := makeExpandableSC("fast-csi", true)
	pvc := makeBoundPVC("apps", "data-0", "fast-csi", "10Gi", "10Gi", nil)
	cs := fake.NewSimpleClientset(sc, pvc)
	srv := mockPromLowFreeServer(t, [3]string{"apps", "data-0", "0.10"})

	p := pvcAutoExpandProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	chk := probetest.MustCheck[*pvcAutoExpandCheck](t, p)

	// Sweep 1: arms first-seen ledger (under 10m window -> passes).
	probetest.FreezeNow(p.Deps, base)
	if res := runAutoExpandSweep(chk, p.Deps); !res.Pass {
		t.Fatalf("first observation must arm, not fail: %+v", res)
	}

	// Sweep 2 (+11m): breaches >=10m -> fails, emits Warning Event, does NOT expand by default.
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	res := runAutoExpandSweep(chk, p.Deps)
	if res.Pass {
		t.Fatalf("sustained <15%% free must fail: %+v", res)
	}
	if !strings.Contains(res.Why, "apps/data-0") {
		t.Fatalf("Why missing apps/data-0: %q", res.Why)
	}
	if v, ok := pvcLowFreeSeries(t, "apps", "data-0"); !ok || v != 1 {
		t.Fatalf("gauge = %v,%v want 1,true", v, ok)
	}

	evs, err := cs.EventsV1().Events("apps").List(ctx, metav1.ListOptions{})
	if err != nil || len(evs.Items) != 1 || evs.Items[0].Reason != pvcLowFreeEventReason {
		t.Fatalf("expected 1 PVCLowFreeSpace event, got err=%v items=%+v", err, evs.Items)
	}

	got, err := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, "data-0", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if req := pvcReqStorage(got); req.String() != "10Gi" {
		t.Fatalf("detection-only default mutated PVC size to %s", req.String())
	}
}

func TestPVCAutoExpandEnvAndAnnotationOptInOut(t *testing.T) {
	base := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

	t.Run("env opt-in expands +25% and min +1Gi and respects opt-out false", func(t *testing.T) {
		pvcLowFreeSpaceGauge.Reset()
		t.Setenv("NODE_AUTOMATION_PVC_AUTO_EXPAND_HEAL_ENABLED", "true")

		sc := makeExpandableSC("fast-csi", true)
		// 10Gi -> +25% = 12800Mi
		pvcBig := makeBoundPVC("apps", "big", "fast-csi", "10Gi", "10Gi", nil)
		// 2Gi -> +25% = 0.5Gi < min +1Gi -> 3Gi
		pvcSmall := makeBoundPVC("apps", "small", "fast-csi", "2Gi", "2Gi", nil)
		// Explicit opt-out "false" overrides env=true
		pvcOptOut := makeBoundPVC("apps", "optout", "fast-csi", "10Gi", "10Gi", map[string]string{
			annoPVCAutoExpand: "false",
		})

		cs := fake.NewSimpleClientset(sc, pvcBig, pvcSmall, pvcOptOut)
		srv := mockPromLowFreeServer(t,
			[3]string{"apps", "big", "0.08"},
			[3]string{"apps", "small", "0.05"},
			[3]string{"apps", "optout", "0.05"},
		)
		p := pvcAutoExpandProber(cs)
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		chk := probetest.MustCheck[*pvcAutoExpandCheck](t, p)

		probetest.FreezeNow(p.Deps, base)
		_ = runAutoExpandSweep(chk, p.Deps)
		probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
		_ = runAutoExpandSweep(chk, p.Deps)

		bigGot, _ := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, "big", metav1.GetOptions{})
		if got := bigGot.Spec.Resources.Requests[corev1.ResourceStorage]; got.Value() != 12800*pvcAutoExpandOneMiB {
			t.Fatalf("big PVC size = %s (%d), want 12800Mi", got.String(), got.Value())
		}
		if bigGot.Annotations[annoPVCAutoExpandBaseline] != "10Gi" {
			t.Fatalf("baseline annotation = %q, want 10Gi", bigGot.Annotations[annoPVCAutoExpandBaseline])
		}

		smallGot, _ := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, "small", metav1.GetOptions{})
		if got := smallGot.Spec.Resources.Requests[corev1.ResourceStorage]; got.Value() != 3*pvcAutoExpandOneGiB {
			t.Fatalf("small PVC size = %s (%d), want 3Gi", got.String(), got.Value())
		}

		optOutGot, _ := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, "optout", metav1.GetOptions{})
		if req := pvcReqStorage(optOutGot); req.String() != "10Gi" {
			t.Fatalf("opted-out PVC size = %s, want 10Gi", req.String())
		}
	})

	t.Run("annotation opt-in works when env is false", func(t *testing.T) {
		pvcLowFreeSpaceGauge.Reset()
		t.Setenv("NODE_AUTOMATION_PVC_AUTO_EXPAND_HEAL_ENABLED", "false")

		sc := makeExpandableSC("fast-csi", true)
		pvcOptIn := makeBoundPVC("apps", "optin", "fast-csi", "4Gi", "4Gi", map[string]string{
			annoPVCAutoExpand: "true",
		})
		cs := fake.NewSimpleClientset(sc, pvcOptIn)
		srv := mockPromLowFreeServer(t, [3]string{"apps", "optin", "0.10"})

		p := pvcAutoExpandProber(cs)
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		chk := probetest.MustCheck[*pvcAutoExpandCheck](t, p)

		probetest.FreezeNow(p.Deps, base)
		_ = runAutoExpandSweep(chk, p.Deps)
		probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
		_ = runAutoExpandSweep(chk, p.Deps)

		got, _ := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, "optin", metav1.GetOptions{})
		if req := got.Spec.Resources.Requests[corev1.ResourceStorage]; req.Value() != 5*pvcAutoExpandOneGiB {
			t.Fatalf("annotated opt-in PVC size = %s, want 5Gi", req.String())
		}
	})
}

func TestPVCAutoExpandSafetyGuardsAndCaps(t *testing.T) {
	base := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

	t.Run("skips non-expandable SC, active resize conditions, req > cap", func(t *testing.T) {
		pvcLowFreeSpaceGauge.Reset()
		t.Setenv("NODE_AUTOMATION_PVC_AUTO_EXPAND_HEAL_ENABLED", "true")

		scNo := makeExpandableSC("no-expand", false)
		scYes := makeExpandableSC("yes-expand", true)

		pvcNoSC := makeBoundPVC("apps", "nosc", "no-expand", "10Gi", "10Gi", nil)
		pvcResizing := makeBoundPVC("apps", "resizing", "yes-expand", "10Gi", "10Gi", nil)
		pvcResizing.Status.Conditions = []corev1.PersistentVolumeClaimCondition{{
			Type:   corev1.PersistentVolumeClaimResizing,
			Status: corev1.ConditionTrue,
		}}
		pvcReqGT := makeBoundPVC("apps", "reqgt", "yes-expand", "12Gi", "10Gi", nil)

		cs := fake.NewSimpleClientset(scNo, scYes, pvcNoSC, pvcResizing, pvcReqGT)
		srv := mockPromLowFreeServer(t,
			[3]string{"apps", "nosc", "0.05"},
			[3]string{"apps", "resizing", "0.05"},
			[3]string{"apps", "reqgt", "0.05"},
		)
		p := pvcAutoExpandProber(cs)
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		chk := probetest.MustCheck[*pvcAutoExpandCheck](t, p)

		probetest.FreezeNow(p.Deps, base)
		_ = runAutoExpandSweep(chk, p.Deps)
		probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
		_ = runAutoExpandSweep(chk, p.Deps)

		for _, tc := range []struct{ name, want string }{
			{"nosc", "10Gi"},
			{"resizing", "10Gi"},
			{"reqgt", "12Gi"},
		} {
			got, _ := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, tc.name, metav1.GetOptions{})
			if req := pvcReqStorage(got); req.String() != tc.want {
				t.Fatalf("%s expanded unexpectedly: %s", tc.name, req.String())
			}
		}
	})

	t.Run("2x baseline cap and custom max annotation", func(t *testing.T) {
		pvcLowFreeSpaceGauge.Reset()
		t.Setenv("NODE_AUTOMATION_PVC_AUTO_EXPAND_HEAL_ENABLED", "true")

		sc := makeExpandableSC("fast-csi", true)
		// Already at 18Gi with baseline 10Gi -> 2x cap is 20Gi (clamped from 22.5Gi)
		pvc2x := makeBoundPVC("apps", "cap2x", "fast-csi", "18Gi", "18Gi", map[string]string{
			annoPVCAutoExpandBaseline: "10Gi",
		})
		// Already at 20Gi with baseline 10Gi -> capped, no expansion, emits PVCAutoExpandCapReached
		pvcAtCap := makeBoundPVC("apps", "atcap", "fast-csi", "20Gi", "20Gi", map[string]string{
			annoPVCAutoExpandBaseline: "10Gi",
		})
		// Custom max 12Gi on 10Gi -> clamped to 12Gi
		pvcCustom := makeBoundPVC("apps", "custom", "fast-csi", "10Gi", "10Gi", map[string]string{
			annoPVCAutoExpandMax: "12Gi",
		})

		cs := fake.NewSimpleClientset(sc, pvc2x, pvcAtCap, pvcCustom)
		srv := mockPromLowFreeServer(t,
			[3]string{"apps", "cap2x", "0.05"},
			[3]string{"apps", "atcap", "0.05"},
			[3]string{"apps", "custom", "0.05"},
		)
		p := pvcAutoExpandProber(cs)
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		chk := probetest.MustCheck[*pvcAutoExpandCheck](t, p)

		probetest.FreezeNow(p.Deps, base)
		_ = runAutoExpandSweep(chk, p.Deps)
		probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
		_ = runAutoExpandSweep(chk, p.Deps)

		got2x, _ := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, "cap2x", metav1.GetOptions{})
		if req := pvcReqStorage(got2x); req.Value() != 20*pvcAutoExpandOneGiB {
			t.Fatalf("cap2x = %s, want 20Gi", req.String())
		}
		gotAtCap, _ := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, "atcap", metav1.GetOptions{})
		if req := pvcReqStorage(gotAtCap); req.String() != "20Gi" {
			t.Fatalf("atcap = %s, want 20Gi", req.String())
		}
		gotCustom, _ := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, "custom", metav1.GetOptions{})
		if req := pvcReqStorage(gotCustom); req.Value() != 12*pvcAutoExpandOneGiB {
			t.Fatalf("custom = %s, want 12Gi", req.String())
		}
	})
}

func TestPVCAutoExpandCooldownRunawayFluxAndHold(t *testing.T) {
	base := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

	t.Run("6h cooldown and runaway fill-rate pause", func(t *testing.T) {
		pvcLowFreeSpaceGauge.Reset()
		t.Setenv("NODE_AUTOMATION_PVC_AUTO_EXPAND_HEAL_ENABLED", "true")

		sc := makeExpandableSC("fast-csi", true)
		pvc := makeBoundPVC("apps", "runaway", "fast-csi", "10Gi", "10Gi", nil)
		cs := fake.NewSimpleClientset(sc, pvc)
		srv := mockPromLowFreeServer(t, [3]string{"apps", "runaway", "0.05"})

		p := pvcAutoExpandProber(cs)
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		chk := probetest.MustCheck[*pvcAutoExpandCheck](t, p)

		// Arm & first expansion at +11m (10Gi -> 12800Mi)
		probetest.FreezeNow(p.Deps, base)
		_ = runAutoExpandSweep(chk, p.Deps)
		probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
		_ = runAutoExpandSweep(chk, p.Deps)

		// Simulate storage backend finishing resize so capacity == request
		cur, _ := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, "runaway", metav1.GetOptions{})
		if req := pvcReqStorage(cur); req.Value() != 12800*pvcAutoExpandOneMiB {
			t.Fatalf("expand #1 failed: %s", req.String())
		}
		cur.Status.Capacity = corev1.ResourceList{
			corev1.ResourceStorage: cur.Spec.Resources.Requests[corev1.ResourceStorage],
		}
		_, _ = cs.CoreV1().PersistentVolumeClaims("apps").UpdateStatus(ctx, cur, metav1.UpdateOptions{})

		// +3h: still inside 6h cooldown -> no expansion
		probetest.FreezeNow(p.Deps, base.Add(3*time.Hour))
		_ = runAutoExpandSweep(chk, p.Deps)
		after3h, _ := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, "runaway", metav1.GetOptions{})
		if req := pvcReqStorage(after3h); req.Value() != 12800*pvcAutoExpandOneMiB {
			t.Fatalf("expanded inside 6h cooldown: %s", req.String())
		}

		// +6h30m: cooldown expired -> expand #2 (12800Mi -> 16000Mi)
		probetest.FreezeNow(p.Deps, base.Add(6*time.Hour+30*time.Minute))
		_ = runAutoExpandSweep(chk, p.Deps)
		after6h, _ := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, "runaway", metav1.GetOptions{})
		if req := pvcReqStorage(after6h); req.Value() != 16000*pvcAutoExpandOneMiB {
			t.Fatalf("expand #2 after 6h cooldown = %s, want 16000Mi", req.String())
		}
		after6h.Status.Capacity = corev1.ResourceList{
			corev1.ResourceStorage: after6h.Spec.Resources.Requests[corev1.ResourceStorage],
		}
		_, _ = cs.CoreV1().PersistentVolumeClaims("apps").UpdateStatus(ctx, after6h, metav1.UpdateOptions{})

		// +13h (inside 24h runaway window, 2 expansions already happened): paused + emits runaway Warning Event
		probetest.FreezeNow(p.Deps, base.Add(13*time.Hour))
		_ = runAutoExpandSweep(chk, p.Deps)
		after13h, _ := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, "runaway", metav1.GetOptions{})
		if req := pvcReqStorage(after13h); req.Value() != 16000*pvcAutoExpandOneMiB {
			t.Fatalf("runaway pause did not halt expansion #3: %s", req.String())
		}
		evs, _ := cs.EventsV1().Events("apps").List(ctx, metav1.ListOptions{})
		foundRunaway := false
		for _, ev := range evs.Items {
			if ev.Reason == pvcAutoExpandRunawayReason {
				foundRunaway = true
				break
			}
		}
		if !foundRunaway {
			t.Fatalf("expected %s Warning Event on runaway pause, got %+v", pvcAutoExpandRunawayReason, evs.Items)
		}
	})

	t.Run("FluxPatchGate and maintenance hold block expansion and refund budget", func(t *testing.T) {
		pvcLowFreeSpaceGauge.Reset()
		t.Setenv("NODE_AUTOMATION_PVC_AUTO_EXPAND_HEAL_ENABLED", "true")

		heal.ConfigureFluxConflictLoop(3, 30*time.Minute)
		t.Cleanup(func() { heal.ConfigureFluxConflictLoop(0, 0) })
		heal.ConfigureBudget(1, time.Hour)
		t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

		sc := makeExpandableSC("fast-csi", true)
		fluxPVC := makeBoundPVC("apps", "flux-pvc", "fast-csi", "10Gi", "10Gi", nil)
		fluxPVC.ManagedFields = []metav1.ManagedFieldsEntry{{Manager: "helm-controller"}}
		// Pre-record 2 Flux hits so the 3rd triggers FluxPatchGate denial.
		heal.FluxPatchGate("pvc", fluxPVC, CheckNamePVCAutoExpand+":apps/flux-pvc", base)
		heal.FluxPatchGate("pvc", fluxPVC, CheckNamePVCAutoExpand+":apps/flux-pvc", base)

		freePVC := makeBoundPVC("apps", "free-pvc", "fast-csi", "10Gi", "10Gi", nil)

		cs := fake.NewSimpleClientset(sc, fluxPVC, freePVC)
		srv := mockPromLowFreeServer(t,
			[3]string{"apps", "flux-pvc", "0.05"},
			[3]string{"apps", "free-pvc", "0.05"},
		)
		p := pvcAutoExpandProber(cs)
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		chk := probetest.MustCheck[*pvcAutoExpandCheck](t, p)

		probetest.FreezeNow(p.Deps, base)
		_ = runAutoExpandSweep(chk, p.Deps)
		probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
		_ = runAutoExpandSweep(chk, p.Deps)

		gotFlux, _ := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, "flux-pvc", metav1.GetOptions{})
		if req := pvcReqStorage(gotFlux); req.String() != "10Gi" {
			t.Fatalf("FluxPatchGate failed to block flux-pvc expansion: %s", req.String())
		}
		gotFree, _ := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, "free-pvc", metav1.GetOptions{})
		if req := pvcReqStorage(gotFree); req.Value() != 12800*pvcAutoExpandOneMiB {
			t.Fatalf("FluxPatchGate denial did not refund budget for free-pvc: %s", req.String())
		}

		// Maintenance hold blocks expansion.
		pvcHold := makeBoundPVC("apps", "hold-pvc", "fast-csi", "10Gi", "10Gi", nil)
		csHold := fake.NewSimpleClientset(
			[]runtime.Object{
				sc,
				pvcHold,
				&appsv1.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:   "kube-system",
						Name:        "kured",
						Annotations: map[string]string{"weave.works/kured-node-lock": "cluster-upgrade"},
					},
				},
			}...,
		)
		srvHold := mockPromLowFreeServer(t, [3]string{"apps", "hold-pvc", "0.05"})
		pHold := pvcAutoExpandProber(csHold)
		pHold.Cfg.HTTPContent.URL = srvHold.URL
		pHold.HTTPClient = srvHold.Client()
		chkHold := probetest.MustCheck[*pvcAutoExpandCheck](t, pHold)

		probetest.FreezeNow(pHold.Deps, base)
		_ = runAutoExpandSweep(chkHold, pHold.Deps)
		probetest.FreezeNow(pHold.Deps, base.Add(11*time.Minute))
		_ = runAutoExpandSweep(chkHold, pHold.Deps)

		gotHold, _ := csHold.CoreV1().PersistentVolumeClaims("apps").Get(ctx, "hold-pvc", metav1.GetOptions{})
		if req := pvcReqStorage(gotHold); req.String() != "10Gi" {
			t.Fatalf("maintenance hold failed to block expansion: %s", req.String())
		}
	})

	t.Run("static empty storageClassName skips default SC, cap never shrinks below capacity, and deleted PVC skips", func(t *testing.T) {
		pvcLowFreeSpaceGauge.Reset()
		t.Setenv("NODE_AUTOMATION_PVC_AUTO_EXPAND_HEAL_ENABLED", "true")

		defaultSC := makeExpandableSC("default-expand", true)
		defaultSC.Annotations = map[string]string{"storageclass.kubernetes.io/is-default-class": "true"}

		// Explicit storageClassName="" means static binding (NO StorageClass) -> must NOT fall back to defaultSC.
		staticPVC := makeBoundPVC("apps", "static-pvc", "", "10Gi", "10Gi", nil)
		// curReq (10Gi) < curCap (15Gi) with max 12Gi -> must NOT shrink to 12Gi!
		shrinkCapPVC := makeBoundPVC("apps", "shrink-cap", "default-expand", "10Gi", "15Gi", map[string]string{
			annoPVCAutoExpandMax: "12Gi",
		})
		// curReq (10Gi) < curCap (15Gi) with max 30Gi -> expands from 15Gi (+25% = 18.75Gi = 19200Mi).
		growFromCapPVC := makeBoundPVC("apps", "grow-cap", "default-expand", "10Gi", "15Gi", map[string]string{
			annoPVCAutoExpandMax: "30Gi",
		})

		cs := fake.NewSimpleClientset(defaultSC, staticPVC, shrinkCapPVC, growFromCapPVC)
		srv := mockPromLowFreeServer(t,
			[3]string{"apps", "static-pvc", "0.05"},
			[3]string{"apps", "shrink-cap", "0.05"},
			[3]string{"apps", "grow-cap", "0.05"},
			[3]string{"apps", "deleted-stale", "0.05"},
		)
		p := pvcAutoExpandProber(cs)
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		chk := probetest.MustCheck[*pvcAutoExpandCheck](t, p)

		probetest.FreezeNow(p.Deps, base)
		_ = runAutoExpandSweep(chk, p.Deps)
		probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
		res := runAutoExpandSweep(chk, p.Deps)

		if strings.Contains(res.Why, "deleted-stale") {
			t.Fatalf("stale PromQL PVC without k8s object should not alert: %q", res.Why)
		}
		gotStatic, _ := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, "static-pvc", metav1.GetOptions{})
		if req := pvcReqStorage(gotStatic); req.String() != "10Gi" {
			t.Fatalf("static storageClassName=\"\" expanded via default SC: %s", req.String())
		}
		gotShrink, _ := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, "shrink-cap", metav1.GetOptions{})
		if req := pvcReqStorage(gotShrink); req.String() != "10Gi" {
			t.Fatalf("shrink-cap mutated below capacity: %s", req.String())
		}
		gotGrow, _ := cs.CoreV1().PersistentVolumeClaims("apps").Get(ctx, "grow-cap", metav1.GetOptions{})
		if req := pvcReqStorage(gotGrow); req.Value() != 19200*pvcAutoExpandOneMiB {
			t.Fatalf("grow-cap = %s (%d), want 19200Mi", req.String(), req.Value())
		}
	})
}

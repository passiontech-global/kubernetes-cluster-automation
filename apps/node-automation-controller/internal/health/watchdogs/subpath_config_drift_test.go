// subpath_config_drift_test.go — coverage for the pure helpers of
// the subpath-config-drift check: the content-hash signature
// (ConfigMap AND Secret keys, items remapping, absent keys), the
// fresh-pod StartTime exemption, the system/quorum/opt-out
// exclusions, and the FluxPatchGate kind mapping.
package watchdogs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// driftPodSpec builds a pod spec mounting one ConfigMap key and one
// Secret key via subPath.
func driftPodSpec(cmName, cmKey, secName, secKey string) *corev1.PodSpec {
	return &corev1.PodSpec{
		Volumes: []corev1.Volume{
			{
				Name: "cfg",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: cmName},
					},
				},
			},
			{
				Name: "sec",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: secName,
					},
				},
			},
		},
		Containers: []corev1.Container{{
			Name: "app",
			VolumeMounts: []corev1.VolumeMount{
				{Name: "cfg", MountPath: "/etc/app", SubPath: cmKey},
				{Name: "sec", MountPath: "/etc/sec", SubPath: secKey},
			},
		}},
	}
}

func TestSubPathContentHashDetectsKeyContentDrift(t *testing.T) {
	p := &subpathConfigDriftCheck{}
	spec := driftPodSpec("app-config", "flags.yaml",
		"app-secret", "token")
	cmData := map[string]map[string]string{
		"apps/app-config": {"flags.yaml": "v1"},
	}
	secData := map[string]map[string][]byte{
		"apps/app-secret": {"token": []byte("abc")},
	}
	h1 := p.subPathContentHash(spec, "apps", cmData, secData)
	if h1 == "" {
		t.Fatal("hash empty for a spec with subPath mounts")
	}
	// Same content → same hash (stable signature).
	if h2 := p.subPathContentHash(spec, "apps", cmData, secData); h2 != h1 {
		t.Fatal("hash not deterministic")
	}
	// ConfigMap content change → different hash.
	cmData["apps/app-config"]["flags.yaml"] = "v2"
	if h3 := p.subPathContentHash(spec, "apps", cmData, secData); h3 == h1 {
		t.Fatal("ConfigMap content drift not detected")
	}
	// Secret content change → different hash.
	cmData["apps/app-config"]["flags.yaml"] = "v1"
	secData["apps/app-secret"]["token"] = []byte("xyz")
	if h4 := p.subPathContentHash(spec, "apps", cmData, secData); h4 == h1 {
		t.Fatal("Secret content drift not detected")
	}
	// A deleted key contributes "<absent>" — drift, not silence.
	delete(secData["apps/app-secret"], "token")
	if h5 := p.subPathContentHash(spec, "apps", cmData, secData); h5 == h1 {
		t.Fatal("deleted Secret key not detected as drift")
	}
	// No subPath mounts → empty signature (out of scope).
	plain := &corev1.PodSpec{Containers: []corev1.Container{{
		VolumeMounts: []corev1.VolumeMount{{Name: "cfg", MountPath: "/etc"}},
	}}}
	if h := p.subPathContentHash(plain, "apps", cmData, secData); h != "" {
		t.Fatal("non-subPath mount produced a signature")
	}
}

// The opt-out annotation is read through the sweep overlay. An opt-out
// stamped earlier in the SAME sweep (cooldown/sibling check) must hide
// the workload from this check even though the snapshot's own
// annotation map is still empty — the frozen copy must not win.
func TestSubPathRunHonorsOverlayedOptOut(t *testing.T) {
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "app",
		},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "app"}},
			Spec: corev1.PodSpec{
				Volumes: []corev1.Volume{{
					Name: "cfg",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "app-config"},
						},
					},
				}},
				Containers: []corev1.Container{{
					Name:         "app",
					VolumeMounts: []corev1.VolumeMount{{Name: "cfg", MountPath: "/etc/app", SubPath: "flags.yaml"}},
				}},
			},
		}},
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "app-config"},
		Data:       map[string]string{"flags.yaml": "v1"},
	}
	cs := fake.NewSimpleClientset(dep, cm)
	var patches int
	cs.PrependReactor("patch", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			patches++
			return false, nil, nil
		})
	d := probetest.NewDeps(cs, probetest.OpDyn())
	now := time.Now()
	probetest.FreezeNow(d, now)
	chk := &subpathConfigDriftCheck{Deps: d,
		hashes: map[string]string{}, driftSince: map[string]time.Time{}}
	sweepCtx := probefw.WithSweepSnapshot(ctx)

	// First sweep seeds the subPath hash baseline.
	chk.Run(sweepCtx)
	if len(chk.hashes) != 1 {
		t.Fatalf("baseline seeds = %d, want 1", len(chk.hashes))
	}
	// Drift the source ConfigMap content in the live API.
	changed := cm.DeepCopy()
	changed.Data["flags.yaml"] = "v2"
	if _, err := cs.CoreV1().ConfigMaps("apps").Update(ctx, changed, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	// Stamp the opt-out onto the SNAPSHOT-cached Deployment via the
	// overlay — the object's own map stays empty.
	cached, err := chk.AllDeployments(sweepCtx)
	if err != nil || len(cached) != 1 {
		t.Fatalf("cached deployments = %d, err %v", len(cached), err)
	}
	payload, err := kube.MergePatchAnnos(map[string]any{
		kube.AnnoSubPathReloadOptOut: "true",
	})
	if err != nil {
		t.Fatal(err)
	}
	kube.RecordAnnoPatch(sweepCtx, &cached[0], payload)

	// Two full scans past the 15m settle window: without the overlay
	// read the second one would nudge the Deployment (patches=1).
	probetest.FreezeNow(d, now.Add(31*time.Minute))
	chk.Run(sweepCtx)
	probetest.FreezeNow(d, now.Add(62*time.Minute))
	res := chk.Run(sweepCtx)
	if !res.Pass {
		t.Fatalf("opted-out workload must not be flagged: %+v", res)
	}
	if patches != 0 {
		t.Fatalf("opted-out workload got %d restart-template patches", patches)
	}
}

func TestSubPathFreshPodsStartTimeExemption(t *testing.T) {
	driftStart := time.Now().Add(-15 * time.Minute)
	w := subPathWorkload{
		kind: "Deployment", ns: "apps", name: "app",
		template: map[string]string{"app": "app"},
	}
	fresh := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "app-new",
			Labels: map[string]string{"app": "app"},
		},
		Status: corev1.PodStatus{
			Phase:     corev1.PodRunning,
			StartTime: &metav1.Time{Time: driftStart.Add(time.Minute)},
		},
	}
	stale := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "app-old",
			Labels: map[string]string{"app": "app"},
		},
		Status: corev1.PodStatus{
			Phase:     corev1.PodRunning,
			StartTime: &metav1.Time{Time: driftStart.Add(-time.Hour)},
		},
	}
	other := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "other", Name: "unrelated",
			Labels: map[string]string{"app": "app"},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}

	// All pods fresh → exempt (they mounted post-drift content).
	freshOnly, total := subPathFreshPods(w, []*corev1.Pod{fresh}, driftStart)
	if !freshOnly || total != 1 {
		t.Fatalf("fresh pods: fresh=%v total=%d want true/1", freshOnly, total)
	}
	// One stale pod → NOT exempt — the nudge must still roll it.
	mixed, _ := subPathFreshPods(w, []*corev1.Pod{fresh, stale}, driftStart)
	if mixed {
		t.Fatal("mixed-age pods wrongly exempted")
	}
	// Pods in other namespaces / wrong labels don't count.
	if f, tot := subPathFreshPods(w, []*corev1.Pod{other}, driftStart); f || tot != 0 {
		t.Fatalf("unrelated pod counted: fresh=%v total=%d", f, tot)
	}
	// Zero matching pods → not fresh (nothing proves resolution).
	if f, tot := subPathFreshPods(w, nil, driftStart); f || tot != 0 {
		t.Fatalf("empty census: fresh=%v total=%d", f, tot)
	}
}

func TestSubPathDriftedExclusions(t *testing.T) {
	template := map[string]string{"app": "x"}
	if !subPathDrifted("apps", template, nil) {
		t.Fatal("plain workload wrongly excluded")
	}
	for _, ns := range []string{"kube-system", "flux-system", "node-ops",
		"cert-manager", "linkerd", "external-secrets"} {
		if subPathDrifted(ns, template, nil) {
			t.Fatalf("system namespace %s not excluded", ns)
		}
	}
	quorum := map[string]string{"cnpg.io/cluster": "pg"}
	if subPathDrifted("apps", quorum, nil) {
		t.Fatal("quorum-labelled workload not excluded")
	}
	for _, val := range []string{"true", "1", "yes", "True"} {
		optOut := map[string]string{"passiontech.dev/subpath-reload-opt-out": val}
		if subPathDrifted("apps", template, optOut) {
			t.Fatalf("opted-out (%q) workload not excluded", val)
		}
	}
	if !subPathDrifted("apps", template, map[string]string{"passiontech.dev/subpath-reload-opt-out": "false"}) {
		t.Fatal("opt-out=false unexpectedly excluded")
	}
	if subPathDrifted("apps", map[string]string{"app.kubernetes.io/part-of": "dragonfly"}, nil) {
		t.Fatal("dragonfly workload not excluded")
	}
}

func TestSubPathGateKindMapping(t *testing.T) {
	cases := map[string]string{
		"Deployment":  "deployment",
		"StatefulSet": "statefulset",
		"DaemonSet":   "daemonset",
	}
	for in, want := range cases {
		if got := subPathGateKind(in); got != want {
			t.Fatalf("subPathGateKind(%q)=%q want %q", in, got, want)
		}
	}
}

func makeSubPathDep(ns, name, cmName, secName string, mf []metav1.ManagedFieldsEntry) *appsv1.Deployment {
	var vols []corev1.Volume
	var mounts []corev1.VolumeMount
	if cmName != "" {
		vols = append(vols, corev1.Volume{
			Name: "cfg",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: cmName},
				},
			},
		})
		mounts = append(mounts, corev1.VolumeMount{Name: "cfg", MountPath: "/etc/app", SubPath: "flags.yaml"})
	}
	if secName != "" {
		vols = append(vols, corev1.Volume{
			Name: "sec",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{SecretName: secName},
			},
		})
		mounts = append(mounts, corev1.VolumeMount{Name: "sec", MountPath: "/etc/sec", SubPath: "token"})
	}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:     ns,
			Name:          name,
			ManagedFields: mf,
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				Spec: corev1.PodSpec{
					Volumes:    vols,
					Containers: []corev1.Container{{Name: "app", VolumeMounts: mounts}},
				},
			},
		},
	}
}

func TestSubPathLastScanPreservedOnCensusError(t *testing.T) {
	cases := []struct {
		name     string
		verb     string
		resource string
		needPod  bool
	}{
		{name: "deployments list error", verb: "list", resource: "deployments"},
		{name: "statefulsets list error", verb: "list", resource: "statefulsets"},
		{name: "daemonsets list error", verb: "list", resource: "daemonsets"},
		{name: "configmaps get error", verb: "get", resource: "configmaps"},
		{name: "secrets get error", verb: "get", resource: "secrets"},
		{name: "pods list error", verb: "list", resource: "pods", needPod: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dep := makeSubPathDep("apps", "app", "app-cfg", "app-sec", nil)
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "app-cfg"},
				Data:       map[string]string{"flags.yaml": "v1"},
			}
			sec := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "app-sec"},
				Data:       map[string][]byte{"token": []byte("t1")},
			}
			cs := fake.NewSimpleClientset(dep, cm, sec)
			d := probetest.NewDeps(cs, probetest.OpDyn())
			base := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
			probetest.FreezeNow(d, base)
			chk := &subpathConfigDriftCheck{
				Deps:       d,
				hashes:     map[string]string{},
				driftSince: map[string]time.Time{},
			}

			var prevLastScan time.Time
			scanAt := base
			if tc.needPod {
				// Seed baseline, drift CM, and reach >15m settle window so PodsIn runs.
				chk.Run(probetest.SweepCtx(ctx, chk.Deps))
				if !chk.lastScan.Equal(base) {
					t.Fatalf("initial lastScan=%v, want %v", chk.lastScan, base)
				}
				cm2 := cm.DeepCopy()
				cm2.Data["flags.yaml"] = "v2"
				if _, err := cs.CoreV1().ConfigMaps("apps").Update(ctx, cm2, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
				scanAt = base.Add(subPathScanInterval + time.Minute)
				probetest.FreezeNow(d, scanAt)
				chk.Run(probetest.SweepCtx(ctx, chk.Deps))
				prevLastScan = chk.lastScan

				scanAt = scanAt.Add(subPathScanInterval + time.Minute)
				probetest.FreezeNow(d, scanAt)
			}

			cs.PrependReactor(tc.verb, tc.resource, func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("boom")
			})
			res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
			if res.Infra == nil {
				t.Fatalf("expected Infra error on %s %s, got %+v", tc.verb, tc.resource, res)
			}
			if !chk.lastScan.Equal(prevLastScan) {
				t.Fatalf("lastScan advanced to %v on error, want preserved %v", chk.lastScan, prevLastScan)
			}

			// Clear error and run 1m later (NOT 30m later): must NOT throttle!
			cs.ReactionChain = cs.ReactionChain[1:]
			retryAt := scanAt.Add(time.Minute)
			probetest.FreezeNow(d, retryAt)
			res2 := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
			if res2.Infra != nil {
				t.Fatalf("retry sweep failed unexpectedly: %+v", res2)
			}
			if !chk.lastScan.Equal(retryAt) {
				t.Fatalf("retry sweep throttled: lastScan=%v, want %v", chk.lastScan, retryAt)
			}
		})
	}
}

func TestSubPathReloadGateOrderingRefundReservationAndLazyPodsIn(t *testing.T) {
	fluxManaged := []metav1.ManagedFieldsEntry{{
		Manager:    "helm-controller",
		Operation:  metav1.ManagedFieldsOperationApply,
		APIVersion: "apps/v1",
	}}
	nudged := func(t *testing.T, cs *fake.Clientset, ns, name string) bool {
		t.Helper()
		got, err := cs.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_, ok := got.Spec.Template.Annotations[kube.RestartedAtAnno]
		return ok
	}

	t.Run("cooldown suppresses FluxPatchGate sightings", func(t *testing.T) {
		heal.ConfigureFluxConflictLoop(2, 2*time.Hour)
		var hookCalls int
		heal.SetFluxConflictHook(func(heal.FluxConflictSignal) { hookCalls++ })
		t.Cleanup(func() {
			heal.ConfigureFluxConflictLoop(0, 0)
			heal.SetFluxConflictHook(nil)
		})

		dep := makeSubPathDep("apps", "app-cool", "cm-cool", "", fluxManaged)
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "cm-cool"},
			Data:       map[string]string{"flags.yaml": "v1"},
		}
		cs := fake.NewSimpleClientset(dep, cm)
		d := probetest.NewDeps(cs, probetest.OpDyn())
		base := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
		chk := &subpathConfigDriftCheck{
			Deps:       d,
			hashes:     map[string]string{},
			driftSince: map[string]time.Time{},
		}
		w := subPathWorkload{kind: "Deployment", ns: "apps", name: "app-cool", template: dep.Spec.Template.Labels, obj: dep}

		// Stamp cooldown.
		ck := probefw.SelfHealKey(CheckNameSubPathConfigDrift, "Deployment/apps/app-cool")
		chk.reloadHeals.Stamp(ck, base)
		if resolved, spent := chk.reloadWorkload(probetest.SweepCtx(ctx, d), logr.Discard(), w, nil, base.Add(-20*time.Minute), base.Add(time.Minute), true); resolved || spent {
			t.Fatalf("expected cooldown skip, got resolved=%v spent=%v", resolved, spent)
		}
		if resolved, spent := chk.reloadWorkload(probetest.SweepCtx(ctx, d), logr.Discard(), w, nil, base.Add(-20*time.Minute), base.Add(2*time.Minute), true); resolved || spent {
			t.Fatalf("expected cooldown skip, got resolved=%v spent=%v", resolved, spent)
		}
		if hookCalls != 0 {
			t.Fatalf("FluxConflictHook fired %d times during cooldown, want 0", hookCalls)
		}

		// Past cooldown: 1st unblocked call at max=2 must succeed.
		after := base.Add(subPathReloadCooldown + time.Minute)
		resolved, spent := chk.reloadWorkload(probetest.SweepCtx(ctx, d), logr.Discard(), w, nil, base.Add(-20*time.Minute), after, true)
		if !resolved || !spent {
			t.Fatalf("post-cooldown reload failed: resolved=%v spent=%v (phantom Flux hits leaked)", resolved, spent)
		}
	})

	t.Run("TryReserveWorkloadKey denial refunds budget and skips FluxPatchGate", func(t *testing.T) {
		heal.ConfigureBudget(1, time.Hour)
		heal.ConfigureFluxConflictLoop(2, 30*time.Minute)
		t.Cleanup(func() {
			heal.ConfigureBudget(0, 0)
			heal.ConfigureFluxConflictLoop(0, 0)
		})

		depA := makeSubPathDep("apps", "a-res", "cm-a", "", fluxManaged)
		depB := makeSubPathDep("apps", "b-free", "cm-b", "", nil)
		cs := fake.NewSimpleClientset(depA, depB)
		d := probetest.NewDeps(cs, probetest.OpDyn())
		base := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
		probetest.FreezeNow(d, base)
		chk := &subpathConfigDriftCheck{
			Deps:       d,
			hashes:     map[string]string{},
			driftSince: map[string]time.Time{},
		}
		sctx := probetest.SweepCtx(ctx, d)
		if !kube.TryReserveWorkloadKey(sctx, "apps/Deployment/a-res") {
			t.Fatal("failed to pre-reserve key")
		}
		wA := subPathWorkload{kind: "Deployment", ns: "apps", name: "a-res", template: depA.Spec.Template.Labels, obj: depA}
		wB := subPathWorkload{kind: "Deployment", ns: "apps", name: "b-free", template: depB.Spec.Template.Labels, obj: depB}

		if resolved, spent := chk.reloadWorkload(sctx, logr.Discard(), wA, nil, base.Add(-20*time.Minute), base, true); resolved || spent {
			t.Fatalf("reserved workload should skip without spending: resolved=%v spent=%v", resolved, spent)
		}
		if resolved, spent := chk.reloadWorkload(sctx, logr.Discard(), wB, nil, base.Add(-20*time.Minute), base, true); !resolved || !spent {
			t.Fatalf("sibling workload did not get refunded grant: resolved=%v spent=%v", resolved, spent)
		}
		if nudged(t, cs, "apps", "a-res") || !nudged(t, cs, "apps", "b-free") {
			t.Fatalf("unexpected patch outcomes for a-res/b-free")
		}
	})

	t.Run("FluxPatchGate denial releases workload key, refunds budget, and uses duty-prefixed key", func(t *testing.T) {
		heal.ConfigureBudget(1, time.Hour)
		heal.ConfigureFluxConflictLoop(2, 30*time.Minute)
		t.Cleanup(func() {
			heal.ConfigureBudget(0, 0)
			heal.ConfigureFluxConflictLoop(0, 0)
		})

		depFlux := makeSubPathDep("apps", "a-flux", "cm-a", "", fluxManaged)
		depFree := makeSubPathDep("apps", "b-free", "cm-b", "", nil)
		depIso := makeSubPathDep("apps", "c-iso", "cm-c", "", fluxManaged)
		base := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

		// Exhaust duty-prefixed key for a-flux, and only sibling/unprefixed keys for c-iso.
		heal.FluxPatchGate("deployment", depFlux, CheckNameSubPathConfigDrift+":Deployment/apps/a-flux", base)
		heal.FluxPatchGate("deployment", depIso, "other-duty:Deployment/apps/c-iso", base)
		heal.FluxPatchGate("deployment", depIso, "Deployment/apps/c-iso", base)

		cs := fake.NewSimpleClientset(depFlux, depFree, depIso)
		d := probetest.NewDeps(cs, probetest.OpDyn())
		chk := &subpathConfigDriftCheck{
			Deps:       d,
			hashes:     map[string]string{},
			driftSince: map[string]time.Time{},
		}
		sctx := probetest.SweepCtx(ctx, d)
		wFlux := subPathWorkload{kind: "Deployment", ns: "apps", name: "a-flux", template: depFlux.Spec.Template.Labels, obj: depFlux}
		wFree := subPathWorkload{kind: "Deployment", ns: "apps", name: "b-free", template: depFree.Spec.Template.Labels, obj: depFree}
		wIso := subPathWorkload{kind: "Deployment", ns: "apps", name: "c-iso", template: depIso.Spec.Template.Labels, obj: depIso}

		if resolved, spent := chk.reloadWorkload(sctx, logr.Discard(), wFlux, nil, base.Add(-20*time.Minute), base, true); resolved || spent {
			t.Fatalf("FluxPatchGate denial must skip: resolved=%v spent=%v", resolved, spent)
		}
		if !kube.TryReserveWorkloadKey(sctx, "apps/Deployment/a-flux") {
			t.Fatal("FluxPatchGate denial leaked workload key reservation")
		}
		if resolved, spent := chk.reloadWorkload(sctx, logr.Discard(), wFree, nil, base.Add(-20*time.Minute), base, true); !resolved || !spent {
			t.Fatalf("sibling b-free did not receive refunded grant: resolved=%v spent=%v", resolved, spent)
		}

		// c-iso must not be blocked by sibling/unprefixed keys.
		heal.ConfigureBudget(1, time.Hour)
		if resolved, spent := chk.reloadWorkload(sctx, logr.Discard(), wIso, nil, base.Add(-20*time.Minute), base, true); !resolved || !spent {
			t.Fatalf("c-iso wrongly blocked by sibling/unprefixed FluxPatchGate key: resolved=%v spent=%v", resolved, spent)
		}
	})

	t.Run("Patch failure releases workload key, keeps spent=true, and does not refund budget", func(t *testing.T) {
		heal.ConfigureBudget(1, time.Hour)
		t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

		depFail := makeSubPathDep("apps", "a-fail", "cm-a", "", nil)
		depSibling := makeSubPathDep("apps", "b-sib", "cm-b", "", nil)
		cs := fake.NewSimpleClientset(depFail, depSibling)
		cs.PrependReactor("patch", "deployments", func(action ktesting.Action) (bool, runtime.Object, error) {
			if action.(ktesting.PatchAction).GetName() == "a-fail" {
				return true, nil, errors.New("patch error")
			}
			return false, nil, nil
		})
		d := probetest.NewDeps(cs, probetest.OpDyn())
		base := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
		chk := &subpathConfigDriftCheck{
			Deps:       d,
			hashes:     map[string]string{},
			driftSince: map[string]time.Time{},
		}
		sctx := probetest.SweepCtx(ctx, d)
		wFail := subPathWorkload{kind: "Deployment", ns: "apps", name: "a-fail", template: depFail.Spec.Template.Labels, obj: depFail}
		wSib := subPathWorkload{kind: "Deployment", ns: "apps", name: "b-sib", template: depSibling.Spec.Template.Labels, obj: depSibling}

		resolved, spent := chk.reloadWorkload(sctx, logr.Discard(), wFail, nil, base.Add(-20*time.Minute), base, true)
		if resolved || !spent {
			t.Fatalf("failed Patch must return resolved=false, spent=true, got %v, %v", resolved, spent)
		}
		if !kube.TryReserveWorkloadKey(sctx, "apps/Deployment/a-fail") {
			t.Fatal("Patch failure leaked workload key reservation")
		}
		// Budget should NOT be refunded, so sibling is denied.
		if res2, sp2 := chk.reloadWorkload(sctx, logr.Discard(), wSib, nil, base.Add(-20*time.Minute), base, true); res2 || sp2 {
			t.Fatalf("failed Patch wrongly refunded budget grant to sibling: %v, %v", res2, sp2)
		}
	})

	t.Run("lazy PodsIn skips pod list when no drift settled and isolates by namespace", func(t *testing.T) {
		dep := makeSubPathDep("apps", "app", "cm-app", "", nil)
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "cm-app"},
			Data:       map[string]string{"flags.yaml": "v1"},
		}
		otherPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "other", Name: "app-stale",
				Labels: map[string]string{"app": "app"},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}
		freshPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "apps", Name: "app-fresh",
				Labels: map[string]string{"app": "app"},
			},
		}
		cs := fake.NewSimpleClientset(dep, cm, otherPod, freshPod)
		var podLists int
		cs.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
			podLists++
			return false, nil, nil
		})
		d := probetest.NewDeps(cs, probetest.OpDyn())
		base := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
		probetest.FreezeNow(d, base)
		chk := &subpathConfigDriftCheck{
			Deps:       d,
			hashes:     map[string]string{},
			driftSince: map[string]time.Time{},
		}

		// Scan 1 (seed): 0 pod lists.
		chk.Run(probetest.SweepCtx(ctx, d))
		if podLists != 0 {
			t.Fatalf("podLists = %d on baseline seed, want 0", podLists)
		}

		// Drift CM and mark freshPod as started post-drift.
		cm2 := cm.DeepCopy()
		cm2.Data["flags.yaml"] = "v2"
		if _, err := cs.CoreV1().ConfigMaps("apps").Update(ctx, cm2, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		t1 := base.Add(subPathScanInterval + time.Minute)
		probetest.FreezeNow(d, t1)
		chk.Run(probetest.SweepCtx(ctx, d)) // observes driftSince = t1 (<15m)
		if podLists != 0 {
			t.Fatalf("podLists = %d before settle window, want 0", podLists)
		}

		fp, _ := cs.CoreV1().Pods("apps").Get(ctx, "app-fresh", metav1.GetOptions{})
		fp.Status = corev1.PodStatus{
			Phase:     corev1.PodRunning,
			StartTime: &metav1.Time{Time: t1.Add(time.Minute)},
		}
		_, _ = cs.CoreV1().Pods("apps").UpdateStatus(ctx, fp, metav1.UpdateOptions{})

		t2 := t1.Add(subPathScanInterval + time.Minute)
		probetest.FreezeNow(d, t2)
		chk.Run(probetest.SweepCtx(ctx, d))
		if podLists != 1 {
			t.Fatalf("podLists = %d when drift settled, want 1", podLists)
		}
		// other/app-stale must not prevent self-resolution for apps/app, so no patch landed.
		if nudged(t, cs, "apps", "app") {
			t.Fatal("stale pod in other namespace blocked fresh-pod resolution in apps")
		}
	})
}

func makeSubPathWorkloadFixture(kind, ns, name string, annos map[string]string) (runtime.Object, subPathWorkload) {
	labels := map[string]string{"app": name}
	meta := metav1.ObjectMeta{Namespace: ns, Name: name, Annotations: annos}
	tmpl := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: labels},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	switch kind {
	case "Deployment":
		dep := &appsv1.Deployment{ObjectMeta: meta, Spec: appsv1.DeploymentSpec{Template: tmpl}}
		return dep, subPathWorkload{kind: kind, ns: ns, name: name, template: labels, obj: dep}
	case "StatefulSet":
		sts := &appsv1.StatefulSet{ObjectMeta: meta, Spec: appsv1.StatefulSetSpec{Template: tmpl}}
		return sts, subPathWorkload{kind: kind, ns: ns, name: name, template: labels, obj: sts}
	case "DaemonSet":
		ds := &appsv1.DaemonSet{ObjectMeta: meta, Spec: appsv1.DaemonSetSpec{Template: tmpl}}
		return ds, subPathWorkload{kind: kind, ns: ns, name: name, template: labels, obj: ds}
	default:
		rs := &appsv1.ReplicaSet{ObjectMeta: meta, Spec: appsv1.ReplicaSetSpec{Template: tmpl}}
		return rs, subPathWorkload{kind: kind, ns: ns, name: name, template: labels, obj: rs}
	}
}

func TestSubPathReloadWorkloadBranches(t *testing.T) {
	base := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	driftStart := base.Add(-20 * time.Minute)

	stalePod := func(ns, app string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: app + "-stale", Labels: map[string]string{"app": app}},
			Status: corev1.PodStatus{
				Phase:     corev1.PodRunning,
				StartTime: &metav1.Time{Time: driftStart.Add(-5 * time.Minute)},
			},
		}
	}
	freshPod := func(ns, app string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: app + "-fresh", Labels: map[string]string{"app": app}},
			Status: corev1.PodStatus{
				Phase:     corev1.PodRunning,
				StartTime: &metav1.Time{Time: driftStart.Add(time.Minute)},
			},
		}
	}

	assertRestartedAndStamped := func(t *testing.T, cs *fake.Clientset, sctx context.Context, chk *subpathConfigDriftCheck, w subPathWorkload) {
		t.Helper()
		var tplAnnos, objAnnos map[string]string
		switch w.kind {
		case "Deployment":
			got, err := cs.AppsV1().Deployments(w.ns).Get(ctx, w.name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			tplAnnos, objAnnos = got.Spec.Template.Annotations, got.Annotations
			list, err := chk.AllDeployments(sctx)
			if err != nil || len(list) != 1 || list[0].Spec.Template.Annotations[kube.RestartedAtAnno] == "" {
				t.Fatalf("InvalidateDeployments did not refresh snapshot: list=%+v err=%v", list, err)
			}
		case "StatefulSet":
			got, err := cs.AppsV1().StatefulSets(w.ns).Get(ctx, w.name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			tplAnnos, objAnnos = got.Spec.Template.Annotations, got.Annotations
			list, err := chk.AllStatefulSets(sctx)
			if err != nil || len(list) != 1 || list[0].Spec.Template.Annotations[kube.RestartedAtAnno] == "" {
				t.Fatalf("InvalidateStatefulSets did not refresh snapshot: list=%+v err=%v", list, err)
			}
		case "DaemonSet":
			got, err := cs.AppsV1().DaemonSets(w.ns).Get(ctx, w.name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			tplAnnos, objAnnos = got.Spec.Template.Annotations, got.Annotations
			list, err := chk.AllDaemonSets(sctx)
			if err != nil || len(list) != 1 || list[0].Spec.Template.Annotations[kube.RestartedAtAnno] == "" {
				t.Fatalf("InvalidateDaemonSets did not refresh snapshot: list=%+v err=%v", list, err)
			}
		}
		if tplAnnos[kube.RestartedAtAnno] == "" {
			t.Fatalf("%s missing RestartedAtAnno", w.kind)
		}
		wantStamp := base.UTC().Format(time.RFC3339)
		if objAnnos[kube.AnnoLastSubPathReload] != wantStamp {
			t.Fatalf("%s AnnoLastSubPathReload = %q, want %q", w.kind, objAnnos[kube.AnnoLastSubPathReload], wantStamp)
		}
		if gotEff := kube.EffectiveAnno(sctx, w.obj, kube.AnnoLastSubPathReload); gotEff != wantStamp {
			t.Fatalf("SweepOverlay EffectiveAnno = %q, want %q", gotEff, wantStamp)
		}
		ck := probefw.SelfHealKey(CheckNameSubPathConfigDrift, w.kind+"/"+w.ns+"/"+w.name)
		if !chk.reloadHeals.CooledDown(ck, subPathReloadCooldown, base) {
			t.Fatalf("reloadHeals not stamped for %q", ck)
		}
	}

	type testCase struct {
		name              string
		kind              string
		mayPatch          bool
		fresh             bool
		nilDyn            bool
		preAnnos          map[string]string
		overlayStamp      bool
		kuredHold         bool
		exhaustBudget     bool
		nodeListErr       bool
		patchErrResource  string
		failMergePatch    bool
		wantResolved      bool
		wantSpent         bool
		wantPatches       int
		wantErrDelta      float64
		wantKeyReserved   bool
		wantReloadStamped bool
		verifySuccess     bool
	}

	cases := []testCase{
		{
			name:              "Deployment reload success",
			kind:              "Deployment",
			mayPatch:          true,
			wantResolved:      true,
			wantSpent:         true,
			wantPatches:       2,
			wantKeyReserved:   true,
			wantReloadStamped: true,
			verifySuccess:     true,
		},
		{
			name:              "StatefulSet reload success",
			kind:              "StatefulSet",
			mayPatch:          true,
			wantResolved:      true,
			wantSpent:         true,
			wantPatches:       2,
			wantKeyReserved:   true,
			wantReloadStamped: true,
			verifySuccess:     true,
		},
		{
			name:              "DaemonSet reload success",
			kind:              "DaemonSet",
			mayPatch:          true,
			wantResolved:      true,
			wantSpent:         true,
			wantPatches:       2,
			wantKeyReserved:   true,
			wantReloadStamped: true,
			verifySuccess:     true,
		},
		{
			name:         "fresh pods self-resolve when mayPatch=true",
			kind:         "Deployment",
			mayPatch:     true,
			fresh:        true,
			wantResolved: true,
			wantSpent:    false,
		},
		{
			name:         "fresh pods self-resolve when mayPatch=false",
			kind:         "Deployment",
			mayPatch:     false,
			fresh:        true,
			wantResolved: true,
			wantSpent:    false,
		},
		{
			name:         "mayPatch=false skips gates and patch",
			kind:         "Deployment",
			mayPatch:     false,
			wantResolved: false,
			wantSpent:    false,
		},
		{
			name:         "HealAllowedPersisted unverifiable when Dyn is nil",
			kind:         "Deployment",
			mayPatch:     true,
			nilDyn:       true,
			wantResolved: false,
			wantSpent:    false,
			wantErrDelta: 1,
		},
		{
			name:         "HealAllowedPersisted unverifiable on nodes list error",
			kind:         "Deployment",
			mayPatch:     true,
			nodeListErr:  true,
			wantResolved: false,
			wantSpent:    false,
			wantErrDelta: 1,
		},
		{
			name:         "HealAllowedPersisted skips on persisted annotation cooldown",
			kind:         "Deployment",
			mayPatch:     true,
			preAnnos:     map[string]string{kube.AnnoLastSubPathReload: base.Add(-10 * time.Minute).UTC().Format(time.RFC3339)},
			wantResolved: false,
			wantSpent:    false,
		},
		{
			name:         "HealAllowedPersisted skips on SweepOverlay persisted annotation",
			kind:         "Deployment",
			mayPatch:     true,
			overlayStamp: true,
			wantResolved: false,
			wantSpent:    false,
		},
		{
			name:         "HealAllowedPersisted skips under maintenance hold",
			kind:         "Deployment",
			mayPatch:     true,
			kuredHold:    true,
			wantResolved: false,
			wantSpent:    false,
		},
		{
			name:          "HealAllowedPersisted skips when global budget exhausted",
			kind:          "Deployment",
			mayPatch:      true,
			exhaustBudget: true,
			wantResolved:  false,
			wantSpent:     false,
		},
		{
			name:             "StatefulSet template patch error releases key and counts error",
			kind:             "StatefulSet",
			mayPatch:         true,
			patchErrResource: "statefulsets",
			wantResolved:     false,
			wantSpent:        true,
			wantPatches:      1,
			wantErrDelta:     1,
		},
		{
			name:             "DaemonSet template patch error releases key and counts error",
			kind:             "DaemonSet",
			mayPatch:         true,
			patchErrResource: "daemonsets",
			wantResolved:     false,
			wantSpent:        true,
			wantPatches:      1,
			wantErrDelta:     1,
		},
		{
			name:            "stampSubPathReload failure after template patch still resolves and counts error",
			kind:            "Deployment",
			mayPatch:        true,
			failMergePatch:  true,
			wantResolved:    true,
			wantSpent:       true,
			wantPatches:     2,
			wantErrDelta:    1,
			wantKeyReserved: true,
		},
		{
			name:              "unknown kind fallthrough stamps cooldown without apps patch",
			kind:              "ReplicaSet",
			mayPatch:          true,
			wantResolved:      true,
			wantSpent:         true,
			wantKeyReserved:   true,
			wantReloadStamped: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.exhaustBudget {
				heal.ConfigureBudget(1, time.Hour)
				t.Cleanup(func() { heal.ConfigureBudget(0, 0) })
			}

			obj, w := makeSubPathWorkloadFixture(tc.kind, "apps", "app", tc.preAnnos)
			objs := []runtime.Object{obj}
			if tc.kuredHold {
				objs = append(objs, &appsv1.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:   "kube-system",
						Name:        "kured",
						Annotations: map[string]string{"weave.works/kured-node-lock": "cluster-upgrade"},
					},
				})
			}
			var sibW subPathWorkload
			if tc.exhaustBudget {
				sibObj, sw := makeSubPathWorkloadFixture("Deployment", "apps", "sib", nil)
				objs = append(objs, sibObj)
				sibW = sw
			}

			cs := fake.NewSimpleClientset(objs...)
			var patchCalls int
			cs.PrependReactor("patch", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
				pa := action.(ktesting.PatchAction)
				res := pa.GetResource().Resource
				if res != "deployments" && res != "statefulsets" && res != "daemonsets" {
					return false, nil, nil
				}
				patchCalls++
				if tc.patchErrResource == res {
					return true, nil, errors.New("template patch failed")
				}
				if tc.failMergePatch && pa.GetPatchType() == types.MergePatchType {
					return true, nil, errors.New("merge patch failed")
				}
				return false, nil, nil
			})
			if tc.nodeListErr {
				cs.PrependReactor("list", "nodes", func(ktesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("nodes list failed")
				})
			}

			var dyn dynamic.Interface = probetest.OpDyn()
			if tc.nilDyn {
				dyn = nil
			}
			d := probetest.NewDeps(cs, dyn)
			probetest.FreezeNow(d, base)
			chk := &subpathConfigDriftCheck{
				Deps:       d,
				hashes:     map[string]string{},
				driftSince: map[string]time.Time{},
			}
			sctx := probetest.SweepCtx(ctx, d)
			defer probetest.VerifySweep(sctx)

			if tc.exhaustBudget {
				if res, sp := chk.reloadWorkload(sctx, logr.Discard(), sibW, nil, driftStart, base, true); !res || !sp {
					t.Fatalf("pre-spend sibling failed: resolved=%v spent=%v", res, sp)
				}
				patchCalls = 0
			}
			if tc.overlayStamp {
				payload, err := kube.MergePatchAnnos(map[string]any{
					kube.AnnoLastSubPathReload: base.Add(-10 * time.Minute).UTC().Format(time.RFC3339),
				})
				if err != nil {
					t.Fatal(err)
				}
				kube.RecordAnnoPatch(sctx, w.obj, payload)
			}

			pods := []*corev1.Pod{stalePod("apps", "app")}
			if tc.fresh {
				pods = []*corev1.Pod{freshPod("apps", "app")}
			}

			beforeErrs := probetest.CounterSnapshot(t, d.Name)
			resolved, spent := chk.reloadWorkload(sctx, logr.Discard(), w, pods, driftStart, base, tc.mayPatch)

			if resolved != tc.wantResolved || spent != tc.wantSpent {
				t.Fatalf("reloadWorkload = (%v, %v), want (%v, %v)", resolved, spent, tc.wantResolved, tc.wantSpent)
			}
			if patchCalls != tc.wantPatches {
				t.Fatalf("patchCalls = %d, want %d", patchCalls, tc.wantPatches)
			}
			probetest.AssertCounterDelta(t, d.Name, beforeErrs, tc.wantErrDelta)

			wKey := w.ns + "/" + w.kind + "/" + w.name
			if gotReserved := !kube.TryReserveWorkloadKey(sctx, wKey); gotReserved != tc.wantKeyReserved {
				t.Fatalf("workload key %q reserved=%v, want %v", wKey, gotReserved, tc.wantKeyReserved)
			}

			ck := probefw.SelfHealKey(CheckNameSubPathConfigDrift, w.kind+"/"+w.ns+"/"+w.name)
			if gotStamped := chk.reloadHeals.CooledDown(ck, subPathReloadCooldown, base); gotStamped != tc.wantReloadStamped {
				t.Fatalf("reloadHeals stamped=%v, want %v", gotStamped, tc.wantReloadStamped)
			}

			if tc.verifySuccess {
				assertRestartedAndStamped(t, cs, sctx, chk, w)
			}
			if tc.failMergePatch {
				dep, err := cs.AppsV1().Deployments(w.ns).Get(ctx, w.name, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if dep.Spec.Template.Annotations[kube.RestartedAtAnno] == "" {
					t.Fatal("expected template RestartedAtAnno even when stampSubPathReload failed")
				}
				if dep.Annotations[kube.AnnoLastSubPathReload] != "" || kube.EffectiveAnno(sctx, w.obj, kube.AnnoLastSubPathReload) != "" {
					t.Fatal("AnnoLastSubPathReload must not be recorded when stampSubPathReload fails")
				}
			}
		})
	}
}

func TestSubPathStampSubPathReload(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	stamp := now.UTC().Format(time.RFC3339)
	payload, err := kube.MergePatchAnnos(map[string]any{kube.AnnoLastSubPathReload: stamp})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name        string
		kind        string
		data        []byte
		patchErrRes string
		wantErr     bool
		wantPatches int
		verifyAnno  bool
	}{
		{name: "Deployment success", kind: "Deployment", data: payload, wantPatches: 1, verifyAnno: true},
		{name: "StatefulSet success", kind: "StatefulSet", data: payload, wantPatches: 1, verifyAnno: true},
		{name: "DaemonSet success", kind: "DaemonSet", data: payload, wantPatches: 1, verifyAnno: true},
		{name: "unknown kind CronJob is no-op", kind: "CronJob", data: payload},
		{name: "empty kind is no-op", kind: "", data: payload},
		{name: "Deployment patch error", kind: "Deployment", data: payload, patchErrRes: "deployments", wantErr: true, wantPatches: 1},
		{name: "StatefulSet patch error", kind: "StatefulSet", data: payload, patchErrRes: "statefulsets", wantErr: true, wantPatches: 1},
		{name: "DaemonSet patch error", kind: "DaemonSet", data: payload, patchErrRes: "daemonsets", wantErr: true, wantPatches: 1},
		{name: "invalid patch bytes on Deployment", kind: "Deployment", data: []byte{}, wantErr: true, wantPatches: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obj, w := makeSubPathWorkloadFixture(tc.kind, "apps", "app", nil)
			cs := fake.NewSimpleClientset(obj)
			if tc.patchErrRes != "" {
				cs.PrependReactor("patch", tc.patchErrRes, func(ktesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("injected patch error")
				})
			}
			chk := &subpathConfigDriftCheck{
				Deps:       probetest.NewDeps(cs, probetest.OpDyn()),
				hashes:     map[string]string{},
				driftSince: map[string]time.Time{},
			}

			gotErr := chk.stampSubPathReload(ctx, w, tc.data)
			if (gotErr != nil) != tc.wantErr {
				t.Fatalf("stampSubPathReload err = %v, wantErr=%v", gotErr, tc.wantErr)
			}

			var patches int
			for _, a := range cs.Actions() {
				if a.GetVerb() == "patch" {
					patches++
				}
			}
			if patches != tc.wantPatches {
				t.Fatalf("patch actions = %d, want %d", patches, tc.wantPatches)
			}

			if tc.verifyAnno {
				var annos map[string]string
				switch tc.kind {
				case "Deployment":
					g, e := cs.AppsV1().Deployments("apps").Get(ctx, "app", metav1.GetOptions{})
					if e != nil {
						t.Fatal(e)
					}
					annos = g.Annotations
				case "StatefulSet":
					g, e := cs.AppsV1().StatefulSets("apps").Get(ctx, "app", metav1.GetOptions{})
					if e != nil {
						t.Fatal(e)
					}
					annos = g.Annotations
				case "DaemonSet":
					g, e := cs.AppsV1().DaemonSets("apps").Get(ctx, "app", metav1.GetOptions{})
					if e != nil {
						t.Fatal(e)
					}
					annos = g.Annotations
				}
				if annos[kube.AnnoLastSubPathReload] != stamp {
					t.Fatalf("stamped annotation = %q, want %q", annos[kube.AnnoLastSubPathReload], stamp)
				}
			}
		})
	}
}

func TestSubPathEmitDriftEvent(t *testing.T) {
	base := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	t.Run("empty findings emits nothing", func(t *testing.T) {
		for _, findings := range [][]string{nil, {}} {
			cs := fake.NewSimpleClientset()
			d := probetest.NewDeps(cs, probetest.OpDyn())
			chk := &subpathConfigDriftCheck{Deps: d, eventHealed: state.CooldownSet{}}
			before := probetest.CounterSnapshot(t, d.Name)

			chk.emitDriftEvent(ctx, logr.Discard(), findings, base)

			probetest.AssertCounterDelta(t, d.Name, before, 0)
			evs, err := cs.EventsV1().Events("kube-system").List(ctx, metav1.ListOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if len(evs.Items) != 0 {
				t.Fatalf("got %d events, want 0", len(evs.Items))
			}
			ck := probefw.SelfHealKey(CheckNameSubPathConfigDrift, "event")
			if chk.eventHealed.CooledDown(ck, subPathEventCooldown, base) {
				t.Fatal("eventHealed stamped on empty findings")
			}
		}
	})

	t.Run("single and multiple findings format and cooldown lifecycle", func(t *testing.T) {
		cases := []struct {
			name     string
			findings []string
			wantNote string
		}{
			{
				name:     "single finding",
				findings: []string{"Deployment/apps/a"},
				wantNote: "subpath config drift: 1 workload(s) (Deployment/apps/a)",
			},
			{
				name:     "multiple findings",
				findings: []string{"Deployment/apps/a", "StatefulSet/apps/b"},
				wantNote: "subpath config drift: 2 workload(s) (Deployment/apps/a)",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				cs := fake.NewSimpleClientset()
				d := probetest.NewDeps(cs, probetest.OpDyn())
				chk := &subpathConfigDriftCheck{Deps: d}

				chk.emitDriftEvent(ctx, logr.Discard(), tc.findings, base)

				evs, err := cs.EventsV1().Events("kube-system").List(ctx, metav1.ListOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if len(evs.Items) != 1 {
					t.Fatalf("events = %d, want 1", len(evs.Items))
				}
				ev := evs.Items[0]
				wantName := "subpath-config-drift-" + base.Format("20060102-150405")
				if ev.Name != wantName || ev.Reason != "SubPathConfigDrift" || ev.Action != "SubPathConfigDrift" ||
					ev.Type != corev1.EventTypeWarning || ev.ReportingController != "node-automation-controller" ||
					ev.ReportingInstance != d.Name || ev.Note != tc.wantNote ||
					ev.Regarding != (corev1.ObjectReference{APIVersion: "v1", Kind: "Namespace", Name: "kube-system"}) ||
					!ev.EventTime.Time.Equal(base) {
					t.Fatalf("unexpected event: %+v", ev)
				}

				// Within cooldown -> suppressed.
				chk.emitDriftEvent(ctx, logr.Discard(), tc.findings, base.Add(30*time.Minute))
				evs2, _ := cs.EventsV1().Events("kube-system").List(ctx, metav1.ListOptions{})
				if len(evs2.Items) != 1 {
					t.Fatalf("expected cooldown suppression, got %d events", len(evs2.Items))
				}

				// At cooldown boundary -> 2nd event emitted.
				later := base.Add(subPathEventCooldown)
				chk.emitDriftEvent(ctx, logr.Discard(), tc.findings, later)
				evs3, _ := cs.EventsV1().Events("kube-system").List(ctx, metav1.ListOptions{})
				if len(evs3.Items) != 2 {
					t.Fatalf("expected 2nd event after cooldown expiry, got %d", len(evs3.Items))
				}
			})
		}
	})

	t.Run("event create error counts error and does not stamp cooldown", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		cs.PrependReactor("create", "events", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("rbac denied")
		})
		d := probetest.NewDeps(cs, probetest.OpDyn())
		chk := &subpathConfigDriftCheck{Deps: d}
		before := probetest.CounterSnapshot(t, d.Name)

		chk.emitDriftEvent(ctx, logr.Discard(), []string{"Deployment/apps/a"}, base)

		probetest.AssertCounterDelta(t, d.Name, before, 1)
		ck := probefw.SelfHealKey(CheckNameSubPathConfigDrift, "event")
		if chk.eventHealed.CooledDown(ck, subPathEventCooldown, base) {
			t.Fatal("eventHealed must not be stamped after create failure")
		}

		// Clearing the reactor allows immediate emission without waiting out cooldown.
		cs.ReactionChain = cs.ReactionChain[1:]
		chk.emitDriftEvent(ctx, logr.Discard(), []string{"Deployment/apps/a"}, base.Add(time.Minute))
		var list *eventsv1.EventList
		list, err := cs.EventsV1().Events("kube-system").List(ctx, metav1.ListOptions{})
		if err != nil || len(list.Items) != 1 {
			t.Fatalf("expected 1 event after transient failure cleared, got %d (err=%v)", len(list.Items), err)
		}
	})
}

func TestSubPathFreshPodsEmptyTemplateSelectorDoesNotMatchOtherPods(t *testing.T) {
	driftStart := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	unrelatedFresh := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "apps",
			Name:              "other-pod",
			Labels:            map[string]string{"app": "other"},
			CreationTimestamp: metav1.NewTime(driftStart.Add(time.Minute)),
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	w := subPathWorkload{kind: "Deployment", ns: "apps", name: "empty-tpl", template: nil}
	if allFresh, total := subPathFreshPods(w, []*corev1.Pod{unrelatedFresh}, driftStart); allFresh || total != 0 {
		t.Fatalf("empty template selector matched unrelated pod: allFresh=%v total=%d", allFresh, total)
	}
}

func TestSubPathDoesNotLeakGaugeOnPodsInInfraError(t *testing.T) {
	t.Cleanup(subPathConfigDriftGauge.Reset)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "leak-app"},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "leak-app"}},
			Spec: corev1.PodSpec{
				Volumes: []corev1.Volume{{
					Name: "cfg",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "leak-cfg"},
						},
					},
				}},
				Containers: []corev1.Container{{
					Name:         "app",
					VolumeMounts: []corev1.VolumeMount{{Name: "cfg", MountPath: "/etc/app", SubPath: "k"}},
				}},
			},
		}},
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "leak-cfg"},
		Data:       map[string]string{"k": "v1"},
	}
	cs := fake.NewSimpleClientset(dep, cm)
	d := probetest.NewDeps(cs, probetest.OpDyn())
	now := time.Now()
	probetest.FreezeNow(d, now)
	chk := &subpathConfigDriftCheck{Deps: d, hashes: map[string]string{}, driftSince: map[string]time.Time{}}

	// Seed baseline.
	chk.Run(probetest.SweepCtx(ctx, d))
	changed := cm.DeepCopy()
	changed.Data["k"] = "v2"
	_, _ = cs.CoreV1().ConfigMaps("apps").Update(ctx, changed, metav1.UpdateOptions{})
	probetest.FreezeNow(d, now.Add(subPathScanInterval+time.Minute))
	chk.Run(probetest.SweepCtx(ctx, d)) // sets driftSince

	// Fail PodsIn after rep.Flag fires.
	cs.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("pod list failed")
	})
	probetest.FreezeNow(d, now.Add(2*subPathScanInterval+2*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, d))
	if res.Infra == nil {
		t.Fatalf("expected Infra error on PodsIn failure, got %+v", res)
	}

	// Recover CM + PodsIn -> next sweep must prune the gauge series cleanly.
	cs.ReactionChain = cs.ReactionChain[1:]
	reverted := cm.DeepCopy()
	reverted.Data["k"] = "v1"
	_, _ = cs.CoreV1().ConfigMaps("apps").Update(ctx, reverted, metav1.UpdateOptions{})
	probetest.FreezeNow(d, now.Add(3*subPathScanInterval+3*time.Minute))
	if res2 := chk.Run(probetest.SweepCtx(ctx, d)); !res2.Pass {
		t.Fatalf("expected PASS after CM reverted, got %+v", res2)
	}
	if m := probetest.FindMetric(t, "node_automation_subpath_config_drift", map[string]string{
		"namespace": "apps", "workload": "leak-app", "kind": "Deployment",
	}); m != nil {
		t.Fatalf("orphaned subpath drift gauge leaked after PodsIn Infra error: %v", m)
	}
}

func TestSubPathStampReloadRecordsAnnoPatchInOverlay(t *testing.T) {
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web", UID: "dep-uid"}}
	cs := fake.NewSimpleClientset(dep)
	d := probetest.NewDeps(cs, probetest.OpDyn())
	chk := &subpathConfigDriftCheck{Deps: d}
	sctx := probetest.SweepCtx(ctx, d)

	payload, err := kube.MergePatchAnnos(map[string]any{kube.AnnoLastSubPathReload: "2026-11-28T10:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if err := chk.stampSubPathReload(sctx, subPathWorkload{kind: "Deployment", ns: "apps", name: "web", obj: dep}, payload); err != nil {
		t.Fatalf("stampSubPathReload: %v", err)
	}
	if got := kube.EffectiveAnno(sctx, dep, kube.AnnoLastSubPathReload); got != "2026-11-28T10:00:00Z" {
		t.Fatalf("EffectiveAnno = %q, want 2026-11-28T10:00:00Z", got)
	}
}

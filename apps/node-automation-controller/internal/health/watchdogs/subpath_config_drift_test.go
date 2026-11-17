// subpath_config_drift_test.go — coverage for the pure helpers of
// the subpath-config-drift check: the content-hash signature
// (ConfigMap AND Secret keys, items remapping, absent keys), the
// fresh-pod StartTime exemption, the system/quorum/opt-out
// exclusions, and the FluxPatchGate kind mapping.
package watchdogs

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	freshOnly, total := subPathFreshPods(w, []corev1.Pod{*fresh}, driftStart)
	if !freshOnly || total != 1 {
		t.Fatalf("fresh pods: fresh=%v total=%d want true/1", freshOnly, total)
	}
	// One stale pod → NOT exempt — the nudge must still roll it.
	mixed, _ := subPathFreshPods(w, []corev1.Pod{*fresh, *stale}, driftStart)
	if mixed {
		t.Fatal("mixed-age pods wrongly exempted")
	}
	// Pods in other namespaces / wrong labels don't count.
	if f, tot := subPathFreshPods(w, []corev1.Pod{*other}, driftStart); f || tot != 0 {
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

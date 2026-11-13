// logs_test.go — ReadPodLogTail over the fake clientset's get-pods-log
// reactor (testhelp.ProbeLogReactor): first-match scan, no-match,
// the maxBytes stream cap, and the error-not-clean fetch contract.
package kube

import (
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/testhelp"
)

func logTailPod() *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "ns", Name: "p1"}}
}

func TestReadPodLogTail(t *testing.T) {
	match := func(line string) bool { return strings.Contains(line, "needle") }

	t.Run("first matching line wins", func(t *testing.T) {
		cs := fake.NewSimpleClientset(logTailPod())
		cs.PrependReactor("get", "pods", testhelp.ProbeLogReactor(
			"noise\nneedle in line\nmore noise", nil))
		hit, err := ReadPodLogTail(t.Context(), cs, logTailPod(),
			PodLogOpts{TailLines: 50, MaxBytes: 1 << 20, Timeout: time.Second}, match)
		if err != nil || !hit {
			t.Fatalf("ReadPodLogTail = (%v,%v), want (true,nil)", hit, err)
		}
	})

	t.Run("no match reads clean", func(t *testing.T) {
		cs := fake.NewSimpleClientset(logTailPod())
		cs.PrependReactor("get", "pods", testhelp.ProbeLogReactor(
			"all quiet\nnothing here", nil))
		hit, err := ReadPodLogTail(t.Context(), cs, logTailPod(),
			PodLogOpts{TailLines: 50, MaxBytes: 1 << 20, Timeout: time.Second}, match)
		if err != nil || hit {
			t.Fatalf("ReadPodLogTail = (%v,%v), want (false,nil)", hit, err)
		}
	})

	t.Run("maxBytes caps the scanned body", func(t *testing.T) {
		cs := fake.NewSimpleClientset(logTailPod())
		cs.PrependReactor("get", "pods", testhelp.ProbeLogReactor(
			"ok\nneedle beyond the cap", nil))
		// 3 bytes => only "ok\n" is read — the needle must not match.
		hit, err := ReadPodLogTail(t.Context(), cs, logTailPod(),
			PodLogOpts{TailLines: 50, MaxBytes: 3, Timeout: time.Second}, match)
		if err != nil || hit {
			t.Fatalf("ReadPodLogTail = (%v,%v), want (false,nil)", hit, err)
		}
	})

	t.Run("fetch failure is inconclusive not clean", func(t *testing.T) {
		cs := fake.NewSimpleClientset(logTailPod())
		cs.PrependReactor("get", "pods", testhelp.ProbeLogReactor(
			"", errors.New("log fetch boom")))
		hit, err := ReadPodLogTail(t.Context(), cs, logTailPod(),
			PodLogOpts{TailLines: 50, MaxBytes: 1 << 20, Timeout: time.Second}, match)
		if err == nil || hit {
			t.Fatalf("ReadPodLogTail = (%v,%v), want (false,err)", hit, err)
		}
	})
}

func TestResolveDefaultContainer(t *testing.T) {
	multi := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "ns", Name: "p2"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "linkerd-proxy"},
			{Name: "app"},
			{Name: "config-reloader"},
		}}}

	if got := ResolveDefaultContainer(multi, "explicit"); got != "explicit" {
		t.Errorf("explicit = %q, want explicit", got)
	}
	// The annotation wins when it names a real container — even an
	// infra sidecar, since kubectl trusts it verbatim.
	ann := multi.DeepCopy()
	ann.Annotations = map[string]string{
		"kubectl.kubernetes.io/default-container": "config-reloader"}
	if got := ResolveDefaultContainer(ann, ""); got != "config-reloader" {
		t.Errorf("annotation = %q, want config-reloader", got)
	}
	// An annotation naming a nonexistent container is ignored.
	ann.Annotations["kubectl.kubernetes.io/default-container"] = "ghost"
	if got := ResolveDefaultContainer(ann, ""); got != "app" {
		t.Errorf("bad annotation = %q, want app (first non-sidecar)", got)
	}
	// No annotation: first non-infra container.
	if got := ResolveDefaultContainer(multi, ""); got != "app" {
		t.Errorf("no annotation = %q, want app", got)
	}
	// All infra sidecars: fall back to the first container.
	allSide := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{
		{Name: "linkerd-proxy"}, {Name: "envoy"}}}}
	if got := ResolveDefaultContainer(allSide, ""); got != "linkerd-proxy" {
		t.Errorf("all-sidecar pod = %q, want linkerd-proxy", got)
	}
	// No containers at all: "" keeps the apiserver's own verdict.
	if got := ResolveDefaultContainer(&corev1.Pod{}, ""); got != "" {
		t.Errorf("empty pod = %q, want \"\"", got)
	}
}

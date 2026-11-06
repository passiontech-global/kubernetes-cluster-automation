// logs_test.go — PodLogTail over the fake clientset's get-pods-log
// reactor (testhelp.ProbeLogReactor): first-match scan, no-match,
// the maxBytes stream cap, and the error-not-clean fetch contract.
package probefw

import (
	"context"
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

func TestPodLogTail(t *testing.T) {
	match := func(line string) bool { return strings.Contains(line, "needle") }

	t.Run("first matching line wins", func(t *testing.T) {
		cs := fake.NewSimpleClientset(logTailPod())
		cs.PrependReactor("get", "pods", testhelp.ProbeLogReactor(
			"noise\nneedle in line\nmore noise", nil))
		hit, err := PodLogTail(context.Background(), cs, logTailPod(),
			"", 50, 1<<20, time.Second, match)
		if err != nil || !hit {
			t.Fatalf("PodLogTail = (%v,%v), want (true,nil)", hit, err)
		}
	})

	t.Run("no match reads clean", func(t *testing.T) {
		cs := fake.NewSimpleClientset(logTailPod())
		cs.PrependReactor("get", "pods", testhelp.ProbeLogReactor(
			"all quiet\nnothing here", nil))
		hit, err := PodLogTail(context.Background(), cs, logTailPod(),
			"", 50, 1<<20, time.Second, match)
		if err != nil || hit {
			t.Fatalf("PodLogTail = (%v,%v), want (false,nil)", hit, err)
		}
	})

	t.Run("maxBytes caps the scanned body", func(t *testing.T) {
		cs := fake.NewSimpleClientset(logTailPod())
		cs.PrependReactor("get", "pods", testhelp.ProbeLogReactor(
			"ok\nneedle beyond the cap", nil))
		// 3 bytes => only "ok\n" is read — the needle must not match.
		hit, err := PodLogTail(context.Background(), cs, logTailPod(),
			"", 50, 3, time.Second, match)
		if err != nil || hit {
			t.Fatalf("PodLogTail = (%v,%v), want (false,nil)", hit, err)
		}
	})

	t.Run("fetch failure is inconclusive not clean", func(t *testing.T) {
		cs := fake.NewSimpleClientset(logTailPod())
		cs.PrependReactor("get", "pods", testhelp.ProbeLogReactor(
			"", errors.New("log fetch boom")))
		hit, err := PodLogTail(context.Background(), cs, logTailPod(),
			"", 50, 1<<20, time.Second, match)
		if err == nil || hit {
			t.Fatalf("PodLogTail = (%v,%v), want (false,err)", hit, err)
		}
	})
}

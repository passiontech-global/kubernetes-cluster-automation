package corednswatchdog

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func TestCoreDNSWatchdogPluginLoopCrashLoopRecreate(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  corednsNS,
			Name:       "coredns",
			Generation: 2,
		},
		Spec: appsv1.DeploymentSpec{Replicas: ptr.To[int32](2)},
		Status: appsv1.DeploymentStatus{
			ObservedGeneration: 2,
			UpdatedReplicas:    2,
			ReadyReplicas:      1, // ReadyReplicas < Replicas because 1 pod is CrashLoopBackOff!
		},
	}
	healthyPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: corednsNS,
			Name:      "coredns-healthy",
			UID:       types.UID("uid-healthy"),
			Labels:    map[string]string{"k8s-app": "kube-dns"},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: "10.0.0.10",
			Conditions: []corev1.PodCondition{{
				Type:   corev1.PodReady,
				Status: corev1.ConditionTrue,
			}},
		},
	}
	loopPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: corednsNS,
			Name:      "coredns-looping",
			UID:       types.UID("uid-loop"),
			Labels:    map[string]string{"k8s-app": "kube-dns"},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "coredns",
				State: corev1.ContainerState{
					Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"},
				},
				LastTerminationState: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{ExitCode: 1},
				},
			}},
		},
	}
	readyNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
		},
	}

	cs := fake.NewSimpleClientset(deploy, healthyPod, loopPod, readyNode)
	w := &coreDNSWatchdog{
		cs:       cs,
		dyn:      testutil.NewDynamicClient(),
		now:      func() time.Time { return now },
		logHitFn: func(context.Context, string) string { return "" },
		prevLogFn: func(_ context.Context, p *corev1.Pod) string {
			if p.Name == "coredns-looping" {
				return "[FATAL] plugin/loop: Loop (127.0.0.1:55312 -> :53) detected for zone \".\""
			}
			return ""
		},
		dnsFn:    func(context.Context, string, string) ([]string, error) { return []string{"10.96.0.1"}, nil },
		panicsFn: func(context.Context, string) (float64, bool) { return 0, true },
	}

	if err := w.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	if _, err := cs.CoreV1().Pods(corednsNS).Get(context.Background(), "coredns-looping", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expected CrashLoopBackOff plugin/loop pod deleted despite ReadyReplicas<Replicas, err=%v", err)
	}
	if _, err := cs.CoreV1().Pods(corednsNS).Get(context.Background(), "coredns-healthy", metav1.GetOptions{}); err != nil {
		t.Fatalf("healthy coredns pod must remain untouched: %v", err)
	}
}

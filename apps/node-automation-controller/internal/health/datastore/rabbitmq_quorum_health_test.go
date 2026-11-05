// rabbitmq_quorum_health_test.go — coverage for the
// rabbitmq-quorum-health check (W10-ST3): alarm FAIL, stuck-
// unready heal with quorum, healthy pass.
package datastore

import (
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/health/probetest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func TestRabbitMQQuorumAlarmFails(t *testing.T) {
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "file_descriptor_limit") {
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq", "pod": "rabbitmq-server-0"},
				Value:  1,
			}}
		}
		return nil
	})
	pods := []runtime.Object{}
	for _, n := range []string{"rabbitmq-server-0", "rabbitmq-server-1", "rabbitmq-server-2"} {
		pods = append(pods, rabbitMQMemberPod("mq", n, true))
	}
	cs := fake.NewSimpleClientset(pods...)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	res := mustCheck[*rabbitMQQuorumHealthCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("fd-limit alarm must fail: %+v", res)
	}
	if !strings.Contains(res.Why, "rabbitmq-server-0") ||
		!strings.Contains(res.Why, "fd_limit_alarm") {
		t.Fatalf("why missing diagnostics: %q", res.Why)
	}
}

func TestRabbitMQQuorumStuckUnreadyHeal(t *testing.T) {
	// Prometheus dead -> pod signature still heals: unready >10m
	// with >=2 Ready siblings.
	bad := rabbitMQMemberPod("mq", "rabbitmq-server-0", false)
	bad.Status.Conditions[0].LastTransitionTime = metav1.NewTime(time.Now().Add(-15 * time.Minute))
	r1 := rabbitMQMemberPod("mq", "rabbitmq-server-1", true)
	r2 := rabbitMQMemberPod("mq", "rabbitmq-server-2", true)
	cs := fake.NewSimpleClientset(bad, r1, r2)
	p := testProber(cs)

	res := mustCheck[*rabbitMQQuorumHealthCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("stuck-unready quorum member must fail: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("mq").Get(ctx, "rabbitmq-server-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("unready pod should be deleted with quorum intact, err=%v", err)
	}
}

func TestRabbitMQQuorumHealthyPasses(t *testing.T) {
	pods := []runtime.Object{
		rabbitMQMemberPod("mq", "rabbitmq-server-0", true),
		rabbitMQMemberPod("mq", "rabbitmq-server-1", true),
		rabbitMQMemberPod("mq", "rabbitmq-server-2", true),
	}
	cs := fake.NewSimpleClientset(pods...)
	p := testProber(cs)
	if res := mustCheck[*rabbitMQQuorumHealthCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("healthy quorum must pass: %+v", res)
	}
}

func rabbitMQMemberPod(ns, name string, ready bool) *corev1.Pod {
	pod := probetest.PodWithPhase(ns, name, corev1.PodRunning, ready, time.Hour)
	pod.Labels = map[string]string{
		"app.kubernetes.io/part-of":   "rabbitmq",
		"app.kubernetes.io/component": "rabbitmq",
	}
	return pod
}

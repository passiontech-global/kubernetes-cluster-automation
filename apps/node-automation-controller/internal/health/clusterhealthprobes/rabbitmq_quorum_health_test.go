// rabbitmq_quorum_health_test.go — coverage for the
// rabbitmq-quorum-health check (W10-ST3): alarm FAIL, stuck-
// unready heal with quorum, healthy pass.
package clusterhealthprobes

import (
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func TestRabbitMQQuorumAlarmFails(t *testing.T) {
	srv, _ := promTestServer(t, func(query string) []promTestSample {
		if strings.Contains(query, "file_descriptor_limit") {
			return []promTestSample{{
				labels: map[string]string{"namespace": "mq", "pod": "rabbitmq-server-0"},
				value:  1,
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
	p.cfg.httpURL = srv.URL
	p.httpClient = srv.Client()

	res := mustCheck[*rabbitMQQuorumHealthCheck](t, p).run(ctx)
	if res.pass {
		t.Fatalf("fd-limit alarm must fail: %+v", res)
	}
	if !strings.Contains(res.why, "rabbitmq-server-0") ||
		!strings.Contains(res.why, "fd_limit_alarm") {
		t.Fatalf("why missing diagnostics: %q", res.why)
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

	res := mustCheck[*rabbitMQQuorumHealthCheck](t, p).run(ctx)
	if res.pass {
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
	if res := mustCheck[*rabbitMQQuorumHealthCheck](t, p).run(ctx); !res.pass {
		t.Fatalf("healthy quorum must pass: %+v", res)
	}
}

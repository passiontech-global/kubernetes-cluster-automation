// linkerd_protocol_detection_stall_test.go — coverage for the
// linkerd-protocol-detection-stall check (W10-NM3): opaque-ports
// heal patch + pod re-roll, skip-inbound coverage, port-set
// parsing.
package clusterhealthprobes

import (
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// ---------------------------------------------------------------------------
// W10-NM3 — linkerd-protocol-detection-stall
// ---------------------------------------------------------------------------

func TestLinkerdOpaquePortsHealPatchesTemplateAndDeletesPod(t *testing.T) {
	sts := emptyStatefulSet("apps", "cache")
	pod := meshedPodWithPorts("apps", "cache-0", []int32{6379, 8080}, "", "")
	setPodOwnerStatefulSet(pod, "cache")
	cs := fake.NewSimpleClientset(sts, pod)
	p := testProber(cs)

	res := mustCheck[*linkerdProtocolDetectionStallCheck](t, p).run(ctx)
	if res.pass {
		t.Fatalf("unannotated binary port must fail: %+v", res)
	}
	if !strings.Contains(res.why, "6379") {
		t.Fatalf("why missing port diagnostics: %q", res.why)
	}
	got, err := cs.AppsV1().StatefulSets("apps").Get(ctx, "cache", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Spec.Template.Annotations["config.linkerd.io/opaque-ports"] != "6379" {
		t.Fatalf("template opaque-ports = %q, want 6379",
			got.Spec.Template.Annotations["config.linkerd.io/opaque-ports"])
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "cache-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("pod should be deleted after template patch, err=%v", err)
	}
	if m := findMetric(t, "node_automation_linkerd_opaque_port_missing",
		map[string]string{"namespace": "apps", "pod": "cache-0", "port": "6379"}); m == nil {
		t.Fatal("opaque-port-missing gauge absent")
	}
}

func TestLinkerdOpaquePortsAnnotatedPasses(t *testing.T) {
	pod := meshedPodWithPorts("apps", "cache-0", []int32{6379}, "6379", "")
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	if res := mustCheck[*linkerdProtocolDetectionStallCheck](t, p).run(ctx); !res.pass {
		t.Fatalf("annotated port must pass: %+v", res)
	}
}

func TestLinkerdSkipInboundCoversPort(t *testing.T) {
	pod := meshedPodWithPorts("apps", "cache-0", []int32{6379}, "", "6379")
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	if res := mustCheck[*linkerdProtocolDetectionStallCheck](t, p).run(ctx); !res.pass {
		t.Fatalf("skip-inbound-ports must cover the port: %+v", res)
	}
}

func TestLinkerdNonBinaryPortPasses(t *testing.T) {
	pod := meshedPodWithPorts("apps", "web-0", []int32{8080, 9090}, "", "")
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	if res := mustCheck[*linkerdProtocolDetectionStallCheck](t, p).run(ctx); !res.pass {
		t.Fatalf("non-binary ports must pass: %+v", res)
	}
}

func TestParsePortSetRanges(t *testing.T) {
	got := parsePortSet("6379, 8000-8002")
	for _, want := range []int{6379, 8000, 8001, 8002} {
		if !got[want] {
			t.Fatalf("port %d missing from %v", want, got)
		}
	}
	if len(got) != 4 {
		t.Fatalf("unexpected ports: %v", got)
	}
}

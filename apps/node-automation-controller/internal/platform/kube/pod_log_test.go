// logs_test.go — ReadPodLogTail over the fake clientset's get-pods-log
// reactor (testhelp.ProbeLogReactor): first-match scan, no-match,
// the maxBytes stream cap, and the error-not-clean fetch contract.
package kube

import (
	"context"
	"errors"
	"io"
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

// chunkReader forces short reads so the ring trims across several
// iterations — the path where the newline that terminates a cut
// fragment has not arrived yet.
type chunkReader struct {
	data string
	off  int
	n    int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	end := r.off + r.n
	if end > len(r.data) {
		end = len(r.data)
	}
	copy(p, r.data[r.off:end])
	read := end - r.off
	r.off = end
	return read, nil
}

// A cap that cuts through the middle of the oldest retained line
// must discard the fragment up to the next newline — a timestamp-
// less first line would make PodLogLineTS callers read a signature
// match on it as freshly written.
func TestReadPodLogTailBytesDropsCutHeadLine(t *testing.T) {
	log := "2024-01-01T00:00:00Z old one\n" +
		"2024-01-01T00:00:01Z old two\n" +
		"2024-01-01T00:00:02Z needle here\n"
	got, err := readPodLogTailBytes(&chunkReader{data: log, n: 7}, 50)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "needle here") {
		t.Fatalf("newest line lost: %q", got)
	}
	for _, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		if _, ok := PodLogLineTS(line); !ok {
			t.Fatalf("tail retained a partial first line %q", line)
		}
	}
	// The signature on the cut fragment itself must never match:
	// a capped read of only that fragment yields no verifiable line.
	frag, err := readPodLogTailBytes(strings.NewReader(
		"2024-01-01T00:00:00Z needle in a cut line"), 12)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(frag, "needle") {
		t.Fatalf("fragment without a timestamp must not be returned: %q", frag)
	}
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

func TestReadPodLogTextZeroBoundsAndScanWorkers(t *testing.T) {
	cs := fake.NewSimpleClientset(logTailPod())
	cs.PrependReactor("get", "pods", testhelp.ProbeLogReactor("line1\nline2", nil))
	// Zero Timeout and MaxBytes must not cancel immediately or truncate to 0 bytes.
	got, err := ReadPodLogText(t.Context(), cs, logTailPod(), PodLogOpts{})
	if err != nil || got != "line1\nline2" {
		t.Fatalf("ReadPodLogText zero opts = (%q,%v), want (line1\\nline2,nil)", got, err)
	}
	// Non-positive workers must clamp to 1 instead of failing errgroup.SetLimit.
	res := ScanPodLogs(t.Context(), []*corev1.Pod{logTailPod()}, 0,
		func(_ context.Context, p *corev1.Pod) (string, error) {
			return p.Name, nil
		})
	if len(res) != 1 || res[0].Err != nil || res[0].Value != "p1" {
		t.Fatalf("ScanPodLogs(workers=0) = %+v, want [{Value:p1 Err:<nil>}]", res)
	}
}

// logs_test.go — ReadPodLogTail over the fake clientset's get-pods-log
// reactor (testhelp.ProbeLogReactor): first-match scan, no-match,
// the maxBytes stream cap, and the error-not-clean fetch contract.
package kube

import (
	"bytes"
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

type errAfterReader struct {
	data []byte
	off  int
	err  error
}

func (r *errAfterReader) Read(p []byte) (int, error) {
	if r.off < len(r.data) {
		n := copy(p, r.data[r.off:])
		r.off += n
		return n, nil
	}
	return 0, r.err
}

// DefaultPodLogMaxBytes caps ReadPodLogText when MaxBytes <= 0 so an
// unbounded GetLogs stream cannot OOM the controller: ==1 MiB passes
// verbatim, >1 MiB tail-truncates to <=1 MiB keeping the newest complete
// timestamped lines, MaxBytes=-1 defaults identically, and explicit
// positive MaxBytes overrides the default.
func TestReadPodLogTextDefaultMaxBytes(t *testing.T) {
	const line = "2024-01-01T00:00:00Z log line padding for 64 byte test record!!\n" // 64 bytes
	if len(line) != 64 {
		t.Fatalf("test fixture line len = %d, want 64", len(line))
	}
	exactPayload := strings.Repeat(line, int(DefaultPodLogMaxBytes)/len(line))
	if int64(len(exactPayload)) != DefaultPodLogMaxBytes {
		t.Fatalf("exactPayload len = %d, want %d", len(exactPayload), DefaultPodLogMaxBytes)
	}
	overLine := "2024-01-01T00:00:01Z newest tail line that must survive truncation\n"
	overPayload := exactPayload + strings.Repeat(overLine, 64)

	for _, tc := range []struct {
		name      string
		payload   string
		maxBytes  int64
		wantExact bool
		wantTail  string
	}{
		{
			name:      "zero MaxBytes at exact 1 MiB boundary",
			payload:   exactPayload,
			maxBytes:  0,
			wantExact: true,
		},
		{
			name:     "zero MaxBytes over 1 MiB truncates head and keeps newest lines",
			payload:  overPayload,
			maxBytes: 0,
			wantTail: overLine,
		},
		{
			name:     "negative MaxBytes defaults to 1 MiB and caps",
			payload:  overPayload,
			maxBytes: -1,
			wantTail: overLine,
		},
		{
			name:     "explicit positive MaxBytes overrides default",
			payload:  strings.Repeat(line, 4) + overLine,
			maxBytes: int64(len(overLine) + 10),
			wantTail: overLine,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(logTailPod())
			cs.PrependReactor("get", "pods", testhelp.ProbeLogReactor(tc.payload, nil))
			got, err := ReadPodLogText(t.Context(), cs, logTailPod(), PodLogOpts{
				MaxBytes:   tc.maxBytes,
				Timestamps: true,
			})
			if err != nil {
				t.Fatalf("ReadPodLogText: %v", err)
			}
			if tc.wantExact {
				if got != tc.payload {
					t.Fatalf("len(got)=%d, want exact %d", len(got), len(tc.payload))
				}
				return
			}
			limit := tc.maxBytes
			if limit <= 0 {
				limit = DefaultPodLogMaxBytes
			}
			if int64(len(got)) > limit {
				t.Fatalf("len(got)=%d exceeds cap %d", len(got), limit)
			}
			if !strings.HasSuffix(got, tc.wantTail) {
				t.Fatalf("tail missing newest line %q", tc.wantTail)
			}
			for _, l := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
				if _, ok := PodLogLineTS(l); !ok {
					t.Fatalf("retained partial line without timestamp: %q", l)
				}
			}
		})
	}
}

func TestReadPodLogTailBytesBoundaryCutAndErrors(t *testing.T) {
	t.Run("exact maxBytes without newline returns full payload", func(t *testing.T) {
		payload := bytes.Repeat([]byte("a"), 128)
		got, err := readPodLogTailBytes(bytes.NewReader(payload), 128)
		if err != nil || got != string(payload) {
			t.Fatalf("got (len=%d, err=%v), want (len=128, nil)", len(got), err)
		}
	})

	t.Run("over maxBytes without newline drops cut fragment", func(t *testing.T) {
		payload := bytes.Repeat([]byte("a"), 129)
		got, err := readPodLogTailBytes(bytes.NewReader(payload), 128)
		if err != nil || got != "" {
			t.Fatalf("got (%q, %v), want (\"\", nil)", got, err)
		}
	})

	t.Run("defensive clamp when maxBytes <= 0", func(t *testing.T) {
		got, err := readPodLogTailBytes(strings.NewReader("line1\nline2\n"), -5)
		if err != nil || got != "line1\nline2\n" {
			t.Fatalf("got (%q, %v), want (line1\\nline2\\n, nil)", got, err)
		}
	})

	t.Run("stream error propagates unchanged", func(t *testing.T) {
		boom := errors.New("stream reset")
		got, err := readPodLogTailBytes(&errAfterReader{data: []byte("partial\n"), err: boom}, 1024)
		if !errors.Is(err, boom) || got != "" {
			t.Fatalf("got (%q, %v), want (\"\", %v)", got, err, boom)
		}
	})
}

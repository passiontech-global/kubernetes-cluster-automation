// logs.go — PodLogTail, the pod log-tail signature scanner four
// checks share (cloudflared QUIC edge-dial storm, linkerd-h2 stream
// storm, scylla gossip/raft stall, postgres WAL archive): one
// bounded GetLogs fetch — ctx timeout, TailLines, an io.LimitReader
// byte cap — then a per-line match that stops at the first hit. A
// fetch/read failure is inconclusive, NOT healthy, so the error is
// returned for the caller to log rather than reading "no match" as
// clean — the posture every reference site documents.
package probefw

import (
	"context"
	"io"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// infraSidecars are the mesh/observability sidecar names ResolveDefaultContainer
// skips when picking a pod's primary container — the same class the kubectl
// default-container annotation exists to escape.
var infraSidecars = map[string]bool{
	"linkerd-proxy": true, "config-reloader": true,
	"kube-rbac-proxy": true, "istio-proxy": true,
	"envoy": true, "promtail": true, "fluent-bit": true,
}

// ResolveDefaultContainer picks the container a pod-log read should
// target when the caller passed "": the explicit name when set, then
// the kubectl.kubernetes.io/default-container annotation when it names
// a real container, then the first non-infra sidecar, then the first
// container. Resolving client-side matters: GetLogs with Container=""
// on a MULTI-container pod is an HTTP 400 ("a container name must be
// specified") — the apiserver's default-container rule only covers
// pods the annotation already disambiguates.
func ResolveDefaultContainer(pod *corev1.Pod, explicit string) string {
	if explicit != "" {
		return explicit
	}
	names := make(map[string]bool, len(pod.Spec.Containers))
	for _, c := range pod.Spec.Containers {
		names[c.Name] = true
	}
	if ann := pod.Annotations["kubectl.kubernetes.io/default-container"]; ann != "" && names[ann] {
		return ann
	}
	for _, c := range pod.Spec.Containers {
		if !infraSidecars[c.Name] {
			return c.Name
		}
	}
	if len(pod.Spec.Containers) > 0 {
		return pod.Spec.Containers[0].Name
	}
	return ""
}

// PodLogTail fetches the last tailLines of one pod container's log
// and reports whether any line satisfies match. container "" resolves
// via ResolveDefaultContainer — required on multi-container pods,
// where an empty Container is an HTTP 400 rather than a default;
// maxBytes bounds the streamed body. The scan stops at the
// first matching line — a caller needing the match's detail closes
// over it inside match (the WAL guard captures its reason string).
// Lines are matched verbatim: case-folding/marker sets stay with the
// caller (cloudflared/linkerd lower-case per line, scylla regexes
// case-sensitively).
func PodLogTail(ctx context.Context, cs kubernetes.Interface,
	pod *corev1.Pod, container string, tailLines, maxBytes int64,
	timeout time.Duration, match func(line string) bool) (bool, error) {

	lctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stream, err := cs.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name,
		&corev1.PodLogOptions{
			Container: ResolveDefaultContainer(pod, container),
			TailLines: &tailLines,
		}).Stream(lctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = stream.Close() }()
	data, err := io.ReadAll(io.LimitReader(stream, maxBytes))
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if match(line) {
			return true, nil
		}
	}
	return false, nil
}

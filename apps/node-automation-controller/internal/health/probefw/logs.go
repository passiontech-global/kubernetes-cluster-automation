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

// PodLogTail fetches the last tailLines of one pod container's log
// and reports whether any line satisfies match. container "" follows
// the apiserver's default-container rule (the cloudflared check's
// posture); maxBytes bounds the streamed body. The scan stops at the
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
			Container: container,
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

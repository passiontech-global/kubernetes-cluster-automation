// pod_log_probe.go — layer 1 of coredns-stale-watchdog, the log
// fast-path: stream each coredns pod's last-10m log and grep the
// informer/reflector death signature. Instant catch, no false
// positives.
package corednswatchdog

import (
	"context"
	"io"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// corednsLogRE is the dead-informer signature — the exact bash
// alternation. Healthy pods only log a few INFO lines at boot.
var corednsLogRE = regexp.MustCompile(
	`Failed to watch|failed to watch|Failed to list|failed to list|Unauthorized|reflector`)

// logHit returns the first last-10m log line matching the informer
// death signature ("" = clean/unreadable). Bounded to 8s / 256KiB.
// A stream/read failure is inconclusive, not clean — logged so a
// broken pod-log path (RBAC, API flap) cannot silently disable
// layer 1 while layers 2/3 keep reporting "fresh".
func (w *coreDNSWatchdog) logHit(ctx context.Context, pod string) string {
	log := logf.FromContext(ctx)
	lctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	since := int64(corednsLogSinceS)
	stream, err := w.cs.CoreV1().Pods(corednsNS).GetLogs(pod,
		&corev1.PodLogOptions{SinceSeconds: &since}).Stream(lctx)
	if err != nil {
		log.Info("log: cannot stream pod logs — layer 1 inconclusive", "pod", pod, "error", err)
		return ""
	}
	defer func() { _ = stream.Close() }()
	data, err := io.ReadAll(io.LimitReader(stream, corednsMaxLogBytes))
	if err != nil {
		log.Info("log: cannot read pod log stream — layer 1 inconclusive", "pod", pod, "error", err)
		return ""
	}
	for rest := string(data); rest != ""; {
		line, after, _ := strings.Cut(rest, "\n")
		rest = after
		if corednsLogRE.MatchString(line) {
			return line
		}
	}
	return ""
}

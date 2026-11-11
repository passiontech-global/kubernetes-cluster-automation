// pod_log_probe.go — layer 1 of coredns-stale-watchdog, the log
// fast-path: stream each coredns pod's last-10m log and grep the
// informer/reflector death signature. Instant catch, no false
// positives.
package corednswatchdog

import (
	"context"
	"regexp"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// corednsLogRE is the dead-informer signature — the bash alternation
// minus its bare `reflector` alternative: a standalone `reflector`
// word matched healthy startup lines too (every informer logs
// "Starting reflector" once at boot), so a fresh pod could ride a
// streak it never earned. The watch/list-failure + Unauthorized
// signatures stay — they only appear when the watch actually died.
var corednsLogRE = regexp.MustCompile(
	`Failed to watch|failed to watch|Failed to list|failed to list|Unauthorized`)

// logHit returns the first last-10m log line matching the informer
// death signature ("" = clean/unreadable). Bounded to 8s / 256KiB.
// A stream/read failure is inconclusive, not clean — logged so a
// broken pod-log path (RBAC, API flap) cannot silently disable
// layer 1 while layers 2/3 keep reporting "fresh". The read rides
// the shared kube.ReadPodLogTail fetch: the caller carries only the
// pod name, so the stub pod's empty spec resolves the container to
// "" — the same apiserver-default request the raw GetLogs made.
func (w *coreDNSWatchdog) logHit(ctx context.Context, pod string) string {
	log := logf.FromContext(ctx)
	var hit string
	_, err := kube.ReadPodLogTail(ctx, w.cs,
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: corednsNS, Name: pod}},
		kube.PodLogOpts{
			SinceSeconds: corednsLogSinceS,
			MaxBytes:     corednsMaxLogBytes,
			Timeout:      8 * time.Second,
		}, func(line string) bool {
			if corednsLogRE.MatchString(line) {
				hit = line
				return true
			}
			return false
		})
	if err != nil {
		log.Info("log: cannot stream pod logs — layer 1 inconclusive", "pod", pod, "error", err)
		return ""
	}
	return hit
}

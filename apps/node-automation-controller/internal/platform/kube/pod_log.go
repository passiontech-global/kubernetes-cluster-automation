// pod_log.go — the shared bounded pod-log readers: ReadPodLogText fetches a
// bounded GetLogs tail (ctx timeout, optional TailLines/SinceSeconds,
// a trailing-byte cap that keeps the NEWEST lines) and returns the raw
// text; ReadPodLogTail is
// ReadPodLogText plus a per-line match that stops at the first hit. The
// pod log-tail signature scanners (cloudflared QUIC edge-dial storm,
// linkerd-h2 stream storm, scylla gossip/raft stall, postgres WAL
// archive, ...) share this one fetch path instead of hand-rolling
// GetLogs plumbing; callers that post-process the blob rather than
// match per line call ReadPodLogText directly. A fetch/read failure is
// inconclusive, NOT healthy, so the error is returned for the caller
// to log rather than reading "no match" as clean — the posture every
// reference site documents.
package kube

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
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

// DefaultPodLogMaxBytes bounds ReadPodLogText and readPodLogTailBytes when
// PodLogOpts.MaxBytes <= 0 so an unbounded GetLogs stream cannot OOM
// the controller.
const DefaultPodLogMaxBytes int64 = 1 << 20 // 1 MiB

// PodLogOpts bounds one pod-log read. TailLines/SinceSeconds mirror
// the PodLogOptions fields; <=0 leaves the bound off the request (the
// apiserver's own default). MaxBytes caps the streamed tail (values <=0
// default to DefaultPodLogMaxBytes, 1 MiB, keeping the newest trailing
// bytes), and Timeout bounds the whole fetch with a ctx deadline.
type PodLogOpts struct {
	// Container targets one container; "" resolves via
	// ResolveDefaultContainer — required on multi-container pods,
	// where an empty Container is an HTTP 400 rather than a default.
	Container    string
	TailLines    int64
	SinceSeconds int64
	MaxBytes     int64
	Timeout      time.Duration
	// Timestamps requests kubelet's per-line RFC3339Nano prefix —
	// the freshness gate log-signature checks use to prove a
	// matching line was written AFTER the pod's previous scan
	// (a SinceSeconds window overlaps across sweeps, so without
	// line timestamps an old error reads as a live one for
	// window/sweep-interval extra cycles).
	Timestamps bool
	// Previous reads the previous terminated container's logs (for
	// CrashLoopBackOff diagnostics).
	Previous bool
}

// ReadPodLogText fetches the bounded pod-log read for one pod container
// and returns the text. Blob consumers (whole-tail signature scans,
// raw text audits) call this; ReadPodLogTail layers the per-line match.
func ReadPodLogText(ctx context.Context, cs kubernetes.Interface,
	pod *corev1.Pod, o PodLogOpts) (string, error) {

	lctx := ctx
	if o.Timeout > 0 {
		var cancel context.CancelFunc
		lctx, cancel = context.WithTimeout(ctx, o.Timeout)
		defer cancel()
	}
	logOpts := &corev1.PodLogOptions{
		Container: ResolveDefaultContainer(pod, o.Container),
	}
	if o.TailLines > 0 {
		logOpts.TailLines = &o.TailLines
	}
	if o.SinceSeconds > 0 {
		logOpts.SinceSeconds = &o.SinceSeconds
	}
	if o.Timestamps {
		logOpts.Timestamps = true
	}
	if o.Previous {
		logOpts.Previous = true
	}
	stream, err := cs.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, logOpts).Stream(lctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = stream.Close() }()
	maxBytes := o.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultPodLogMaxBytes
	}
	return readPodLogTailBytes(stream, maxBytes)
}

// readPodLogTailBytes reads the stream keeping only its LAST
// maxBytes. Kubelet streams log lines oldest→newest, so the
// head-truncating io.LimitReader every caller used to hand-roll
// keeps the OLDEST bytes and silently drops the NEWEST lines —
// precisely the freshness evidence the log-signature gates weigh
// (a capped tail that lost its newest lines reads as "no fresh
// evidence" and the check goes silent on a live incident). The
// ring keeps memory bounded at ~2×maxBytes: bytes.Buffer.Next
// discards from the front after each chunk lands.
func readPodLogTailBytes(stream io.Reader, maxBytes int64) (string, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultPodLogMaxBytes
	}
	var buf bytes.Buffer
	tmp := make([]byte, 32*1024)
	// headPartial is set while the buffer's first line is a fragment
	// whose timestamp head was cut by an earlier byte-count trim.
	// Newlines can arrive in later (small) Read chunks, so the cut
	// cannot always be finalized in the same iteration.
	headPartial := false
	for {
		n, err := stream.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
			if int64(buf.Len()) > maxBytes {
				data := buf.Bytes()
				keepFrom := buf.Len() - int(maxBytes)
				if keepFrom > 0 && data[keepFrom-1] != '\n' {
					// The cut lands mid-line: never expose that
					// fragment as line 0 (its RFC3339 prefix is
					// gone and PodLogLineTS callers would read a
					// signature match on it as freshly written).
					// Prefer the next newline (discard the whole
					// fragment). When a short Read has not delivered
					// it yet, keep the bounded tail and mark the
					// head partial — the cut is finalized at EOF or
					// on a later read once the newline lands, never
					// by growing the ring past its byte cap.
					if nl := bytes.IndexByte(data[keepFrom:], '\n'); nl >= 0 {
						keepFrom += nl + 1
						headPartial = false
					} else {
						headPartial = true
					}
				} else {
					headPartial = false
				}
				buf.Next(keepFrom)
			}
		}
		if err != nil {
			if err != io.EOF {
				return "", err
			}
			if headPartial {
				// No complete line ever followed the cut — a
				// timestamp-less fragment must not be matched as
				// fresh evidence.
				if nl := bytes.IndexByte(buf.Bytes(), '\n'); nl >= 0 {
					return buf.String()[nl+1:], nil
				}
				return "", nil
			}
			return buf.String(), nil
		}
	}
}

// PodLogLineTS parses the RFC3339Nano timestamp prefix kubelet adds
// to every line when PodLogOptions.Timestamps is set ("<ts> <msg>").
// ok=false on any other shape — callers treat an unparseable
// matching line as FRESH (fail toward alerting, never toward
// silence).
func PodLogLineTS(line string) (ts time.Time, ok bool) {
	i := strings.IndexByte(line, ' ')
	if i <= 0 {
		return time.Time{}, false
	}
	ts, err := time.Parse(time.RFC3339Nano, line[:i])
	if err != nil {
		return time.Time{}, false
	}
	return ts, true
}

// ReadPodLogTailTimed is ReadPodLogTail plus timestamp freshness:
// it scans EVERY line (no early stop — the newest hit is what the
// freshness gate needs, and the tail is chronological so matches
// arrive oldest→newest) and returns two clocks: newest is the newest
// timestamp among the lines match accepted (the per-signal
// freshness evidence), streamNewest is the newest timestamp on ANY
// line read (the scan-boundary clock — storing the controller's
// own `now` instead would compare kubelet stamps against the wrong
// clock domain). matched reports whether any line matched; both
// timestamps are zero when Timestamps was off or no line carried a
// parseable stamp. Callers gate on newest.After(lastScan) to prove
// the signal post-dates the pod's previous sweep, and advance
// lastScan to streamNewest so the boundary lives in the kubelet's
// clock domain.
func ReadPodLogTailTimed(ctx context.Context, cs kubernetes.Interface,
	pod *corev1.Pod, o PodLogOpts,
	match func(line string) bool) (matched bool, newest, streamNewest time.Time, err error) {

	data, err := ReadPodLogText(ctx, cs, pod, o)
	if err != nil {
		return false, time.Time{}, time.Time{}, err
	}
	for line := range strings.SplitSeq(data, "\n") {
		if ts, ok := PodLogLineTS(line); ok && ts.After(streamNewest) {
			streamNewest = ts
		}
		if !match(line) {
			continue
		}
		matched = true
		if ts, ok := PodLogLineTS(line); ok && ts.After(newest) {
			newest = ts
		}
	}
	return matched, newest, streamNewest, nil
}

// ReadPodLogTail fetches the last bounded read of one pod container's log
// and reports whether any line satisfies match. The scan stops at the
// first matching line — a caller needing the match's detail closes
// over it inside match (the WAL guard captures its reason string).
// Lines are matched verbatim: case-folding/marker sets stay with the
// caller (cloudflared/linkerd lower-case per line, scylla regexes
// case-sensitively).
func ReadPodLogTail(ctx context.Context, cs kubernetes.Interface,
	pod *corev1.Pod, o PodLogOpts, match func(line string) bool) (bool, error) {

	data, err := ReadPodLogText(ctx, cs, pod, o)
	if err != nil {
		return false, err
	}
	for line := range strings.SplitSeq(data, "\n") {
		if match(line) {
			return true, nil
		}
	}
	return false, nil
}

// PodLogScan is one pod's fan-out result: the scan's value (a matched
// reason string, collected markers, ...) and its error. A fetch/read
// failure lands in Err — the caller logs it per pod rather than
// reading "no match" as clean (the inconclusive-not-healthy posture
// every log-scanning check documents); Err is never wrapped, so
// callers can apierrors-classify it exactly as ReadPodLogTail
// returned it.
type PodLogScan[T any] struct {
	Value T
	Err   error
}

// ScanPodLogs fans a bounded worker pool over pods, fetching each
// pod's bounded log tail through the caller's scan closure (which
// composes PodLogOpts + the per-line match itself) and collecting the
// indexed results — out[i] corresponds to pods[i]. Each fetch is a
// kubelet round-trip (the sweep's slowest read), so the pool spawns
// at most min(workers, len(pods)) goroutines instead of one per
// candidate; the result slice is written only at the worker's own
// index, so no locking beyond the errgroup barrier. A panic inside
// one pod's scan reads as that pod's inconclusive scan — never a
// process crash. The pool does NOT cancel sibling scans on an error:
// every pod's verdict is collected (the caller decides per pod).
func ScanPodLogs[T any](ctx context.Context,
	pods []*corev1.Pod, workers int,
	scan func(ctx context.Context, pod *corev1.Pod) (T, error)) []PodLogScan[T] {

	out := make([]PodLogScan[T], len(pods))
	if workers <= 0 {
		workers = 1
	}
	var g errgroup.Group
	g.SetLimit(workers)
	for i := range pods {
		pod := pods[i]
		g.Go(func() error {
			defer func() {
				if r := recover(); r != nil {
					out[i] = PodLogScan[T]{
						Err: fmt.Errorf("pod log scan panicked: %v", r)}
				}
			}()
			v, err := scan(ctx, pod)
			out[i] = PodLogScan[T]{Value: v, Err: err}
			return nil
		})
	}
	_ = g.Wait()
	return out
}

// kubelet_stats.go — the kubelet stats/summary side of the janitor:
// the typed stats projection (cjStats), the wipe-decision math that
// turns a summary + baseline annotation into workdir GiB
// (readStats), and the production nodeStatsReader that pulls the
// summary through the apiserver node proxy (split out of
// concourse_janitor.go — see its header for the module contract).
package concoursejanitor

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
)

// ---------------------------------------------------------------------------
// Stats — replaces the read_stats() sed pipeline.
// ---------------------------------------------------------------------------

const gib = 1024 * 1024 * 1024

// cjStats is the typed projection of a pod's disk reading; the *OK
// flags mirror the bash "-n $VAR" checks (empty = unknown → fail-open).
type cjStats struct {
	node       string
	usedGiB    int64
	capGiB     int64
	pct        int64
	nodefsOK   bool
	workdirGiB int64
	workdirOK  bool
}

// readStats turns kubelet stats/summary + the baseline annotation
// into the numbers the wipe decision needs.
func (j *concourseWorkdirJanitor) readStats(ctx context.Context, pod *corev1.Pod) cjStats {
	s := cjStats{node: pod.Spec.NodeName}
	if s.node == "" {
		return s
	}
	cctx, cancel := context.WithTimeout(ctx, j.reqTimeout)
	defer cancel()
	used, capBytes, imgUsed, err := j.stats.Summary(cctx, s.node)
	if err != nil {
		// Fail-open is deliberate, but a persistently-broken
		// stats/summary path must show up on the error metric —
		// every pod will blind-wipe until it is fixed.
		metrics.IncError(j.queue)
		logf.FromContext(ctx).Info(
			"WARN: stats/summary unreadable — disk unknown, fail-open",
			"pod", pod.Name, "node", s.node, "error", err)
		return s
	}
	if used >= 0 && capBytes > 0 {
		s.usedGiB = used / gib
		s.capGiB = capBytes / gib
		s.pct = used * 100 / capBytes
		s.nodefsOK = true
	}
	if !s.nodefsOK {
		return s
	}
	// workdir = nodefs_used - baseline. Baseline comes from the
	// annotation when it is a non-negative integer (bash case-match
	// `''|*[!0-9]*`), else imageFs_used + 32GiB for OS/k0s/other pods.
	var wd int64
	switch base, err := strconv.ParseUint(pod.Annotations[cjBaselineAnno], 10, 64); {
	case err == nil:
		wd = s.usedGiB - int64(base)
	case imgUsed >= 0:
		if anno := pod.Annotations[cjBaselineAnno]; anno != "" {
			logf.FromContext(ctx).Info(
				"WARN: baseline annotation invalid — estimating from imageFs",
				"pod", pod.Name, "annotation", anno,
				"osBaselineGiB", cjOSBaselineGiB)
		}
		wd = s.usedGiB - imgUsed/gib - cjOSBaselineGiB
	default:
		// No baseline path at all → workdir unknown → fail-open wipe.
		logf.FromContext(ctx).Info(
			"WARN: no usable baseline (imageFs missing) — workdir unknown, fail-open",
			"pod", pod.Name, "annotation", pod.Annotations[cjBaselineAnno])
		return s
	}
	if wd < 0 {
		wd = 0
	}
	s.workdirGiB = wd
	s.workdirOK = true
	return s
}

// ---------------------------------------------------------------------------
// Production implementations of the seams.
// ---------------------------------------------------------------------------

// kubeletSummary is the typed shape of GET
// /api/v1/nodes/<node>/proxy/stats/summary — replaces the bash sed
// pipeline that carved pretty-printed "fs"/"imageFs" blocks out of
// `kubectl get --raw` output.
type kubeletSummary struct {
	Node struct {
		FS struct {
			UsedBytes     *int64 `json:"usedBytes"`
			CapacityBytes *int64 `json:"capacityBytes"`
		} `json:"fs"`
		Runtime struct {
			ImageFS struct {
				UsedBytes *int64 `json:"usedBytes"`
			} `json:"imageFs"`
		} `json:"runtime"`
	} `json:"node"`
}

// kubeletStatsReader is the production nodeStatsReader — the apiserver
// node-proxy subresource, same path the bash hit via `get --raw`.
type kubeletStatsReader struct {
	cs kubernetes.Interface
}

func (r *kubeletStatsReader) Summary(ctx context.Context, node string) (nodefsUsed, nodefsCap, imageFsUsed int64, err error) {
	raw, err := r.cs.CoreV1().RESTClient().Get().
		Resource("nodes").Name(node).
		SubResource("proxy").Suffix("stats", "summary").
		DoRaw(ctx)
	if err != nil {
		return 0, 0, 0, err
	}
	var s kubeletSummary
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, 0, 0, fmt.Errorf("parse stats/summary for node %s: %w", node, err)
	}
	deref := func(p *int64) int64 {
		if p == nil {
			return -1 // absent counter — not a real 0
		}
		return *p
	}
	return deref(s.Node.FS.UsedBytes), deref(s.Node.FS.CapacityBytes), deref(s.Node.Runtime.ImageFS.UsedBytes), nil
}

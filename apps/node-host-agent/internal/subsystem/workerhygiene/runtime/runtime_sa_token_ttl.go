// runtime_sa_token_ttl.go — the sa-token-ttl guard
// (wdeps.CheckSATokenTTL, W13-CP3). BoundServiceAccountTokenVolume
// projected tokens are rotated by kubelet's volumeManager on an
// ~80%-of-TTL refresh. When the volume plugin stalls (watch
// backlog, remount queue wedge) the token on disk quietly nears
// expiry: the pod keeps Running and every API call starts 401ing —
// the signature is a projected token file with a TTL under the
// floor (default 600s). The check scans
// <PodsDir>/<uid>/volumes/kubernetes.io~projected/<vol>/token,
// decodes each JWT's exp claim WITHOUT logging token contents,
// exports node_agent_sa_token_min_ttl_seconds, and for a Running
// pod under the floor emits SATokenRotationStalled + touches the
// node-ops.passiontech.io/token-resync-at pod annotation so the
// kubelet remount/reconcile loop re-syncs the volume.
package runtime

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// saTokenResyncAnnotation is the nudge the check stamps on the pod —
// kubelet's volumeManager observes pod updates and re-syncs the
// projected volume, remounting a freshly-issued token.
const saTokenResyncAnnotation = "node-ops.passiontech.io/token-resync-at"

// saTokenNudgeCooldown is the per-pod re-nudge budget — the
// annotation's own timestamp is the dedupe (a resync that landed
// already carries a fresh stamp), so no last-* file is needed.
const saTokenNudgeCooldown = 15 * time.Minute

// SATokenTTLCheck is the W13-CP3 projected-token expiry guard as a
// Check — stateless: the nudge dedupe rides the pod annotation.
type SATokenTTLCheck struct{ d *wdeps.Deps }

// Name returns the check label / WD_SIG key.
func (c *SATokenTTLCheck) Name() string { return wdeps.CheckSATokenTTL }

// jwtExpUnix extracts the exp claim from a compact JWT — payload
// segment only, base64url-decoded; ok=false on any malformed input.
// The token CONTENTS are never logged anywhere in this package.
func jwtExpUnix(tok string) (int64, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return 0, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return 0, false
	}
	return claims.Exp, true
}

// projectedTokenFiles lists the token paths under one pod's
// kubernetes.io~projected volume dirs — kubelet mounts each
// projected volume under volumes/kubernetes.io~projected/<vol>/.
func projectedTokenFiles(podDir string) []string {
	m, err := filepath.Glob(filepath.Join(podDir, "volumes",
		"kubernetes.io~projected", "*", "token"))
	if err != nil {
		return nil
	}
	return m
}

// Run executes one sa-token-ttl round.
func (c *SATokenTTLCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckSATokenTTL, "gated").Inc()
		return
	}
	podDirs, err := os.ReadDir(c.d.Cfg.PodsDir)
	if err != nil {
		c.d.Cycles.WithLabelValues(wdeps.CheckSATokenTTL, "abort").Inc()
		return
	}
	podByUID := map[string]*corev1.Pod{}
	for i := range e.Pods {
		podByUID[string(e.Pods[i].UID)] = &e.Pods[i]
	}
	now := c.d.Cfg.Seams.Host.NowFn()
	minTTL := -1.0
	for _, ent := range podDirs {
		if !ent.IsDir() {
			continue
		}
		uid := ent.Name()
		pod := podByUID[uid]
		for _, tf := range projectedTokenFiles(
			filepath.Join(c.d.Cfg.PodsDir, uid)) {
			data, err := os.ReadFile(tf)
			if err != nil {
				continue
			}
			exp, ok := jwtExpUnix(strings.TrimSpace(string(data)))
			if !ok {
				continue
			}
			ttl := float64(exp - now.Unix())
			if minTTL < 0 || ttl < minTTL {
				minTTL = ttl
			}
			// Only a Running pod's near-expiry token is an
			// incident — a Terminating/Succeeded pod's stale token
			// is cleanup debt, not a stalled rotation.
			if pod == nil || pod.Status.Phase != corev1.PodRunning ||
				pod.DeletionTimestamp != nil ||
				ttl >= float64(c.d.Cfg.Runtime.SATokenMinTTLSec) {
				continue
			}
			c.stall(ctx, pod, tf, int64(ttl))
		}
	}
	c.d.SATokenMinTTLSec = minTTL
	c.d.Cycles.WithLabelValues(wdeps.CheckSATokenTTL, "ok").Inc()
}

// stall emits the SATokenRotationStalled event and stamps the
// resync annotation — the annotation's own timestamp dedupes
// nudges (a landed resync already refreshed it).
func (c *SATokenTTLCheck) stall(ctx context.Context, pod *corev1.Pod,
	tokenFile string, ttl int64) {
	now := c.d.Cfg.Seams.Host.NowFn()
	// Event first — it reports regardless of the nudge dedupe.
	c.emitEvent(ctx, pod, ttl)
	if c.d.Cfg.Client == nil {
		return
	}
	// Dedupe on the LIVE pod's annotation — the CycleEnv pod is a
	// LIST snapshot, so an annotation stamped last cycle is only
	// visible on a fresh read.
	live, err := c.d.Cfg.Client.CoreV1().Pods(pod.Namespace).
		Get(ctx, pod.Name, metav1.GetOptions{})
	if err == nil && live != nil {
		pod = live
	}
	if prev := pod.Annotations[saTokenResyncAnnotation]; prev != "" {
		if t, err := strconv.ParseInt(prev, 10, 64); err == nil &&
			now.Unix()-t < int64(saTokenNudgeCooldown.Seconds()) {
			return // nudged recently — let the in-flight resync land
		}
	}
	// Patch ONLY the annotation — merge-patch keeps every other
	// field untouched; the kubelet volumeManager sees the pod
	// update and re-syncs the projected volume.
	patch := fmt.Sprintf(`{"metadata":{"annotations":{%q:%q}}}`,
		saTokenResyncAnnotation, strconv.FormatInt(now.Unix(), 10))
	if _, err := c.d.Cfg.Client.CoreV1().Pods(pod.Namespace).Patch(
		ctx, pod.Name, types.MergePatchType, []byte(patch),
		metav1.PatchOptions{}); err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: sa-token-ttl resync nudge %s/%s failed: %v",
			pod.Namespace, pod.Name, err))
		return
	}
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: sa-token-ttl nudged %s/%s (token-resync-at) — projected token %s ttl=%ds",
		pod.Namespace, pod.Name, filepath.Base(filepath.Dir(tokenFile)), ttl))
	c.d.Actions.WithLabelValues(wdeps.CheckSATokenTTL, "nudge").Inc()
}

// emitEvent creates the SATokenRotationStalled Warning event on the
// pod — events.v1 shape like the SystemOOMVictim emitter.
func (c *SATokenTTLCheck) emitEvent(ctx context.Context, pod *corev1.Pod,
	ttl int64) {
	if c.d.Cfg.Client == nil {
		return
	}
	now := c.d.Cfg.Seams.Host.NowFn()
	ev := &eventsv1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s.%x", pod.Name, now.UnixNano()),
			Namespace: pod.Namespace,
		},
		EventTime: metav1.NewMicroTime(now),
		Reason:    "SATokenRotationStalled",
		Note: fmt.Sprintf(
			"projected service-account token ttl=%ds < %ds floor — kubelet volume rotation appears stalled, resync nudged",
			ttl, c.d.Cfg.Runtime.SATokenMinTTLSec),
		Type:                corev1.EventTypeWarning,
		ReportingController: "node-host-agent",
		ReportingInstance:   c.d.Cfg.NodeName,
		Action:              "SATokenRotationStalled",
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Pod",
			Namespace:  pod.Namespace,
			Name:       pod.Name,
			UID:        pod.UID,
		},
	}
	if _, err := c.d.Cfg.Client.EventsV1().Events(pod.Namespace).
		Create(ctx, ev, metav1.CreateOptions{}); err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: SATokenRotationStalled event create failed for %s/%s: %v",
			pod.Namespace, pod.Name, err))
	}
}

// runtime_overlayfs_stale.go — the overlayfs-stale-mount guard
// (wdeps.CheckOverlayFSStale). An ESTALE / missing-lowerdir overlay
// mount failure does not heal by kubelet retrying the same corrupt
// snapshot — the layer on disk IS the problem. After the evidence
// persists for ConsecNeeded cycles the check removes the image
// through the same ctrRmImage seam + shared 15m last-ctr-image-rm
// budget the corrupted-image healer uses, so kubelet's next pull
// re-fetches the layer.
package runtime

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/ctr"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// overlayStaleRe matches the overlayfs mount-failure signatures a
// stuck container surfaces in its Waiting message (ESTALE from a
// stale NFS-backed lowerdir, a lowerdir path containerd lost, or
// the rwlayer create error the CRI reports).
var overlayStaleRe = regexp.MustCompile(
	`ESTALE|stale file handle|failed to mount overlay: no such file or directory|failed to create ?rwlayer`)

type OverlayFSStaleCheck struct {
	d     *wdeps.Deps
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *OverlayFSStaleCheck) Name() string { return wdeps.CheckOverlayFSStale }

// Run executes one overlayfs-stale round.
func (c *OverlayFSStaleCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckOverlayFSStale, "gated").Inc()
		return
	}
	if !e.APIOK {
		// Inconclusive — same "keep state, never act" rule as the
		// other pod-list checks.
		c.d.Cycles.WithLabelValues(wdeps.CheckOverlayFSStale, "abort").Inc()
		return
	}
	stale := 0
	seen := map[string]bool{}
	for i := range e.Pods {
		p := &e.Pods[i]
		statuses := slices.Concat(p.Status.InitContainerStatuses,
			p.Status.ContainerStatuses, p.Status.EphemeralContainerStatuses)
		match := false
		for _, cs := range statuses {
			if w := cs.State.Waiting; w != nil &&
				overlayStaleRe.MatchString(w.Message) {
				match = true
				break
			}
		}
		// A pod that exhausted retries reports the same mount
		// failure at pod level — cover that too (the container
		// Waiting state is already gone).
		if !match && p.Status.Phase == corev1.PodFailed &&
			overlayStaleRe.MatchString(p.Status.Message) {
			match = true
		}
		if !match {
			continue
		}
		stale++
		// The image refs to rm come from the pod's OWN statuses —
		// a stale lowerdir is a layer of the image the pod asked
		// for. Normalized like the corrupted-image healer (ctr rm
		// matches store names verbatim).
		for _, cs := range statuses {
			if cs.Image != "" {
				seen[ctr.NormalizeCRIImageName(cs.Image)] = true
			}
			if cs.ImageID != "" {
				seen[ctr.NormalizeCRIImageName(cs.ImageID)] = true
			}
		}
	}
	if stale == 0 {
		c.fails = 0
		c.d.Cycles.WithLabelValues(wdeps.CheckOverlayFSStale, "ok").Inc()
		return
	}
	c.fails++
	c.d.OverlayFSStaleMounts += int64(stale)
	if c.fails < c.d.Cfg.ConsecNeeded {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: overlayfs-stale-mount stale_pods=%d (check %d/%d)",
			stale, c.fails, c.d.Cfg.ConsecNeeded))
		c.d.Cycles.WithLabelValues(wdeps.CheckOverlayFSStale, "ok").Inc()
		return
	}
	if len(seen) == 0 {
		// Stale evidence but no image ref to act on — counted and
		// logged, nothing removable.
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: overlayfs-stale-mount stale_pods=%d but no image refs", stale))
		c.d.Cycles.WithLabelValues(wdeps.CheckOverlayFSStale, "ok").Inc()
		return
	}
	images := make([]string, 0, len(seen))
	for img := range seen {
		images = append(images, img)
	}
	sort.Strings(images)
	if !c.d.State.RateTrySpend("last-ctr-image-rm", wdeps.CtrImageRmInterval) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: overlayfs-stale-mount image(s) %s - in rm cooldown (<15m), skip",
			strings.Join(images, " ")))
		c.d.Cycles.WithLabelValues(wdeps.CheckOverlayFSStale, "ok").Inc()
		return
	}
	// Budget spent atomically BEFORE acting (lib.sh rate_spend
	// parity): a failed rm still consumed it.
	for _, img := range images {
		if err := c.d.Cfg.Seams.CtrRmImage(ctx, img); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: overlayfs-stale-mount image rm %s failed: %v", img, err))
			continue
		}
		c.d.State.AppendLog("ACTION: overlayfs-stale-mount removed image " + img)
		c.d.Actions.WithLabelValues(wdeps.CheckOverlayFSStale, "image_rm").Inc()
	}
	c.d.Cycles.WithLabelValues(wdeps.CheckOverlayFSStale, "ok").Inc()
}

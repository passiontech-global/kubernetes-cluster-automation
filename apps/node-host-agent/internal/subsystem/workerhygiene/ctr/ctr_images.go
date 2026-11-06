// ctr_images.go — the 37 ctr-image-healer check: pods stuck Waiting
// on a corrupted containerd layer/content-store error get the broken
// image removed (`k0s ctr images rm --sync`) so kubelet's next pull
// re-fetches the missing layer — the pod recovers without a reboot.
// Also owns NormalizeCRIImageName (shared with the runtime
// overlayfs-stale healer, which builds its rm set the same way).
package ctr

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

var (
	// Corrupted containerd layer/content-store signatures inside a
	// pod's Waiting message (37) — a missing blob/snapshot never
	// heals by retrying the pull; the image record must go. The
	// last four are corrupted-on-disk-layer signatures: an ext4
	// "structure needs cleaning" mount failure, a shim task dying
	// on EIO, a truncated .so ("file too short"), and the
	// exec-format class (0-byte truncated binary after hard-reset —
	// heals on repull; a wrong-arch image does NOT, which is why
	// exec-format refs get the once-per-image healed map).
	corruptImageRe = regexp.MustCompile(
		`content digest sha256:[0-9a-f]+: not found|` +
			`failed to extract layer|` +
			`parent snapshot .* does not exist|` +
			`failed to mount .* structure needs cleaning|` +
			`failed to create shim task: .* input/output error|` +
			`error while loading shared libraries: .* file too short|` +
			`exec format error`)

	// execFormatRe is the once-per-image subset — a wrong-arch
	// image can never heal by re-pulling, so each ref is deleted
	// at most once (see CtrImagesCheck.execFormatHealed).
	execFormatRe = regexp.MustCompile(`exec format error`)
)

// corruptImageWaitingReason mirrors the shell reason list — pull
// failures (ErrImagePull/ImagePullBackOff), create failures
// (CreateContainerError) and run/start failures
// (RunContainerError/StartError — the on-disk corrupt-layer and
// exec-format signatures surface there, not at pull).
func corruptImageWaitingReason(r string) bool {
	switch r {
	case "CreateContainerError", "ErrImagePull", "ImagePullBackOff",
		"RunContainerError", "StartError":
		return true
	}
	return false
}

// NormalizeCRIImageName rewrites a kubelet-reported image spec into
// the canonical ref containerd's CRI plugin stored it under. `ctr
// images rm` does zero normalization — it matches the image store's
// name verbatim — while the CRI plugin canonicalizes at pull time
// (distribution/reference splitDockerDomain):
//   - first path segment without '.'/':' that isn't "localhost" is a
//     repo path component, not a registry → prepend "docker.io/";
//   - a single-segment repo path under docker.io gets "library/"
//     inserted (nginx → docker.io/library/nginx) — private-registry
//     single-segment paths are left alone;
//   - a name:tag@sha256:… ref canonicalizes to name@sha256:… (the
//     digest wins, the tag is dropped — only a ':' after the last '/'
//     is a tag; a registry port like host:5000/… is not).
//
// Already-canonical refs pass through unchanged (idempotent).
func NormalizeCRIImageName(spec string) string {
	name, digest := spec, ""
	if i := strings.IndexByte(spec, '@'); i >= 0 {
		name, digest = spec[:i], spec[i:]
		if j := strings.LastIndexByte(name, ':'); j > strings.LastIndexByte(name, '/') {
			name = name[:j]
		}
	}
	domain, rest := "", name
	if i := strings.IndexByte(name, '/'); i >= 0 {
		if head := name[:i]; strings.ContainsAny(head, ".:") || head == "localhost" {
			domain, rest = head, name[i+1:]
		}
	}
	if domain == "" {
		domain, rest = "docker.io", name
	}
	if domain == "docker.io" && !strings.ContainsRune(rest, '/') {
		rest = "library/" + rest
	}
	return domain + "/" + rest + digest
}

// CtrImagesCheck scans this node's pods for containers stuck Waiting
// on a corrupted containerd layer/content-store error and removes the
// broken image (`k0s ctr images rm --sync`) so kubelet's next pull
// re-fetches the missing layer — the pod recovers without a reboot.
// Removal is idempotent (ctr tolerates re-pulls of a pruned ref), so
// unlike the restart checks there is no consecutive gate: the 15m
// last-ctr-image-rm budget alone bounds the churn, and one spend
// covers the whole batch of matching images found in a cycle.
//
// Two containerd quirks shape the rm set:
//   - cs.Image is the SPEC name the pod asked for, but the CRI plugin
//     normalized it at pull (docker.io/ + library/ insertion, digest
//     canonicalization). `ctr images rm` matches store names verbatim
//     and exits 0 with only a warning on a miss — an unnormalized
//     "nginx:1.25" rm silently no-ops while the corrupt record stays.
//     Every spec is run through NormalizeCRIImageName first.
//   - The image store keeps one record per ref: the tag record and the
//     repoDigest record (cs.ImageID, e.g. docker.io/library/nginx@…)
//     are separate entries. Removing only the tag leaves the digest
//     record resolvable, so both are removed per corrupted container.
//
// Normalization is preferred over `ctr images ls` reconciliation —
// one exec per ref keeps the seam shape; a normalized name that still
// isn't in the store just makes ctr warn and exit 0 (accepted).
//
// execFormatHealed is the once-per-image ledger for the exec-format
// class: a 0-byte truncated binary (hard-reset mid-write) heals on
// the repull the rm triggers, but a genuinely wrong-arch image
// repulls the SAME un-runnable ref — deleting it every 15m would
// loop forever. Each normalized ref is deleted at most once for an
// exec-format signature; other signatures stay unlimited (bounded
// by the shared budget only).
type CtrImagesCheck struct {
	d                *wdeps.Deps
	execFormatHealed map[string]bool
}

// Name returns the check label / WD_SIG key.
func (c *CtrImagesCheck) Name() string { return wdeps.CheckCtrImages }

// Run executes one ctr-image-healer round.
func (c *CtrImagesCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckCtrImages, "gated").Inc()
		return
	}
	if !e.APIOK {
		// Inconclusive — same "keep state, never act" rule as the
		// other pod-list checks.
		c.d.Cycles.WithLabelValues(wdeps.CheckCtrImages, "abort").Inc()
		return
	}
	// Dedupe refs across pods and statuses — several containers
	// pinned to one corrupted image need a single rm, not one each.
	seen := map[string]bool{}
	execFmtRefs := map[string]bool{}
	if c.execFormatHealed == nil {
		c.execFormatHealed = map[string]bool{}
	}
	for i := range e.Pods {
		p := &e.Pods[i]
		statuses := slices.Concat(p.Status.InitContainerStatuses,
			p.Status.ContainerStatuses, p.Status.EphemeralContainerStatuses)
		for _, cs := range statuses {
			w := cs.State.Waiting
			if w == nil || !corruptImageWaitingReason(w.Reason) ||
				!corruptImageRe.MatchString(w.Message) {
				continue
			}
			// Exec-format refs heal once — the ledger marks the ref
			// only when the rm is actually attempted below (marking
			// at selection would burn the single shot when the rm
			// budget is in cooldown; a failed rm still counts since a
			// persistent rm failure on a wrong-arch image must not
			// loop either).
			execFmt := execFormatRe.MatchString(w.Message)
			for _, spec := range []string{cs.Image, cs.ImageID} {
				if spec == "" {
					continue
				}
				ref := NormalizeCRIImageName(spec)
				if execFmt {
					if c.execFormatHealed[ref] {
						continue
					}
					execFmtRefs[ref] = true
				}
				seen[ref] = true
			}
		}
	}
	if len(seen) == 0 {
		c.d.Cycles.WithLabelValues(wdeps.CheckCtrImages, "ok").Inc()
		return
	}
	images := make([]string, 0, len(seen))
	for img := range seen {
		images = append(images, img)
	}
	sort.Strings(images) // deterministic order — same convention as dnsStale
	if !c.d.State.RateTrySpend("last-ctr-image-rm", wdeps.CtrImageRmInterval) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: ctr-image-healer corrupted image(s) %s - in rm cooldown (<15m), skip",
			strings.Join(images, " ")))
		c.d.Cycles.WithLabelValues(wdeps.CheckCtrImages, "ok").Inc()
		return
	}
	// Budget spent atomically BEFORE acting (lib.sh rate_spend
	// parity): a failed rm still consumed the budget.
	for _, img := range images {
		if execFmtRefs[img] {
			// Burn the ref's single exec-format heal only now that
			// the rm will actually run — a cooldown skip above must
			// not consume it.
			c.execFormatHealed[img] = true
		}
		if err := c.d.Cfg.Seams.CtrRmImage(ctx, img); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: ctr image rm %s failed: %v", img, err))
			continue
		}
		// NPD contract: "removed corrupted image" feeds the
		// CorruptedImageRemoved filelog pattern.
		c.d.State.AppendLog("ACTION: removed corrupted image " + img)
		c.d.Actions.WithLabelValues(wdeps.CheckCtrImages, "image_rm").Inc()
	}
	c.d.Cycles.WithLabelValues(wdeps.CheckCtrImages, "ok").Inc()
}

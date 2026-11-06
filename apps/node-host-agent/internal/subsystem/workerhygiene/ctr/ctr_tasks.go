package ctr

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"golang.org/x/sys/unix"
)

const (
	contentPruneInterval = 6 * time.Hour // content-store prune budget (Wave-9)
)

var (
	// `containerd-shim-runc-v2 ... -id <64hex>` — orphan-shim task id
	// extraction (shell sed pattern).
	shimIDRe = regexp.MustCompile(`-id ([0-9a-f]{64})`)
	// cri.container-type=sandbox inside task config.json — pause
	// tasks legitimately lack log.json (shell grep -q parity).
	sandboxTypeRe = regexp.MustCompile(`cri\.container-type[^,]*sandbox`)
	// Corrupted containerd layer/content-store signatures inside a
	// pod's Waiting message (37) — a missing blob/snapshot never
	// heals by retrying the pull; the image record must go.
	corruptImageRe = regexp.MustCompile(
		`content digest sha256:[0-9a-f]+: not found|` +
			`failed to extract layer|` +
			`parent snapshot .* does not exist`)
)

// shimFlagValue extracts `-name value` / `-name=value` (double-dash
// forms tolerated) from a shim argv. ok=false when the flag is absent
// or value-less.
func shimFlagValue(argv []string, name string) (string, bool) {
	for i, a := range argv {
		if a == "-"+name || a == "--"+name {
			if i+1 < len(argv) {
				return argv[i+1], true
			}
			return "", false
		}
		if v, ok := strings.CutPrefix(a, "-"+name+"="); ok {
			return v, true
		}
		if v, ok := strings.CutPrefix(a, "--"+name+"="); ok {
			return v, true
		}
	}
	return "", false
}

// hostSidePath maps an in-pod /host-mounted path back to the path a
// host process reports — the shim's -address carries the HOST socket
// path (/run/k0s/containerd.sock) while config paths live under the
// host-root mount (/host/run/k0s/containerd.sock).
func hostSidePath(p string) string {
	if rest, ok := strings.CutPrefix(p, "/host/"); ok {
		return "/" + rest
	}
	if p == "/host" {
		return "/"
	}
	return p
}

// normalizeCtrAddr canonicalizes a containerd grpc socket address so
// a cosmetic difference can't mark our own shim foreign: the unix://
// scheme and the /var/run symlink collapse to the canonical /run path.
func normalizeCtrAddr(a string) string {
	a = strings.TrimPrefix(a, "unix://")
	if a == "" {
		return ""
	}
	a = filepath.Clean("/" + strings.TrimPrefix(a, "/"))
	if rest, ok := strings.CutPrefix(a, "/var/run/"); ok {
		a = "/run/" + rest
	}
	return a
}

// ctrShimSockets returns the host-side socket paths the k0s
// containerd is expected to listen on: the configured
// ContainerdSocket plus the path derived from CtrTaskRoot
// (…/containerd/io.containerd.runtime.v2.task/k8s.io → the sibling
// …/k0s/containerd.sock — k0s keeps the socket next to the containerd
// root dir, not inside it).
func ctrShimSockets(d *wdeps.Deps) map[string]bool {
	out := map[string]bool{}
	if s := normalizeCtrAddr(hostSidePath(d.Cfg.Ctr.Socket)); s != "" {
		out[s] = true
	}
	derived := filepath.Join(
		filepath.Dir(filepath.Dir(filepath.Dir(d.Cfg.CtrTaskRoot))),
		"containerd.sock")
	if s := normalizeCtrAddr(hostSidePath(derived)); s != "" {
		out[s] = true
	}
	return out
}

// validShimNamespace guards the per-namespace task-dir join against
// path traversal — a shim cmdline is host-controlled input.
func validShimNamespace(ns string) bool {
	return ns != "" && ns != "." && ns != ".." &&
		!strings.ContainsAny(ns, "/\\")
}

// shimTaskDir resolves the task dir a shim of namespace ns + id would
// own under THIS containerd: k8s.io is CtrTaskRoot itself, a foreign
// namespace on the same daemon lives at the sibling
// io.containerd.runtime.v2.task/<ns>/<id> dir.
func shimTaskDir(d *wdeps.Deps, ns, id string) string {
	return filepath.Join(filepath.Dir(d.Cfg.CtrTaskRoot), ns, id)
}

// ctrShimScope parses a containerd-shim-runc-v2 argv and reports the
// task id + whether the shim belongs to the containerd instance this
// agent watches. A shim is in-scope only when BOTH flags are present
// AND -address names our containerd socket — a missing/unparseable
// flag means the instance can't be verified, so the shim is treated
// as foreign (fail closed: never reap an unidentified shim).
func ctrShimScope(d *wdeps.Deps, argv []string) (ns, sid string, inScope bool) {
	m := shimIDRe.FindStringSubmatch(strings.Join(argv, " "))
	if m == nil {
		return "", "", false
	}
	ns, nsOK := shimFlagValue(argv, "namespace")
	addr, addrOK := shimFlagValue(argv, "address")
	if !nsOK || !addrOK || !validShimNamespace(ns) {
		return "", "", false
	}
	if !ctrShimSockets(d)[normalizeCtrAddr(addr)] {
		return "", "", false
	}
	return ns, m[1], true
}

// CtrTasksCheck cleans wedged containerd task dirs and orphan shims —
// the filesystem port of the shell's ctr-based checks (no ctr socket
// needed in the agent pod):
//
//   - Orphan shim: live containerd-shim-runc-v2 process scoped to THIS
//     containerd (-address names the k0s socket; -address/-namespace
//     absent or foreign → not ours, never touched) whose -id task dir
//     is gone from its namespace's task root AND the sandbox root,
//     proc age >=5m → SIGKILL (cap MaxShimKill/cycle).
//   - Wedged task dir: init.pid unreadable/dead/zombie, OR init alive
//     but log.json missing on a non-sandbox task — confirmed via a
//     wedged-seen-<id> marker persisting >=5m (the marker replaces
//     "dead >=5m": dir age can't distinguish a just-exited init from
//     a real wedge). Confirmed → SIGKILL live init + any process
//     holding the id, then remove the dir (cap MaxCtrTaskClean/cycle).
type CtrTasksCheck struct{ d *wdeps.Deps }

// Name returns the check label / WD_SIG key.
func (c *CtrTasksCheck) Name() string { return wdeps.CheckCtrTasks }

// Run executes one ctr-tasks round.
func (c *CtrTasksCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckCtrTasks, "gated").Inc()
		return
	}
	entries, err := os.ReadDir(c.d.Cfg.CtrTaskRoot)
	if err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: ctr task root %s unreadable: %v — ctr-tasks check skipped",
			c.d.Cfg.CtrTaskRoot, err))
		c.d.Cycles.WithLabelValues(wdeps.CheckCtrTasks, "abort").Inc()
		return
	}
	liveDirs := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			liveDirs[e.Name()] = true
		}
	}
	sbDirs := map[string]bool{}
	if es, err := os.ReadDir(c.d.Cfg.SandboxCtlRoot); err == nil {
		for _, e := range es {
			if e.IsDir() {
				sbDirs[e.Name()] = true
			}
		}
	}
	// Phase B — orphan shims (shell ran this FIRST: a shim whose task
	// dir vanished makes every shim-mediated kill fail forever). The
	// reaper is scoped by -address to the containerd that owns
	// CtrTaskRoot: a second containerd on the same host (host dockerd's
	// moby shims, a concourse worker's own daemon) has task dirs under
	// a DIFFERENT root, so its shims used to all read "orphan" and get
	// SIGKILLed every sweep — cold-restarting every foreign container
	// and saturating the node (NodeOverloaded incident 2026-11).
	nShim := 0
	pids := e.PidsOnce()
	for _, pid := range pids {
		if nShim >= c.d.Cfg.Ctr.MaxShimKill {
			break
		}
		argv := c.d.Proc.Cmdline(pid)
		joined := strings.Join(argv, " ")
		if !strings.Contains(joined, "containerd-shim-runc-v2") {
			continue
		}
		ns, sid, inScope := ctrShimScope(c.d, argv)
		if !inScope {
			continue
		}
		if ns == "k8s.io" {
			if liveDirs[sid] || sbDirs[sid] {
				continue
			}
		} else {
			// Foreign namespace on OUR containerd (e.g. a `ctr -n`
			// task): resolve the dir under the sibling namespace
			// root — only a genuinely missing dir is an orphan.
			if _, err := os.Stat(shimTaskDir(c.d, ns, sid)); err == nil ||
				sbDirs[sid] {
				continue
			}
		}
		if c.d.ProcAge(pid) < 5*time.Minute {
			continue
		}
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: kill orphan shim pid=%d id=%.12s ns=%s - task dir missing",
			pid, sid, ns))
		if err := c.d.Cfg.Seams.KillFn(pid, syscall.SIGKILL); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: kill orphan shim pid=%d failed: %v", pid, err))
		}
		nShim++
		c.d.Actions.WithLabelValues(wdeps.CheckCtrTasks, "shim_kill").Inc()
	}
	// Prune wedged-seen markers for dirs that disappeared between
	// runs (teardown finished or a previous cleanup won the race).
	if ms, err := filepath.Glob(
		filepath.Join(c.d.Cfg.WatchdogStateDir, "wedged-seen-*")); err == nil {
		for _, m := range ms {
			if !liveDirs[strings.TrimPrefix(filepath.Base(m), "wedged-seen-")] {
				_ = os.Remove(m)
			}
		}
	}
	// Scan task dirs → wedge candidates confirmed by a >=5m marker.
	var wedged []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		d := filepath.Join(c.d.Cfg.CtrTaskRoot, id)
		marker := "wedged-seen-" + id
		dead := false
		pidData, err := os.ReadFile(filepath.Join(d, "init.pid"))
		ipid, _ := strconv.Atoi(strings.TrimSpace(string(pidData)))
		if err != nil || ipid <= 0 || !c.d.PidLive(ipid) {
			// Unreadable init.pid = half-written dir (containerd
			// restart mid-create) or an exited init — both are
			// wedge-shaped, but a task STARTING writes init.pid a
			// few seconds after the dir: the 5m marker window absorbs
			// that race.
			dead = true
		} else if _, err := os.Stat(filepath.Join(d, "log.json")); err != nil {
			// init alive but log.json gone: runc kill fails with
			// ENOENT forever on non-sandbox tasks (pause tasks have
			// no log.json legitimately); unreadable config.json =
			// wreckage → dead too (grep miss parity).
			if cfg, err := os.ReadFile(filepath.Join(d, "config.json")); err != nil ||
				!sandboxTypeRe.Match(cfg) {
				dead = true
			}
		}
		if !dead {
			// Recovered between runs → cancel the pending confirm.
			_ = os.Remove(filepath.Join(c.d.Cfg.WatchdogStateDir, marker))
			continue
		}
		if !c.d.StateFileExists(marker) {
			c.d.State.RateSpend(marker)
			c.d.State.AppendLog(fmt.Sprintf("ctr-task-dead candidate %.12s - confirm next run", id))
			continue
		}
		if !c.d.State.RateOK(marker, 5*time.Minute) {
			continue
		}
		wedged = append(wedged, d)
	}
	nClean := 0
	for _, d := range wedged {
		id := filepath.Base(d)
		if nClean >= c.d.Cfg.Ctr.MaxTaskClean {
			c.d.State.AppendLog(fmt.Sprintf("suspect: ctr-task-wedged still pending cap=%d",
				c.d.Cfg.Ctr.MaxTaskClean))
			break
		}
		// Marker removal only once the dir is actually being
		// cleaned: a dir dropped by the cap must KEEP its
		// confirmed marker — removing it first made over-cap
		// dirs re-confirm for another 5m forever.
		_ = os.Remove(filepath.Join(c.d.Cfg.WatchdogStateDir, "wedged-seen-"+id))
		// Live init with missing log.json → SIGKILL it first so the
		// shim can drain and exit (shell's kill -9 init).
		if pidData, err := os.ReadFile(filepath.Join(d, "init.pid")); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(pidData))); err == nil &&
				pid > 0 && c.d.PidLive(pid) {
				c.d.State.AppendLog(fmt.Sprintf(
					"ACTION: kill -9 init %d of %.12s - log.json missing", pid, id))
				if err := c.d.Cfg.Seams.KillFn(pid, syscall.SIGKILL); err != nil {
					c.d.State.AppendLog(fmt.Sprintf(
						"suspect: kill init %d of %.12s failed: %v", pid, id, err))
				}
			}
		}
		// pkill -9 -f "$id" parity: kill shim/runc leftovers holding
		// the task id, then remove the dir — containerd GCs the task
		// record once the shim is gone.
		for _, pid := range c.d.PidsWithCmdline(id, pids) {
			if err := c.d.Cfg.Seams.KillFn(pid, syscall.SIGKILL); err != nil {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: kill leftover pid=%d holding task %.12s failed: %v",
					pid, id, err))
			}
		}
		c.d.State.AppendLog(fmt.Sprintf("ACTION: rm wedged task dir %.12s - dead >=5m", id))
		if err := os.RemoveAll(d); err != nil {
			c.d.State.AppendLog(fmt.Sprintf("suspect: rm task dir %.12s failed: %v", id, err))
		}
		nClean++
		c.d.Actions.WithLabelValues(wdeps.CheckCtrTasks, "rm_dir").Inc()
	}
	c.d.Cycles.WithLabelValues(wdeps.CheckCtrTasks, "ok").Inc()
}

// corruptImageWaitingReason mirrors the shell reason list — pull
// failures (ErrImagePull/ImagePullBackOff) and create failures
// (CreateContainerError) both surface corrupted-layer messages.
func corruptImageWaitingReason(r string) bool {
	switch r {
	case "CreateContainerError", "ErrImagePull", "ImagePullBackOff":
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
type CtrImagesCheck struct{ d *wdeps.Deps }

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
			if cs.Image != "" {
				seen[NormalizeCRIImageName(cs.Image)] = true
			}
			if cs.ImageID != "" {
				seen[NormalizeCRIImageName(cs.ImageID)] = true
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

// --- Check: cilium-bpf-ipam (38-cilium-bpf-ipam.sh) ---

// IngestGCCheck is the A3 stale-ingest reaper as a Check; it owns
// the 6h rescan stamp (ex-Hygiene.lastIngestScan).
type IngestGCCheck struct {
	d        *wdeps.Deps
	lastScan time.Time
}

// Name returns the check label / WD_SIG key.
func (c *IngestGCCheck) Name() string { return wdeps.CheckIngestGC }

// Run executes one ctr-ingest-gc round.
func (c *IngestGCCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckIngestGC, "gated").Inc()
		return
	}
	var st unix.Statfs_t
	diskHigh := false
	// Free > total wraps uint64 to ~2^64 → used ~= 1.0 → diskHigh
	// permanently true → the GC sweeps EVERY cycle (btrfs/XFS can
	// report Bavail > Blocks). Saturate instead of subtracting
	// blind — same guard as concourse_cache's fsPressure. The
	// free-side field is Bavail, not Bfree: kubelet/containerd run
	// unprivileged against the root-reserved block margin, so
	// unprivileged-free is the signal that trips ENOSPC first.
	if err := c.d.Cfg.Seams.StatfsFn(c.d.Cfg.Disk.K0sDataDir, &st); err == nil &&
		st.Blocks > 0 && st.Bavail <= st.Blocks {
		used := float64(st.Blocks-st.Bavail) / float64(st.Blocks)
		diskHigh = used > c.d.Cfg.Disk.HighWatermark
	}
	due := c.d.Cfg.Seams.NowFn().Sub(c.lastScan) >= c.d.Cfg.Ctr.IngestScanInterval
	if !diskHigh && !due {
		c.d.Cycles.WithLabelValues(wdeps.CheckIngestGC, "ok").Inc()
		return
	}
	// W9: above the high watermark the content store itself may be
	// the hog — run the store-wide prune on its own 6h budget IN
	// ADDITION to the stale-ingest sweep below. Below the
	// watermark (periodic rescan only) it never fires.
	if diskHigh {
		maybePruneContentStore(c.d, ctx)
	}
	entries, err := os.ReadDir(c.d.Cfg.Ctr.IngestDir)
	if err != nil {
		if os.IsNotExist(err) {
			// Absent dir = nothing to scan — stamp like a clean
			// walk so the 6h cadence still applies.
			c.lastScan = c.d.Cfg.Seams.NowFn()
			c.d.Cycles.WithLabelValues(wdeps.CheckIngestGC, "ok").Inc()
			return
		}
		// A transient read failure must NOT stamp lastScan —
		// stamping here would defer the retry by a full
		// CtrIngestScanInterval (6h).
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: ctr ingest dir %s unreadable: %v — ingest GC skipped",
			c.d.Cfg.Ctr.IngestDir, err))
		c.d.Cycles.WithLabelValues(wdeps.CheckIngestGC, "abort").Inc()
		return
	}
	c.lastScan = c.d.Cfg.Seams.NowFn()
	now := c.d.Cfg.Seams.NowFn()
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if n >= c.d.Cfg.Ctr.MaxTaskClean {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: ctr-ingest-gc still pending cap=%d", c.d.Cfg.Ctr.MaxTaskClean))
			break
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		age := now.Sub(fi.ModTime())
		if age < c.d.Cfg.Ctr.IngestMaxAge {
			continue
		}
		ref := e.Name()
		d := filepath.Join(c.d.Cfg.Ctr.IngestDir, ref)
		if rerr := c.d.Cfg.Seams.CtrRmIngest(ctx, ref); rerr != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: ctr content ingest rm %s failed: %v — removing dir directly", ref, rerr))
		}
		if _, serr := os.Stat(d); serr == nil {
			if rerr := os.RemoveAll(d); rerr != nil {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: rm orphan ingest dir %s failed: %v", d, rerr))
				continue
			}
		}
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: ctr-ingest-gc removed stale ingest %s (age=%.1fh disk_high=%v)",
			ref, age.Hours(), diskHigh))
		n++
		c.d.CtrIngestsCleaned.Inc()
		c.d.Actions.WithLabelValues(wdeps.CheckIngestGC, "ingest_rm").Inc()
	}
	c.d.Cycles.WithLabelValues(wdeps.CheckIngestGC, "ok").Inc()
}

// maybePruneContentStore runs `k0s ctr -n k8s.io content prune` —
// the store-wide GC that drops content blobs no lease references
// (the stale-ingest sweep only touches ingest/ leftovers; leaked
// leased content is what actually fills /var/lib/k0s). Budgeted by
// the last-content-gc marker at contentPruneInterval — the prune
// walks every blob + lease so it must not run every cycle even
// while the disk stays above the watermark. The budget is spent
// BEFORE the command (rate_spend parity); a failed prune logs
// suspect and does NOT count as an action.
func maybePruneContentStore(d *wdeps.Deps, ctx context.Context) {
	if !d.State.RateTrySpend("last-content-gc", contentPruneInterval) {
		return
	}
	if err := d.Cfg.Seams.CtrPruneContent(ctx); err != nil {
		d.State.AppendLog(fmt.Sprintf(
			"suspect: ctr-ingest-gc content prune failed: %v", err))
		return
	}
	d.State.AppendLog("ACTION: ctr-ingest-gc content prune ran (disk above watermark)")
	d.Actions.WithLabelValues(wdeps.CheckIngestGC, "content_gc").Inc()
}

// --- Check: zombie storm (A2) ---
// A container without an init reaper (or a wedged shim) leaves
// hundreds of <defunct> processes under one parent. One parent with
// >ZombieStormThreshold zombies for ConsecNeeded cycles = a storm:
// the pod UID is recovered from the parent's cgroup and reported to
// node-watchdog.log for the nodereporter ZombieProcessStorm Event.

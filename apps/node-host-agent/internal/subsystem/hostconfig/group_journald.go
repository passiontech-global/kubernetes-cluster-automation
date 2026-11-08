// group_journald.go — journald persistence converge for standalone
// hosts (no kubelet hostPath to flip Storage=auto): the drop-in, the
// machine-id journal dir and the orphaned-journal fold, plus the
// cheap integrity probe groupBase runs every cycle (split out of
// group_base.go — pure move, same package).
package hostconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
)

// ---------- journald persistence (standalone hosts) ----------
//
// DaemonSet nodes get persistent journals as a mount side-effect:
// the pod's /var/log/journal hostPath is DirectoryOrCreate, and a
// Storage=auto journald goes persistent once the dir exists at its
// start. The standalone deployments (interdc hubs, k0s controllers,
// infra VMs) had no equivalent converge: a journald that started
// before the dir existed — or whose journal files were
// deleted/vacuumed under it — writes nowhere and never recovers on
// its own (cicd controller 103.186.101.30, 2026-11:
// /var/log/journal/<machine-id> existed but EMPTY, journalctl
// answered "No journal files were found." and the journal-unreadable
// watchdog latch fired with nothing remediating it). groupBase runs
// this on every standalone host before the integrity probe so a
// restart the probe prescribes lands on Storage=persistent.

// journaldPersistence converges the generic persistent-storage
// drop-in on standalone hosts — a no-op on DaemonSet nodes, where
// the /var/log/journal hostPath mount already flips Storage=auto.
func (c *cyc) journaldPersistence() {
	if !c.r.cfg.Standalone {
		return
	}
	c.journaldStorage("/etc/systemd/journald.conf.d/50-node-config-agent.conf",
		[]byte(`# Managed by node-config-agent — persistent journald on standalone
# hosts (no kubelet hostPath to flip Storage=auto). A journald that
# started before /var/log/journal existed, or lost its files under it,
# writes nowhere until restarted (cicd controller incident 2026-11).
[Journal]
Storage=persistent
`))
}

// journaldStorage converges one journald.conf.d drop-in plus the
// machine-id journal dir, restarts systemd-journald when the drop-in
// changed or the dir was missing — journald only re-scans storage on
// start, so a dir created under a running journald stays invisible
// without the bounce — and folds orphaned *.journal files (stale
// machine-id dirs, e.g. cloned images) into the live dir. The restart
// is recorded on c.journaldRestarted so journaldIntegrity does not
// spend its restart budget on a second bounce in the same cycle.
func (c *cyc) journaldStorage(dropinPath string, dropin []byte) {
	r, ctx := c.r, c.ctx
	_ = r.ensureDir("/etc/systemd/journald.conf.d", 0o755)
	ch, _ := r.writeManaged(dropinPath, dropin, 0o644)
	created := c.ensureJournalDir()
	if ch || created {
		r.restartService(ctx, "systemd-journald.service")
		c.journaldRestarted = true
	}
	c.journaldOrphanFold()
}

// ensureJournalDir creates /var/log/journal/<machine-id> with the
// 02755 root:systemd-journal shape journald expects (the same
// ownership systemd's own creation uses). Returns true when the dir
// was missing before this cycle — the caller restarts journald so
// the fresh dir is actually seen. chmod/chgrp failures are
// best-effort warns: drifted perms weaken the setup but never block
// the converge.
func (c *cyc) ensureJournalDir() bool {
	r, ctx := c.r, c.ctx
	mid := r.machineID()
	if mid == "" {
		return false
	}
	dir := "/var/log/journal/" + mid
	created := !r.fileExists(dir)
	if err := os.MkdirAll(r.hp(dir), 0o755); err != nil {
		logger().Warn("journald: journal dir create failed — persistence may not take effect",
			"dir", dir, "error", err)
		return created
	}
	// os.ModeSetgid|0755, not 0o2755: os.Chmod maps the abstract
	// FileMode flags — the raw 0o2000 bit is silently dropped (the
	// api-lb block this replaces had that latent bug).
	if err := os.Chmod(r.hp(dir), os.ModeSetgid|0o755); err != nil {
		logger().Warn("journald: chmod journal dir failed", "dir", dir, "error", err)
	}
	if _, err := r.run(ctx, "chgrp", "systemd-journal", dir); err != nil {
		logger().Warn("journald: chgrp journal dir failed", "dir", dir, "error", err)
	}
	return created
}

// journaldOrphanFold moves *.journal files stranded under stale
// machine-id dirs into the live one — same mv-with-rename dance as
// ansible (incident 2026-10-09 cloned-image journals).
func (c *cyc) journaldOrphanFold() {
	r, ctx := c.r, c.ctx
	mid := r.machineID()
	if mid == "" {
		return
	}
	// sh -c runs in the host namespaces via the Runner — unjoined
	// host paths, not HostRoot-prefixed.
	_, _ = r.run(ctx, "sh", "-c", fmt.Sprintf(`mid=%q
for f in /var/log/journal/*/*.journal; do
  [ -e "$f" ] || continue
  case "$f" in "/var/log/journal/$mid/"*) continue ;; esac
  base=$(basename "$f")
  dest="/var/log/journal/$mid/$base"
  [ -e "$dest" ] && dest="/var/log/journal/$mid/orphan-$base"
  mv "$f" "$dest" || echo "WARN: could not move $f"
done`, mid))
}

// machineID reads the host machine-id — the journal storage dir name.
func (r *Reconciler) machineID() string {
	if b, err := os.ReadFile(r.hp("/etc/machine-id")); err == nil {
		return strings.TrimSpace(string(b))
	}
	return ""
}

// ---------- journald integrity probe (groupBase, every cycle) ----------

// journaldRotateCooldown caps how often journaldIntegrity may run
// rotate+vacuum (last-journald-rotate latch in the watchdog state
// dir — last-* names are janitor-safe); journaldRestartCooldown is
// the same budget for the silent-journald restart remedy
// (last-journald-restart).
const (
	journaldRotateCooldown  = time.Hour
	journaldRestartCooldown = time.Hour
)

// journaldIntegrity is the cheap journald probe groupBase runs every
// cycle. Three verdicts:
//
//   - CORRUPT — `journalctl` prints corruption markers, or returns
//     nothing at all while journal files are on disk (post
//     hard-reboot truncation). Remedy: `journalctl --rotate
//     --vacuum-time=3d` so journald recovers (last-journald-rotate
//     cooldown).
//   - SILENT — journalctl reports "No journal files" or produces
//     literally nothing while a journal storage root exists: journald
//     is running but writing nowhere (started before /var/log/journal
//     appeared, or lost its files under it — the cicd controller
//     incident, an empty /var/log/journal/<machine-id> + "No journal
//     files were found."). Rotate cannot create files; the remedy is
//     `systemctl restart systemd-journald`, which journaldStorage
//     has already pointed at persistent storage this cycle
//     (last-journald-restart cooldown). The storage-root gate keeps
//     journald-less minimal hosts out — there silence is
//     configuration, not a fault.
//
// A missing journalctl or a failed read without corruption markers is
// NEITHER — the tool may simply be absent (minimal image) and either
// remedy would fail anyway.
func (c *cyc) journaldIntegrity() {
	r, ctx := c.r, c.ctx
	// No -q: --quiet suppresses "No journal files were found." — the
	// incident signature the SILENT verdict needs (the notice is a
	// journald diagnostic on stderr, folded into out by the Runner).
	out, err := r.run(ctx, "journalctl", "-n", "5", "--no-pager")
	low := strings.ToLower(out)
	corrupt := strings.Contains(low, "corrupt") ||
		strings.Contains(low, "invalid object") ||
		strings.Contains(low, "failed to open journal")
	empty := err == nil && strings.TrimSpace(out) == ""
	files := false
	for _, pat := range []string{
		"/var/log/journal/*/*.journal*",
		"/run/log/journal/*/*.journal*",
	} {
		if m, gerr := filepath.Glob(r.hp(pat)); gerr == nil && len(m) > 0 {
			files = true
			break
		}
	}
	if empty && files {
		// Abnormally empty read: journal files exist on disk but the
		// journal returns no entries at all.
		corrupt = true
	}
	// FilesGone counts even on a non-zero exit — the "No journal
	// files" notice is positive evidence journald has no storage,
	// unlike a bare exec failure. The empty-and-no-files half keeps
	// the err==nil gate: a failed exec with empty output is the
	// missing-binary case, not blindness.
	silent := !corrupt && c.journalStoragePresent() &&
		(journalwatch.FilesGone(out) || (empty && !files))
	switch {
	case corrupt:
		// Cooldown latch like nethealth's last-* budgets: a persistently
		// corrupt (or false-positive) probe would otherwise re-run
		// rotate+vacuum — and re-fail — every cycle, pinning errs and
		// hammering the journal on every converge. The last-* name is
		// janitor-safe (only state-* latches are swept).
		if !r.state.RateOK("last-journald-rotate", journaldRotateCooldown) {
			logger().Warn("base: journald journal still corrupt — rotate+vacuum in cooldown, skipping",
				"cooldown", journaldRotateCooldown.String())
			return
		}
		logger().Warn("base: journald journal corrupt/abnormally empty — rotating + vacuuming",
			"action", "journalctl --rotate --vacuum-time=3d",
			"probe_out", out)
		r.actions.WithLabelValues("journalctl --rotate --vacuum-time=3d").Inc()
		// Spend on the attempt: a failing rotate retries next cycle no
		// more than once per cooldown window.
		_ = r.ensureDir(watchdogStateDir, 0o755)
		r.state.RateSpend("last-journald-rotate")
		// runLong: vacuum of a multi-GB journal on a slow disk blows past
		// the interactive command budget.
		if vout, verr := r.runLong(ctx, "journalctl", "--rotate", "--vacuum-time=3d"); verr != nil {
			c.err("base: journalctl rotate/vacuum failed",
				"out", vout, "error", verr)
		}
	case silent:
		if c.journaldRestarted {
			// journaldStorage already bounced journald this cycle —
			// give it the rest of the converge to open files; if the
			// probe is still silent next cycle the remedy fires then
			// (still inside the restart cooldown budget).
			logger().Info("base: journald silent — already restarted by the persistence converge this cycle")
			return
		}
		if !r.state.RateOK("last-journald-restart", journaldRestartCooldown) {
			logger().Warn("base: journald still writing no journal files — restart in cooldown, skipping",
				"cooldown", journaldRestartCooldown.String())
			return
		}
		logger().Warn("base: journald writing no journal files though storage exists — restarting",
			"action", "systemctl restart systemd-journald.service",
			"probe_out", out)
		// Spend on the attempt: a failing restart retries no more
		// than once per cooldown window.
		_ = r.ensureDir(watchdogStateDir, 0o755)
		r.state.RateSpend("last-journald-restart")
		r.restartService(ctx, "systemd-journald.service")
	}
}

// journalStoragePresent mirrors journalwatch.Tracker.Present for the
// HostRoot view: true while /var/log/journal or /run/log/journal
// exists — the "journald should be writing" witness that gates the
// SILENT verdict.
func (c *cyc) journalStoragePresent() bool {
	for _, d := range []string{"/var/log/journal", "/run/log/journal"} {
		if fi, err := os.Stat(c.r.hp(d)); err == nil && fi.IsDir() {
			return true
		}
	}
	return false
}

// group_journald.go — journald persistence converge for standalone
// hosts (no kubelet hostPath to flip Storage=auto): the drop-in, the
// machine-id journal dir and the orphaned-journal fold.
package hostconfig

import (
	"fmt"
	"os"
	"strings"
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

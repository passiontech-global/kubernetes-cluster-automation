// deploy.go — candidate-staged validated deploys: content lands at
// path+".candidate", the caller's check runs against the CANDIDATE
// (its name appended to check argv), and only a passing candidate is
// promoted — a bad render never sits at the live path a unit loads
// on next start. The candidate is swept on every outcome.
package converge

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrManagedWrite wraps failures that surfaced inside
// Ops.WriteManaged. Ops implementations report write errors
// themselves (hostconfig attributes them to the active cycle), so a
// caller that also counts Deploy's returned error must skip
// ErrManagedWrite to avoid counting the same failure twice.
var ErrManagedWrite = errors.New("converge: managed write failed")

// FileOps is the host-side seam Deploy drives: managed-file writes
// plus command exec, with paths expressed as HOST paths (Join roots
// them under the implementation's HostRoot). Implementations own
// metrics and error attribution.
type FileOps interface {
	// Join roots a host path under the impl's host root.
	Join(hostPath string) string
	// WriteManaged is the sha256-compare + atomic-write verb;
	// returns whether the file changed.
	WriteManaged(hostPath string, content []byte, mode os.FileMode) (bool, error)
	// RemoveManaged deletes a managed file; absent is success.
	RemoveManaged(hostPath string) (bool, error)
	// Run executes a host command (the impl applies its own
	// per-command budget).
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// Ops extends FileOps with the unit verbs NftUnit drives.
type Ops interface {
	FileOps
	DaemonReload(ctx context.Context)
	EnableService(ctx context.Context, unit string)
	StartService(ctx context.Context, unit string)
	RestartService(ctx context.Context, unit string)
}

// Deploy stages content at path+".candidate", runs check against the
// candidate, and promotes to path via WriteManaged only when the
// check passes — the ansible copy+validate-then-promote half of the
// nft/haproxy deploys. An empty check skips validation (unverified
// promote). Returns (changed, err): err is ErrManagedWrite-wrapped
// when a staged/promoting write failed inside the Ops impl (already
// reported there), or the check failure itself carrying argv + out.
//
// An unchanged file skips staging entirely (it was validated the
// cycle it was promoted) but still sweeps a stale candidate a
// crashed converge left behind.
func Deploy(ctx context.Context, o FileOps, path string, content []byte, mode os.FileMode, check ...string) (bool, error) {
	joined := o.Join(path)
	changed := true
	if old, err := os.ReadFile(joined); err == nil &&
		sha256.Sum256(old) == sha256.Sum256(content) {
		changed = false
	}
	if !changed {
		// Cheap sweep, ENOENT ignored — a candidate orphaned between
		// stage and promote must not linger next to the live file.
		if err := os.Remove(joined + ".candidate"); err != nil && !os.IsNotExist(err) {
			logger().Warn("converge: stale candidate sweep failed",
				"path", path+".candidate", "error", err)
		}
		return false, nil
	}
	cand := path + ".candidate"
	if _, err := o.WriteManaged(cand, content, mode); err != nil {
		return false, fmt.Errorf("%w: %s: %s", ErrManagedWrite, cand, err)
	}
	if len(check) > 0 {
		if out, err := o.Run(ctx, check[0], append(check[1:], cand)...); err != nil {
			_, _ = o.RemoveManaged(cand)
			return false, fmt.Errorf("converge: candidate check %q failed (out %q): %w",
				strings.Join(check, " "), out, err)
		}
	}
	// The promote write is NOT best-effort: a failure must surface
	// ErrManagedWrite-wrapped (the Ops impl already attributed it —
	// callers skip re-counting), otherwise a checkedDeploy caller
	// reads ok=true and unmask/enables/restarts onto a stale or
	// missing config. The candidate is swept on this outcome too.
	changed, werr := o.WriteManaged(path, content, mode)
	_, _ = o.RemoveManaged(cand)
	if werr != nil {
		return false, fmt.Errorf("%w: %s: %s", ErrManagedWrite, path, werr)
	}
	return changed, nil
}

// NftUnit deploys an nft ruleset + its oneshot boot unit, applying
// via restart when the file changed (hostconfig's T4/T11 pattern).
// `nft -c` runs on the CANDIDATE — the deploy path must only ever
// hold a validated ruleset, or a broken render would persist where
// the oneshot unit loads it at boot. The returned error is Deploy's
// (ErrManagedWrite-wrapped on staging failures); the unit-file write
// and systemctl verbs report through the Ops impl itself.
func NftUnit(ctx context.Context, o Ops, name, path string, content []byte, desc string) error {
	ch, err := Deploy(ctx, o, path, content, 0o644, "nft", "-c", "-f")
	if err != nil {
		return err
	}
	unitPath := "/etc/systemd/system/" + name + ".service"
	uch, _ := o.WriteManaged(unitPath, []byte(fmt.Sprintf(`[Unit]
Description=%s
After=network-pre.target
Wants=network-pre.target
Before=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f %s
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`, desc, path)), 0o644)
	if ch || uch {
		o.DaemonReload(ctx)
	}
	o.EnableService(ctx, name+".service")
	if ch {
		o.RestartService(ctx, name+".service")
	} else {
		o.StartService(ctx, name+".service")
	}
	return nil
}

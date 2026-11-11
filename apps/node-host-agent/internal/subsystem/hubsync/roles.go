// roles.go — the per-role converge deltas (remoteDir/dirMirror/
// roleProfile) and prepareHost, the preamble every target runs
// before its converge steps. hub_converge branched per role group
// inside one big play; the deltas are data here.
package hubsync

import (
	"context"
	"fmt"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
)

// remoteDir is one remote directory a role's preamble prepares:
// mkdir -p, then a separate chmod when mode is set — the conn
// prepends `sudo -n` to the raw string, so a `mkdir && chmod`
// compound would only escalate mkdir (the chmod would fail EPERM for
// a non-root ssh_user).
type remoteDir struct {
	path string
	mode string // "" — mkdir only
}

// dirMirror is one local→remote config mirror — the syncDir argument
// set for a role's extra source beyond the shared vars mirror.
type dirMirror struct {
	local  string
	remote string
	mode   string
	keep   func(string) bool
}

// roleProfile is one target role's delta against the shared converge
// script. hub_converge branched per role group inside one big play
// (interdc vs api-lb); the deltas are data here, so syncTarget stays
// a linear list of steps with no per-role branching.
type roleProfile struct {
	// dirs are the role's extra remote dirs, created after the
	// shared vars dir — interdc-then-api-lb order, the branch order
	// the shell module ran.
	dirs []remoteDir
	// mirrors are the role's extra local→remote mirrors, pushed
	// after the shared vars mirror.
	mirrors []dirMirror
	// guard marks the api-lb role: the converge carries the
	// api-backend-guard credentials into GuardDir.
	guard bool
}

// roleProfileFor derives target t's converge profile: interdc nodes
// additionally mirror the nebula certs (cert/key material only) into
// RemoteCertsDir; api-lb nodes additionally prepare the 0700 guard
// dir that will hold token+ca.crt.
func roleProfileFor(cfg Config, t Target) roleProfile {
	var p roleProfile
	if t.InterDC {
		p.dirs = append(p.dirs, remoteDir{path: cfg.RemoteCertsDir})
		p.mirrors = append(p.mirrors, dirMirror{
			local:  cfg.NebulaCertsDir,
			remote: cfg.RemoteCertsDir,
			mode:   "0644",
			keep:   isCertArtifact,
		})
	}
	if t.APILB {
		p.dirs = append(p.dirs, remoteDir{path: cfg.GuardDir, mode: "0700"})
		p.guard = true
	}
	return p
}

// prepareHost runs the converge preamble every target needs: the
// passwordless-sudo gate, the shared vars dir, then the role's extra
// dirs in profile order.
func prepareHost(ctx context.Context, c Conn, cfg Config, t Target, p roleProfile) error {
	// Passwordless-sudo gate first: hub_converge ran become:true, so
	// a non-root ssh_user needs `sudo -n` for EVERY remote op (the
	// conn wraps them) — fail fast with a clear error instead of a
	// confusing mkdir/upload failure downstream.
	if needsSudo(t.SSHUser) {
		if _, err := c.Run(ctx, "true"); err != nil {
			return fmt.Errorf("ssh user %q: sudo -n (passwordless sudo) required "+
				"but unavailable: %w", t.SSHUser, err)
		}
	}
	if _, err := c.Run(ctx, "mkdir -p "+hostutil.ShellQuote(cfg.RemoteVarsDir)); err != nil {
		return err
	}
	for _, d := range p.dirs {
		if _, err := c.Run(ctx, "mkdir -p "+hostutil.ShellQuote(d.path)); err != nil {
			return err
		}
		if d.mode != "" {
			if _, err := c.Run(ctx, "chmod "+d.mode+" "+hostutil.ShellQuote(d.path)); err != nil {
				return err
			}
		}
	}
	return nil
}

// isCertArtifact limits the nebula-certs mirror to cert/key
// material: the pod's /config/nebula-certs and /config/vars are the
// SAME projected volume, so an unfiltered mirror would duplicate
// cluster.yaml/defaults.yaml/interdc_nodes.yaml into the remote
// certs dir. hostconfig's certFile lookup consumes nebula-ca.crt +
// nebula-<mesh>.crt; *.pub / *.key cover operator-staged key
// material.
func isCertArtifact(name string) bool {
	return strings.HasSuffix(name, ".crt") ||
		strings.HasSuffix(name, ".pub") ||
		strings.HasSuffix(name, ".key")
}

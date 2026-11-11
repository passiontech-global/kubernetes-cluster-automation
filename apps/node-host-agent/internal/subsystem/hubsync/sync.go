// sync.go — syncTarget, the per-target converge steps: binary,
// config mirrors, api-lb credentials, then the systemd unit and its
// enable/restart action — the hub_converge play order.
package hubsync

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/pagecache"
)

// syncTarget converges one host over SSH: binary, vars (+ nebula
// certs on interdc nodes), api-lb credentials, then the systemd unit
// and its enable/restart action. localSum is the caller's hash of
// LocalBinary — computed once per Cycle rather than per target; ""
// re-hashes here (tests, one-off callers).
func (s *Syncer) syncTarget(ctx context.Context, t Target, token, ca []byte, localSum string) error {
	cfg := s.cfg
	tctx, cancel := context.WithTimeout(ctx, cfg.TargetTimeout)
	defer cancel()

	conn, err := s.dialer.Dial(tctx, t)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	prof := roleProfileFor(cfg, t)
	if err := prepareHost(tctx, conn, cfg, t, prof); err != nil {
		return err
	}

	// a. binary — sha256 compare, stage + chmod + atomic mv on
	// drift. The systemd unit (consumed at step d) hashes in the
	// SAME batched session: both are pure reads, and one SSH
	// round-trip beats two over WAN.
	remoteSums, err := remoteSHA256All(tctx, conn,
		[]string{cfg.RemoteBinary, cfg.UnitPath})
	if err != nil {
		return err
	}
	remoteSum := remoteSums[cfg.RemoteBinary]
	remoteUnitSum := remoteSums[cfg.UnitPath]
	if localSum == "" {
		localSum, err = sha256File(cfg.LocalBinary)
		if err != nil {
			return err
		}
	}
	binaryUpdated := false
	if remoteSum != localSum {
		f, err := os.Open(cfg.LocalBinary)
		if err != nil {
			return err
		}
		err = putAtomic(tctx, conn, cfg.RemoteBinary, f, "0755")
		// The streamed binary's pages were only needed for the put —
		// same every-cycle charge problem as sha256File below.
		pagecache.Drop(f)
		_ = f.Close()
		if err != nil {
			return err
		}
		binaryUpdated = true
		s.cfg.Log.Info("hubsync: binary updated",
			"target", t.Name, "path", cfg.RemoteBinary)
	}

	// b. config dirs — per-file sha256 gating, atomic writes; the
	// role's extra mirrors (interdc certs) follow the shared vars
	// mirror, in profile order.
	if err := s.syncDir(tctx, conn, cfg.VarsDir, cfg.RemoteVarsDir, "0644", nil); err != nil {
		return err
	}
	for _, m := range prof.mirrors {
		if err := s.syncDir(tctx, conn, m.local, m.remote, m.mode, m.keep); err != nil {
			return err
		}
	}

	// c. api-lb guard credentials.
	if prof.guard && len(token) > 0 {
		if err := s.putIfChanged(tctx, conn, path.Join(cfg.GuardDir, "token"), token, "0600"); err != nil {
			return err
		}
		if err := s.putIfChanged(tctx, conn, path.Join(cfg.GuardDir, "ca.crt"), ca, "0600"); err != nil {
			return err
		}
	}

	// d. systemd unit — write on drift, daemon-reload, then the
	// enable/restart action. `enable --now` is the steady-state /
	// fresh-install path; `restart` is required when the binary was
	// just updated or an EXISTING unit file drifted (enable --now
	// leaves a running service on the old unit).
	unit := systemdUnit(t, cfg.RemoteBinary, cfg.RemoteVarsDir, cfg.RemoteCertsDir)
	freshUnit := remoteUnitSum == ""
	unitSum := sha256.Sum256([]byte(unit))
	unitChanged := remoteUnitSum != hex.EncodeToString(unitSum[:])
	if unitChanged {
		if err := putAtomic(tctx, conn, cfg.UnitPath,
			bytes.NewReader([]byte(unit)), "0644"); err != nil {
			return err
		}
		s.cfg.Log.Info("hubsync: systemd unit updated",
			"target", t.Name, "path", cfg.UnitPath)
		if _, err := conn.Run(tctx, "systemctl daemon-reload"); err != nil {
			return err
		}
	}
	svc := unitName(cfg.UnitPath)
	if binaryUpdated || (unitChanged && !freshUnit) {
		if _, err := conn.Run(tctx, "systemctl enable "+hostutil.ShellQuote(svc)); err != nil {
			return err
		}
		if _, err := conn.Run(tctx, "systemctl restart "+hostutil.ShellQuote(svc)); err != nil {
			return err
		}
		s.cfg.Log.Info("hubsync: service restarted after update",
			"target", t.Name, "unit", svc)
	} else {
		if _, err := conn.Run(tctx, "systemctl enable --now "+hostutil.ShellQuote(svc)); err != nil {
			return err
		}
	}
	return nil
}

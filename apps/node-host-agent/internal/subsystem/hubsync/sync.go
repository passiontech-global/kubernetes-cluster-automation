package hubsync

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Cycle is one full converge round — the hub_converge CronJob run:
// re-parse targets (vars drift), fetch the guard credentials when an
// api-lb VM is in scope, then converge each target serially.
// hub_converge used serial:1 — two controllers/lighthouses are never
// in the restart window together, and SSH fan-out stays trivially
// debuggable in logs.
func (s *Syncer) Cycle(ctx context.Context) {
	// A cycle attempt while holding the lease counts — failures are
	// metered + logged, and the retry cadence is SyncInterval /
	// watcher edges, not the renew tick.
	s.syncedWhileHeld = true
	targets, err := loadTargets(s.cfg.VarsDir)
	if err != nil {
		s.cfg.Log.Error("hubsync: target aggregation failed", "error", err)
		s.cycles.WithLabelValues("all", "parse_error").Inc()
		// Nothing converged this cycle — every last-known target
		// reads down until a good parse runs again, otherwise
		// target_up{...}=1 stays stale forever.
		for _, name := range s.lastTargets {
			s.targetUp.WithLabelValues(name).Set(0)
		}
		return
	}
	s.lastTargets = s.lastTargets[:0]
	for _, t := range targets {
		s.lastTargets = append(s.lastTargets, t.Name)
	}

	var token, ca []byte
	guardOK := true
	if anyAPILB(targets) {
		token, ca, err = s.guardCreds(ctx)
		if err != nil {
			// Only api-lb targets consume the guard credentials —
			// the failure scopes to them; interdc/infra targets
			// still converge this cycle.
			s.cfg.Log.Error("hubsync: api-backend-guard secret fetch failed — api-lb targets skipped",
				"secret", s.cfg.SecretNamespace+"/"+s.cfg.SecretName, "error", err)
			s.cycles.WithLabelValues("all", "secret_error").Inc()
			guardOK = false
		}
	}

	var converged, skipped, failed int
	for _, t := range targets {
		if ctx.Err() != nil {
			return
		}
		if t.APILB && !guardOK {
			s.cfg.Log.Error("hubsync: api-lb target skipped — guard credentials unavailable",
				"target", t.Name, "ip", t.IP)
			s.cycles.WithLabelValues(t.Name, "secret_error").Inc()
			s.targetUp.WithLabelValues(t.Name).Set(0)
			skipped++
			continue
		}
		if err := s.syncTarget(ctx, t, token, ca); err != nil {
			s.cfg.Log.Error("hubsync: target converge failed",
				"target", t.Name, "ip", t.IP, "error", err)
			s.cycles.WithLabelValues(t.Name, "error").Inc()
			s.targetUp.WithLabelValues(t.Name).Set(0)
			failed++
			continue
		}
		s.cycles.WithLabelValues(t.Name, "ok").Inc()
		s.lastSuccess.WithLabelValues(t.Name).SetToCurrentTime()
		s.targetUp.WithLabelValues(t.Name).Set(1)
		s.cfg.Log.Info("hubsync: target converged", "target", t.Name, "ip", t.IP)
		converged++
	}
	s.cfg.Log.Info("hubsync: converge cycle complete",
		"targets", len(targets), "converged", converged,
		"skipped", skipped, "failed", failed)
}

func anyAPILB(targets []Target) bool {
	for _, t := range targets {
		if t.APILB {
			return true
		}
	}
	return false
}

// guardCreds reads the api-backend-guard Secret — hub_converge fetched
// the same secret via the in-cluster API to push token+ca.crt to the
// api-lb VM.
func (s *Syncer) guardCreds(ctx context.Context) (token, ca []byte, err error) {
	sec, err := s.cfg.Client.CoreV1().Secrets(s.cfg.SecretNamespace).
		Get(ctx, s.cfg.SecretName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}
	return sec.Data["token"], sec.Data["ca.crt"], nil
}

// syncTarget converges one host over SSH: binary, vars (+ nebula
// certs on interdc nodes), api-lb credentials, then the systemd unit
// and its enable/restart action.
func (s *Syncer) syncTarget(ctx context.Context, t Target, token, ca []byte) error {
	cfg := s.cfg
	tctx, cancel := context.WithTimeout(ctx, cfg.TargetTimeout)
	defer cancel()

	conn, err := s.dialer.Dial(tctx, t)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Passwordless-sudo gate first: hub_converge ran become:true, so
	// a non-root ssh_user needs `sudo -n` for EVERY remote op (the
	// conn wraps them) — fail fast with a clear error instead of a
	// confusing mkdir/upload failure downstream.
	if needsSudo(t.SSHUser) {
		if _, err := conn.Run(tctx, "true"); err != nil {
			return fmt.Errorf("ssh user %q: sudo -n (passwordless sudo) required "+
				"but unavailable: %w", t.SSHUser, err)
		}
	}

	if _, err := conn.Run(tctx, "mkdir -p "+shq(cfg.RemoteVarsDir)); err != nil {
		return err
	}
	if t.InterDC {
		if _, err := conn.Run(tctx, "mkdir -p "+shq(cfg.RemoteCertsDir)); err != nil {
			return err
		}
	}
	if t.APILB {
		if _, err := conn.Run(tctx, "mkdir -p "+shq(cfg.GuardDir)+" && chmod 0700 "+shq(cfg.GuardDir)); err != nil {
			return err
		}
	}

	// a. binary — sha256 compare, stage + chmod + atomic mv on drift.
	remoteSum, err := remoteSHA256(tctx, conn, cfg.RemoteBinary)
	if err != nil {
		return err
	}
	localSum, err := sha256File(cfg.LocalBinary)
	if err != nil {
		return err
	}
	binaryUpdated := false
	if remoteSum != localSum {
		f, err := os.Open(cfg.LocalBinary)
		if err != nil {
			return err
		}
		err = putAtomic(tctx, conn, cfg.RemoteBinary, f, "0755")
		f.Close()
		if err != nil {
			return err
		}
		binaryUpdated = true
		s.cfg.Log.Info("hubsync: binary updated",
			"target", t.Name, "path", cfg.RemoteBinary)
	}

	// b. config dirs — per-file sha256 gating, atomic writes.
	if err := s.syncDir(tctx, conn, cfg.VarsDir, cfg.RemoteVarsDir, "0644", nil); err != nil {
		return err
	}
	if t.InterDC {
		if err := s.syncDir(tctx, conn, cfg.NebulaCertsDir, cfg.RemoteCertsDir, "0644", isCertArtifact); err != nil {
			return err
		}
	}

	// c. api-lb guard credentials.
	if t.APILB && len(token) > 0 {
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
	remoteUnitSum, err := remoteSHA256(tctx, conn, cfg.UnitPath)
	if err != nil {
		return err
	}
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
		if _, err := conn.Run(tctx, "systemctl enable "+svc); err != nil {
			return err
		}
		if _, err := conn.Run(tctx, "systemctl restart "+svc); err != nil {
			return err
		}
		s.cfg.Log.Info("hubsync: service restarted after update",
			"target", t.Name, "unit", svc)
	} else {
		if _, err := conn.Run(tctx, "systemctl enable --now "+svc); err != nil {
			return err
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

// syncDir pushes every regular file of localDir into remoteDir —
// sha256-gated per file, atomic tmp+chmod+mv writes. ConfigMap
// volumes expose keys as symlinks, so "regular" means non-dir,
// non-hidden entries; ReadFile resolves the ..data links. A non-nil
// keep filter further restricts which filenames are mirrored.
func (s *Syncer) syncDir(ctx context.Context, c Conn, localDir, remoteDir, mode string, keep func(string) bool) error {
	entries, err := os.ReadDir(localDir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if keep != nil && !keep(e.Name()) {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		data, err := os.ReadFile(path.Join(localDir, name))
		if err != nil {
			return err
		}
		if err := s.putIfChanged(ctx, c, path.Join(remoteDir, name), data, mode); err != nil {
			return err
		}
	}
	return nil
}

// putIfChanged writes data to remotePath only when the remote sha256
// differs — the ansible copy-module checksum gating.
func (s *Syncer) putIfChanged(ctx context.Context, c Conn, remotePath string, data []byte, mode string) error {
	sum := sha256.Sum256(data)
	remote, err := remoteSHA256(ctx, c, remotePath)
	if err != nil {
		return err
	}
	if remote == hex.EncodeToString(sum[:]) {
		return nil
	}
	return putAtomic(ctx, c, remotePath, bytes.NewReader(data), mode)
}

// sha256File hashes a local file without loading it whole — the
// agent binary is ~15 MiB and cycles run every few minutes.
func sha256File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

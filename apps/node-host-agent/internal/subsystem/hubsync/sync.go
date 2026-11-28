// sync.go — syncTarget, the per-target converge steps: binary,
// config mirrors, api-lb credentials, then the systemd unit and its
// enable/restart action — the hub_converge play order.
package hubsync

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/pagecache"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

// dirProber is an optional fast path implemented by sshConn: one SSH
// session batches all mirror `ls -1pA` listings and orphan-tmp `find`
// scans into a single round-trip.
type dirProber interface {
	ProbeDirs(ctx context.Context, lsDirs, orphanDirs []string) (ls, orphans map[string][]string, err error)
}

// hostProber extends dirProber to also probe the active service's
// running binary/start time inside the same single SSH session, so
// steady-state syncTarget keeps its <=4 session budget while catching
// partial-upgrade stale processes.
type hostProber interface {
	ProbeHost(ctx context.Context, lsDirs, orphanDirs []string, svc, remoteBin, unitPath string) (ls, orphans map[string][]string, stale bool, err error)
}

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

	type mirrorPlan struct {
		dirMirror
		names  []string
		rpaths []string
		err    error
	}
	varsNames, varsPaths, varsErr := readLocalMirror(cfg.VarsDir, cfg.RemoteVarsDir, nil)
	mPlans := make([]mirrorPlan, len(prof.mirrors))
	for i, m := range prof.mirrors {
		names, rpaths, merr := readLocalMirror(m.local, m.remote, m.keep)
		mPlans[i] = mirrorPlan{dirMirror: m, names: names, rpaths: rpaths, err: merr}
	}

	dp, useDirProber := conn.(dirProber)
	hp, useHostProber := conn.(hostProber)
	useProber := useDirProber || useHostProber
	svc := unitName(cfg.UnitPath)
	orphanDirs := make([]string, 0, 5+len(mPlans))
	{
		dirs := []string{path.Dir(cfg.RemoteBinary), path.Dir(cfg.UnitPath)}
		if prof.guard {
			dirs = append(dirs, cfg.GuardDir)
		}
		if useProber {
			dirs = append(dirs, cfg.RemoteVarsDir)
			for _, mp := range mPlans {
				dirs = append(dirs, mp.remote)
			}
		}
		seen := map[string]bool{}
		for _, dir := range dirs {
			if dir == "" || dir == "." || seen[dir] {
				continue
			}
			seen[dir] = true
			orphanDirs = append(orphanDirs, dir)
			if !useProber {
				// Conn-only fallback: sweep non-mirror orphans before step a.
				_ = s.sweepTmpOrphans(tctx, conn, dir)
			}
		}
	}

	// Read-only probe session 1: unify remote SHA-256 checks across
	// binary, unit, vars mirror, role mirrors, and api-lb guard files
	// into a single batched sha256sum session.
	allPaths := make([]string, 0, 2+len(varsPaths)+2)
	allPaths = append(allPaths, cfg.RemoteBinary, cfg.UnitPath)
	if varsErr == nil {
		allPaths = append(allPaths, varsPaths...)
	}
	for _, mp := range mPlans {
		if mp.err == nil {
			allPaths = append(allPaths, mp.rpaths...)
		}
	}
	if prof.guard && len(token) > 0 {
		allPaths = append(allPaths, path.Join(cfg.GuardDir, "token"), path.Join(cfg.GuardDir, "ca.crt"))
	}
	remoteSums, err := remoteSHA256All(tctx, conn, allPaths)
	if err != nil {
		return err
	}
	remoteSum := remoteSums[cfg.RemoteBinary]
	remoteUnitSum := remoteSums[cfg.UnitPath]
	if localSum == "" {
		localSum, err = s.localBinarySum(cfg.LocalBinary)
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
	if varsErr != nil {
		return varsErr
	}
	if err := syncMirrorFiles(tctx, conn, cfg.VarsDir, cfg.RemoteVarsDir, "0644", varsNames, remoteSums); err != nil {
		return err
	}
	if !useProber {
		if err := s.pruneRemoteDir(tctx, conn, cfg.RemoteVarsDir, varsNames); err != nil {
			return err
		}
	}
	for _, mp := range mPlans {
		if mp.err != nil {
			return mp.err
		}
		if err := syncMirrorFiles(tctx, conn, mp.local, mp.remote, mp.mode, mp.names, remoteSums); err != nil {
			return err
		}
		if !useProber {
			if err := s.pruneRemoteDir(tctx, conn, mp.remote, mp.names); err != nil {
				return err
			}
		}
	}

	// c. api-lb guard credentials.
	if prof.guard && len(token) > 0 {
		if err := putIfChangedWithSum(tctx, conn, path.Join(cfg.GuardDir, "token"), token, "0600", remoteSums[path.Join(cfg.GuardDir, "token")]); err != nil {
			return err
		}
		if err := putIfChangedWithSum(tctx, conn, path.Join(cfg.GuardDir, "ca.crt"), ca, "0600", remoteSums[path.Join(cfg.GuardDir, "ca.crt")]); err != nil {
			return err
		}
	}

	// Read-only probe session 2 (batched dirProber/hostProber fast path): one
	// session gathers mirror ls -1pA + all orphan-tmp find scans (+ service staleness).
	staleRunning := false
	staleChecked := false
	if useProber {
		if len(varsNames) == 0 {
			return fmt.Errorf("prune %s: refusing to empty remote dir — local kept-set empty",
				cfg.RemoteVarsDir)
		}
		lsDirs := make([]string, 0, 1+len(mPlans))
		lsDirs = append(lsDirs, cfg.RemoteVarsDir)
		for _, mp := range mPlans {
			if len(mp.names) == 0 {
				return fmt.Errorf("prune %s: refusing to empty remote dir — local kept-set empty",
					mp.remote)
			}
			lsDirs = append(lsDirs, mp.remote)
		}
		var (
			lsMap     map[string][]string
			orphanMap map[string][]string
			err       error
		)
		if useHostProber {
			lsMap, orphanMap, staleRunning, err = hp.ProbeHost(tctx, lsDirs, orphanDirs, svc, cfg.RemoteBinary, cfg.UnitPath)
			staleChecked = true
		} else {
			lsMap, orphanMap, err = dp.ProbeDirs(tctx, lsDirs, orphanDirs)
		}
		if err != nil {
			return err
		}
		if err := s.removeStaleEntries(tctx, conn, cfg.RemoteVarsDir, varsNames, lsMap[cfg.RemoteVarsDir]); err != nil {
			return err
		}
		for _, mp := range mPlans {
			if err := s.removeStaleEntries(tctx, conn, mp.remote, mp.names, lsMap[mp.remote]); err != nil {
				return err
			}
		}
		for _, dir := range orphanDirs {
			s.removeOrphanEntries(tctx, conn, dir, orphanMap[dir])
		}
	}

	// d. systemd unit — write on drift, daemon-reload, then the
	// enable/restart action. `enable --now` is the steady-state /
	// fresh-install path; `restart` is required when the binary was
	// just updated or an EXISTING unit file drifted (enable --now
	// leaves a running service on the old unit).
	unit, err := systemdUnit(t, cfg.RemoteBinary, cfg.RemoteVarsDir, cfg.RemoteCertsDir)
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
	if !binaryUpdated && !unitChanged && !staleChecked {
		staleRunning, err = isRunningProcessStale(tctx, conn, svc, cfg.RemoteBinary, cfg.UnitPath)
		if err != nil {
			return err
		}
	}
	if binaryUpdated || (unitChanged && !freshUnit) || staleRunning {
		if _, err := conn.Run(tctx, "systemctl enable "+fsx.ShellQuote(svc)); err != nil {
			return err
		}
		if _, err := conn.Run(tctx, "systemctl restart "+fsx.ShellQuote(svc)); err != nil {
			return err
		}
		s.cfg.Log.Info("hubsync: service restarted after update",
			"target", t.Name, "unit", svc, "stale_running", staleRunning)
	} else {
		if _, err := conn.Run(tctx, "systemctl enable --now "+fsx.ShellQuote(svc)); err != nil {
			return err
		}
	}
	return nil
}

// staleProcessProbeScript builds a read-only shell snippet checking whether
// an active systemd service is still running an unlinked (" (deleted)")
// binary or started before the on-disk binary or unit file mtime.
func staleProcessProbeScript(svc, remoteBinary, unitPath string) string {
	qSvc := fsx.ShellQuote(svc)
	qBin := fsx.ShellQuote(remoteBinary)
	qUnit := fsx.ShellQuote(unitPath)
	return fmt.Sprintf(
		`state=$(systemctl show -p ActiveState --value %s 2>/dev/null || true); `+
			`pid=$(systemctl show -p MainPID --value %s 2>/dev/null || true); `+
			`exe=""; start_s=""; `+
			`if [ "$state" = "active" ] && [ -n "$pid" ] && [ "$pid" != "0" ]; then `+
			`exe=$(readlink "/proc/$pid/exe" 2>/dev/null || true); `+
			`ts=$(systemctl show -p ExecMainStartTimestamp --value %s 2>/dev/null || true); `+
			`if [ -n "$ts" ]; then start_s=$(date -d "$ts" +%%s 2>/dev/null || true); fi; `+
			`fi; `+
			`bin_mtime=$(stat -c %%Y %s 2>/dev/null || true); `+
			`unit_mtime=$(stat -c %%Y %s 2>/dev/null || true); `+
			`printf 'state=%%s\npid=%%s\nexe=%%s\nstart=%%s\nbin_mtime=%%s\nunit_mtime=%%s\n' "$state" "$pid" "$exe" "$start_s" "$bin_mtime" "$unit_mtime"`,
		qSvc, qSvc, qSvc, qBin, qUnit)
}

func parseStaleProcessProbe(out string) bool {
	var state, exe string
	var startS, binMtime, unitMtime int64
	for line := range strings.SplitSeq(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "state":
			state = v
		case "exe":
			exe = v
		case "start":
			startS, _ = strconv.ParseInt(v, 10, 64)
		case "bin_mtime":
			binMtime, _ = strconv.ParseInt(v, 10, 64)
		case "unit_mtime":
			unitMtime, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	if state != "" && state != "active" {
		return false
	}
	if strings.HasSuffix(exe, " (deleted)") {
		return true
	}
	if startS > 0 && (binMtime > startS || unitMtime > startS) {
		return true
	}
	return false
}

func isRunningProcessStale(ctx context.Context, conn Conn, svc, remoteBinary, unitPath string) (bool, error) {
	out, err := conn.Run(ctx, "sh -c "+fsx.ShellQuote(staleProcessProbeScript(svc, remoteBinary, unitPath)))
	if err != nil {
		return false, err
	}
	return parseStaleProcessProbe(out), nil
}

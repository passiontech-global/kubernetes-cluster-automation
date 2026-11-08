package hubsync

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/pagecache"
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
	s.markSynced()
	targets, dropped, notes, err := loadTargets(s.cfg.VarsDir)
	if err != nil {
		s.cfg.Log.Error("hubsync: target aggregation failed", "error", err)
		s.cycles.WithLabelValues("all", "parse_error").Inc()
		s.markAllKnownDown()
		return
	}
	if len(notes) > 0 {
		// topology.Load reports non-fatal resolution notes (marker
		// dups, zone/jinja eval failures) — surface and meter them,
		// but still converge the targets that did resolve.
		s.cfg.Log.Warn("hubsync: vars resolution notes — converging anyway",
			"notes", notes)
		s.cycles.WithLabelValues("all", "parse_note").Inc()
	}
	s.pruneStaleTargets(targets, dropped)
	s.lastTargets = s.lastTargets[:0]
	for _, t := range targets {
		s.lastTargets = append(s.lastTargets, t.Name)
	}
	for _, name := range dropped {
		// Inventory entry resolved to an EMPTY ip — nothing to
		// dial, but the host is still declared: keep its series
		// (last_success stays as evidence of the last good
		// converge) and read it DOWN. Dropping it from lastTargets
		// would prune the series entirely — the old loud failure
		// mode replaced by silent disappearance.
		s.lastTargets = append(s.lastTargets, name)
		s.targetUp.WithLabelValues(name).Set(0)
		s.cycles.WithLabelValues(name, "unresolved").Inc()
		s.cfg.Log.Warn("hubsync: target resolved to no ip — marked down, series kept",
			"target", name)
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

	// The local binary hash is computed ONCE per cycle — the old
	// per-target sha256File ran 10x ~15MiB disk reads per cycle on a
	// 10-target inventory (pagecache.Drop after it re-faulted the
	// same pages anyway). A hash failure aborts the whole cycle:
	// every target's binary compare needs it, same blast radius as
	// the parse error above.
	localSum, err := sha256File(s.cfg.LocalBinary)
	if err != nil {
		s.cfg.Log.Error("hubsync: local binary hash failed — cycle aborted",
			"path", s.cfg.LocalBinary, "error", err)
		s.cycles.WithLabelValues("all", "error").Inc()
		s.markAllKnownDown()
		return
	}

	converged, skipped, failed, complete := s.convergeTargets(ctx, targets, token, ca, localSum, guardOK)
	if complete {
		s.cfg.Log.Info("hubsync: converge cycle complete",
			"targets", len(targets), "converged", converged,
			"skipped", skipped, "failed", failed)
	}
}

// markAllKnownDown reads every last-known target DOWN — the shared
// abort path (parse failure, local-binary-hash failure): nothing
// converged this cycle, so every last-known target must read down
// until a good cycle runs again, otherwise target_up{...}=1 stays
// stale forever.
func (s *Syncer) markAllKnownDown() {
	for _, name := range s.lastTargets {
		s.targetUp.WithLabelValues(name).Set(0)
	}
}

// convergeTargets runs syncTarget across the cycle's targets
// serially — hub_converge used serial:1 — with the per-target
// bookkeeping: the lease re-check (split-brain guard), the api-lb
// skip when the guard credentials are unavailable, and the
// up/last_success/counter updates. It reports the tally and whether
// the loop ran to the end; a mid-cycle ctx cancellation or lost
// lease aborts silently — no summary line, same as before the split.
func (s *Syncer) convergeTargets(ctx context.Context, targets []Target,
	token, ca []byte, localSum string, guardOK bool) (converged, skipped, failed int, complete bool) {
	for i, t := range targets {
		if ctx.Err() != nil {
			return
		}
		// Re-check the hold before EVERY target — a multi-minute
		// WAN converge can easily outlive the 60s LeaseDuration if
		// the renewer stalls, and continuing would have two holders
		// SSH-converging the same fleet (split-brain).
		if !s.leaseHeld() {
			s.cfg.Log.Warn("hubsync: lease lost or lapsed mid-cycle — "+
				"aborting converge", "done", i, "remaining",
				len(targets)-i)
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
		if err := s.syncTarget(ctx, t, token, ca, localSum); err != nil {
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
	complete = true
	return
}

// pruneStaleTargets drops the metric series of targets no longer in
// the vars-derived set — a renamed/removed host would otherwise keep
// its target_up/last_success label values (and last value) on the
// registry forever. Runs only after a successful loadTargets, so a
// parse failure never prunes (the abort path zeroes instead).
// keep names hosts that ARE still in the inventory but resolved to
// no ip this cycle — they are not in targets yet their series must
// survive (they read target_up=0 as evidence, not vanish).
// (apiprober.pruneStaleBackends pattern.)
func (s *Syncer) pruneStaleTargets(targets []Target, keep []string) {
	live := make(map[string]bool, len(targets)+len(keep))
	for _, t := range targets {
		live[t.Name] = true
	}
	for _, name := range keep {
		live[name] = true
	}
	for _, name := range s.lastTargets {
		if live[name] {
			continue
		}
		s.lastSuccess.DeleteLabelValues(name)
		s.targetUp.DeleteLabelValues(name)
		// cycles carries a second label (result) — drop every series
		// whose target label matches.
		s.cycles.DeletePartialMatch(prometheus.Labels{"target": name})
		s.cfg.Log.Info("hubsync: target left vars — pruned metric series",
			"target", name)
	}
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
	token, ca = sec.Data["token"], sec.Data["ca.crt"]
	if len(token) == 0 || len(ca) == 0 {
		// A secret that exists but lacks the keys would otherwise
		// converge "ok" while pushing nothing — surface it as a
		// secret_error like a missing secret.
		return nil, nil, fmt.Errorf("secret %s/%s missing token/ca.crt data",
			s.cfg.SecretNamespace, s.cfg.SecretName)
	}
	return token, ca, nil
}

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

	// a. binary — sha256 compare, stage + chmod + atomic mv on drift.
	remoteSum, err := remoteSHA256(tctx, conn, cfg.RemoteBinary)
	if err != nil {
		return err
	}
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

// isKeyMaterial flags private-key-looking filenames — mirrored
// config lands under a shared 0644 mode, so staged key material
// would be world-readable on the target without the 0600 override.
func isKeyMaterial(name string) bool {
	n := strings.ToLower(name)
	return strings.HasSuffix(n, ".key") ||
		strings.HasSuffix(n, "key.pem") ||
		strings.Contains(n, "private")
}

// syncDir mirrors every regular file of localDir into remoteDir —
// sha256-gated per file, atomic tmp+chmod+mv writes. ConfigMap
// volumes expose keys as symlinks, so "regular" means non-dir,
// non-hidden entries; ReadFile resolves the ..data links. A non-nil
// keep filter further restricts which filenames are mirrored. Key
// material is chmod'd 0600 regardless of mode. Finally, remote files
// absent from the local set are removed — remoteDir is a dedicated
// managed dir, and a locally-deleted file would otherwise linger on
// every target forever.
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
		m := mode
		if isKeyMaterial(name) {
			m = "0600"
		}
		if err := s.putIfChanged(ctx, c, path.Join(remoteDir, name), data, m); err != nil {
			return err
		}
	}
	return s.pruneRemoteDir(ctx, c, remoteDir, names)
}

// pruneRemoteDir removes files inside remoteDir that are not in
// names — the remote-side half of the mirror. `ls -1pA` returns
// basenames (dotfiles included, no ./..) and marks directories with
// a trailing '/', so stray subdirs are skipped rather than failing
// `rm -f` forever; deletions are scoped to remoteDir by
// construction (basename joined back onto it). An EMPTY kept-set
// refuses outright: mirror semantics would rm every remote file,
// but a locally-empty dir means the SOURCE is broken (empty
// ConfigMap / failed mount), not that the target should be wiped.
// `.<name>.tmp` staging leftovers from an interrupted put are
// pruned too — but only for names absent from the kept set (a tmp
// whose file is still mirrored may be an in-flight upload).
func (s *Syncer) pruneRemoteDir(ctx context.Context, c Conn, remoteDir string, names []string) error {
	if len(names) == 0 {
		return fmt.Errorf("prune %s: refusing to empty remote dir — local kept-set empty",
			remoteDir)
	}
	out, err := c.Run(ctx, "ls -1pA "+hostutil.ShellQuote(remoteDir))
	if err != nil {
		return fmt.Errorf("ls %s: %w", remoteDir, err)
	}
	local := make(map[string]bool, len(names))
	for _, n := range names {
		local[n] = true
	}
	for _, rname := range strings.Split(out, "\n") {
		rname = strings.TrimSpace(rname)
		if rname == "" || local[rname] || strings.HasSuffix(rname, "/") {
			continue
		}
		if strings.HasPrefix(rname, ".") {
			// Dotfiles are bounded to the staging scheme — other
			// hidden files in the managed dir are not ours to
			// touch. A `.<name>.tmp` whose <name> is still kept may
			// be an in-flight upload: leave it.
			stem := strings.TrimPrefix(rname, ".")
			if !strings.HasSuffix(stem, ".tmp") ||
				local[strings.TrimSuffix(stem, ".tmp")] {
				continue
			}
		}
		if _, err := c.Run(ctx, "rm -f "+hostutil.ShellQuote(path.Join(remoteDir, rname))); err != nil {
			return fmt.Errorf("rm stale %s/%s: %w", remoteDir, rname, err)
		}
		s.cfg.Log.Info("hubsync: removed stale remote file",
			"path", path.Join(remoteDir, rname))
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
// agent binary is ~15 MiB and cycles run every few minutes — and
// drops its page-cache pages afterwards so the recurring hash does
// not pin the file in the pod's charged cache (pagecache pkg doc).
func sha256File(p string) (string, error) {
	return pagecache.Sha256File(p)
}

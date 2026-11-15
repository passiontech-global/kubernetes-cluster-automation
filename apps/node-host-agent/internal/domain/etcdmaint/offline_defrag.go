// offline_defrag.go — the planned-downtime defrag (the stage-3
// fallback): stop k0scontroller, respawn the same etcd binary
// standalone on the same data-dir, defrag, SIGTERM it, restart the
// service — plus the health probe it polls and the production
// TempEtcd impl (tempEtcdProc / startTempEtcdExec).
package etcdmaint

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostexec"
)

// waitHealthy polls `endpoint health` up to tries times (1s cadence)
// — the post-stop/start equivalent of the script's `ss -tln | grep
// :2379` loop, but asserting an actual healthy member. It probes the
// LIVE endpoint (certArgs): only the post-restart wait uses it.
func (r *rescuer) waitHealthy(ctx context.Context, tries int) error {
	return r.waitHealthyVia(ctx, tries, r.etcdctl, "etcd")
}

// waitTempHealthy is waitHealthy aimed at the standalone defrag
// etcd — etcdctlTemp's bare loopback endpoint, no certs.
func (r *rescuer) waitTempHealthy(ctx context.Context, tries int) error {
	return r.waitHealthyVia(ctx, tries, r.etcdctlTemp, "standalone etcd")
}

// waitHealthyVia is the shared health-poll body: call is the
// etcdctl flavour (live certArgs vs temp loopback endpoint) and
// what names the member in the timeout error.
func (r *rescuer) waitHealthyVia(ctx context.Context, tries int,
	call func(context.Context, string, ...string) ([]byte, error),
	what string) error {
	if cycle.Poll(ctx, tries, time.Second, func() bool {
		_, err := call(ctx, healthProbeTimeout,
			"endpoint", "health")
		return err == nil
	}, r.cfg.SleepFn) {
		return nil
	}
	return fmt.Errorf("%s still unhealthy after %ds", what, tries)
}

// offlineDefrag is the script's `systemctl stop -> standalone etcd ->
// defrag -> kill -> systemctl start` block. Once the service is
// stopped the deferred restart ALWAYS runs — the script under set -e
// would have left the control plane down on any mid-block failure.
func (r *rescuer) offlineDefrag(ctx context.Context) (err error) {
	pid, flags, err := r.findEtcdProcess()
	if err != nil {
		return err // service never stopped — nothing to restore
	}
	_, _ = fmt.Fprintf(r.out,
		">>> etcd pid=%d data-dir=%s quota-backend-bytes=%s\n",
		pid,
		flagValue(flags, "--data-dir", filepath.Join(r.cfg.K0sDir, "etcd")),
		flagValue(flags, "--quota-backend-bytes", defaultQuotaFlag))

	if _, serr := r.systemctl(ctx, "stop"); serr != nil {
		return fmt.Errorf("systemctl stop %s: %w", r.cfg.Svc, serr)
	}
	_, _ = fmt.Fprintf(r.out, ">>> %s stopped — starting standalone etcd\n",
		r.cfg.Svc)
	// From here the service is down: ALWAYS start it again and wait
	// for the k0s-managed etcd to come back healthy, even when a
	// later step fails or the caller's ctx got cancelled mid-wait.
	defer func() {
		dctx := context.WithoutCancel(ctx)
		if _, serr := r.systemctl(dctx, "start"); serr != nil {
			_, _ = fmt.Fprintf(r.out, ">>> systemctl start %s failed: %v\n",
				r.cfg.Svc, serr)
			if err == nil {
				err = fmt.Errorf("systemctl start %s: %w", r.cfg.Svc, serr)
			}
			return
		}
		if herr := r.waitHealthy(dctx, postStartHealthTries); herr != nil {
			_, _ = fmt.Fprintf(r.out,
				">>> %s not healthy after restart: %v\n", r.cfg.Svc, herr)
			if err == nil {
				err = fmt.Errorf("etcd unhealthy after %s restart: %w",
					r.cfg.Svc, herr)
			}
		}
	}()

	if werr := r.waitPidExit(ctx, pid); werr != nil {
		return werr
	}

	// The starter creates a private 0700 dir + O_EXCL 0600 log under
	// this parent (never a fixed /tmp/etcd-standalone.log — see
	// startTempEtcdExec). The file survives the run for post-mortem.
	_, _ = fmt.Fprintf(r.out,
		">>> standalone etcd log: %s/etcd-standalone-*/etcd-standalone-*.log\n",
		os.TempDir())
	tmp, terr := r.cfg.StartTempEtcd(ctx, r.etcdBin,
		tempEtcdArgs(flags, filepath.Join(r.cfg.K0sDir, "etcd")),
		os.TempDir())
	if terr != nil {
		return fmt.Errorf("start standalone etcd: %w", terr)
	}
	if herr := r.waitTempHealthy(ctx, tempEtcdHealthTries); herr != nil {
		if kerr := tmp.Kill(); kerr != nil { // SIGTERM — grace before reap
			_, _ = fmt.Fprintf(r.out, "(kill standalone etcd: %v)\n", kerr)
		}
		_ = tmp.Wait()
		return fmt.Errorf("standalone etcd never came up: %w", herr)
	}

	_, derr := r.etcdctlTemp(ctx, offlineDefragTimeout, "defrag")
	if kerr := tmp.Kill(); kerr != nil {
		_, _ = fmt.Fprintf(r.out, "(kill standalone etcd: %v)\n", kerr)
	}
	_ = tmp.Wait()
	if derr != nil {
		return fmt.Errorf("offline defrag: %w", derr)
	}
	_, _ = fmt.Fprintln(r.out, ">>> offline defrag done")
	return nil
}

// tempEtcdPeerURL is the throwaway peer port the standalone defrag
// etcd binds — paired with tempEtcdClientURL (plumbing.go) so the
// whole member lives on loopback ports nothing else uses.
const tempEtcdPeerURL = "http://127.0.0.1:22380"

// tempEtcdArgs builds the fully isolated argv for the standalone
// defrag etcd. The captured live flags CANNOT be reused verbatim:
// their --listen-*/--advertise-*/--initial-* entries still name the
// real :2379/:2380 member — a temp etcd inheriting them would try
// to serve (and rejoin) the live cluster shape while
// k0scontroller is stopped, and its client listener would answer on
// the production port with throwaway state. Only --data-dir,
// --quota-backend-bytes and --name carry over; every URL and the
// cluster bootstrap are pinned to loopback throwaway ports and
// --force-new-cluster re-initializes the single-member store from
// the existing data-dir (the disaster-recovery flag etcd documents
// for exactly this offline-rewrite case).
func tempEtcdArgs(flags []string, dataDirDef string) []string {
	name := flagValue(flags, "--name", "default")
	return []string{
		"--data-dir=" + flagValue(flags, "--data-dir", dataDirDef),
		"--name=" + name,
		"--quota-backend-bytes=" +
			flagValue(flags, "--quota-backend-bytes", defaultQuotaFlag),
		"--initial-cluster=" + name + "=" + tempEtcdPeerURL,
		"--listen-peer-urls=" + tempEtcdPeerURL,
		"--initial-advertise-peer-urls=" + tempEtcdPeerURL,
		"--listen-client-urls=" + tempEtcdClientURL,
		"--advertise-client-urls=" + tempEtcdClientURL,
		"--force-new-cluster=true",
	}
}

// --- production TempEtcd impl ---

// tempEtcdProc wraps an exec.Cmd + its log file as a TempEtcd. Kill is
// the script's `kill "$STANDALONE"` (SIGTERM — etcd flushes and drops
// the bbolt data-dir lock on a clean shutdown); Wait gives it
// killGracePeriod before escalating to SIGKILL.
type tempEtcdProc struct {
	cmd *exec.Cmd
	log *os.File
}

func (t *tempEtcdProc) Kill() error {
	if t.cmd.Process == nil {
		return nil
	}
	return t.cmd.Process.Signal(syscall.SIGTERM)
}

func (t *tempEtcdProc) Wait() error {
	done := make(chan error, 1)
	go func() { done <- t.cmd.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-time.After(killGracePeriod):
		if t.cmd.Process != nil {
			_ = t.cmd.Process.Kill()
		}
		err = <-done
	}
	_ = t.log.Close()
	return err
}

// startTempEtcdExec is the default TempEtcdStarter: etcd's stdout and
// stderr land in a fresh log file under parentDir (the script's
// /tmp/etcd-standalone.log role). CommandContext (not a bare Command)
// means a cancelled ctx also kills the standalone — it holds the
// data-dir lock, and leaving it would block the deferred
// `systemctl start` from recovering etcd.
//
// The log is NOT a fixed, predictable name under the shared /tmp
// opened as root: a pre-planted symlink/fifo at that path races the
// O_TRUNC (clobbering the link target) and fs.protected_regular=2
// makes the root-owned open EACCES outright. Instead a fresh 0700
// dir is created (MkdirTemp — a name no attacker can pre-plant) and
// the log opened with os.CreateTemp's O_EXCL semantics inside it,
// chmod'd 0600 — etcd output carries peer URLs/flags and must not
// be world-readable.
func startTempEtcdExec(ctx context.Context, bin string,
	args []string, parentDir string) (TempEtcd, error) {
	if parentDir == "" {
		parentDir = os.TempDir()
	}
	d, err := os.MkdirTemp(parentDir, "etcd-standalone-")
	if err != nil {
		return nil, err
	}
	// MkdirTemp creates 0700 already; the Chmod re-asserts it in
	// case a umask/override weakened the parent's semantics.
	if err := os.Chmod(d, 0o700); err != nil {
		_ = os.Remove(d)
		return nil, err
	}
	f, err := os.CreateTemp(d, "etcd-standalone-*.log")
	if err != nil {
		_ = os.Remove(d)
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.RemoveAll(d)
		return nil, err
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	// Scrub the sd_notify vars: on a standalone host the temp etcd
	// must not inherit NOTIFY_SOCKET and sd_notify back into OUR
	// unit on exit (systemd>=255 auto-sends EXIT_STATUS on exec) —
	// the same hazard hostexec.RunEnv exists for.
	cmd.Env = hostexec.ScrubSystemdEnv(os.Environ())
	// A cancelled ctx must NOT SIGKILL etcd mid-defrag — a hard kill
	// on live bbolt data files risks corruption and leaves the
	// data-dir lock unreleased. Send SIGTERM (the script's
	// `kill "$STANDALONE"` parity: etcd flushes and drops the lock
	// cleanly), and only escalate to SIGKILL if the killGracePeriod
	// WaitDelay elapses.
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	cmd.WaitDelay = killGracePeriod
	cmd.Stdout = f
	cmd.Stderr = f
	if err := cmd.Start(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &tempEtcdProc{cmd: cmd, log: f}, nil
}

// procscan.go — the /proc scanning the offline-defrag stage needs:
// find the running k0s etcd (pid + verbatim argv to respawn
// standalone on the same data-dir), then wait for that pid to be
// fully gone — zombie counts as exited — before the standalone
// opens the data-dir and before k0scontroller restarts.
package etcdmaint

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
)

// waitPidExit polls /proc/<pid> until the process is gone — the old
// etcd must be fully dead before the standalone opens the same
// data-dir. A zombie keeps its /proc entry but is already dead (fds
// and the bbolt lock released), so state Z counts as exited instead
// of stalling the full wait budget.
func (r *rescuer) waitPidExit(ctx context.Context, pid int) error {
	procDir := filepath.Join(r.cfg.ProcRoot, strconv.Itoa(pid))
	if cycle.Poll(ctx, pidExitWaitTries, time.Second, func() bool {
		if _, err := os.Stat(procDir); os.IsNotExist(err) {
			return true
		}
		return r.procZombie(pid)
	}, r.cfg.SleepFn) {
		return nil
	}
	return fmt.Errorf("etcd pid %d did not exit after %ds",
		pid, pidExitWaitTries)
}

// procZombie reports whether /proc/<pid>/stat shows process state Z.
// procfs.Stat reads fields after the LAST ')' — comm is parenthesised
// and may itself contain spaces or parens, so the state field stays
// Fields[0] regardless of what comm holds.
func (r *rescuer) procZombie(pid int) bool {
	st, ok := r.proc.Stat(pid)
	return ok && st.Fields[0] == "Z"
}

// matchEtcdCmdline reports whether a /proc/<pid>/cmdline blob belongs
// to the k0s etcd: argv[0] must equal etcdBin — a HasPrefix alone
// would also match `.../bin/etcdctl` (itself a prefix extension).
func matchEtcdCmdline(cmdline []byte, etcdBin string) bool {
	if !bytes.HasPrefix(cmdline, []byte(etcdBin)) {
		return false
	}
	rest := cmdline[len(etcdBin):]
	return len(rest) == 0 || rest[0] == 0
}

// findEtcdProcess scans ProcRoot for the running k0s etcd — the
// script's `pgrep -f '<k0s>/bin/etcd' | head -1` — and returns its
// pid plus argv[1:] verbatim (the script reused those flags for the
// standalone: --data-dir, --initial-cluster*, listen/advertise URLs,
// cert paths all come along for free).
func (r *rescuer) findEtcdProcess() (int, []string, error) {
	pids, err := r.proc.PIDs()
	if err != nil {
		return 0, nil, fmt.Errorf("read %s: %w", r.cfg.ProcRoot, err)
	}
	slices.Sort(pids)
	for _, pid := range pids {
		// Raw cmdline bytes, not procfs.Cmdline: matchEtcdCmdline's
		// argv[0] boundary check and the verbatim argv[1:] capture
		// (interior empty args preserved) are byte-exact contracts.
		cl, rerr := os.ReadFile(r.proc.File(pid, "cmdline"))
		if rerr != nil || len(cl) == 0 {
			continue
		}
		if !matchEtcdCmdline(cl, r.etcdBin) {
			continue
		}
		var flags []string
		for i, a := range strings.Split(string(cl), "\x00") {
			if i == 0 { // drop argv[0] only
				continue
			}
			flags = append(flags, a)
		}
		// cmdline ends in a NUL, so the split leaves one trailing ""
		// — drop ONLY that. Interior empty elements are legitimate
		// empty flag values; removing them would shift every
		// flag→value pairing (flagValue + the standalone argv).
		if n := len(flags); n > 0 && flags[n-1] == "" {
			flags = flags[:n-1]
		}
		return pid, flags, nil
	}
	return 0, nil, errors.New(
		"no running etcd process found to capture flags from")
}

// flagValue extracts --name=value (or `--name value`) from the
// captured etcd flags, for logging.
func flagValue(flags []string, name, def string) string {
	for i, f := range flags {
		if v, ok := strings.CutPrefix(f, name+"="); ok {
			return v
		}
		if f == name && i+1 < len(flags) {
			return flags[i+1]
		}
	}
	return def
}

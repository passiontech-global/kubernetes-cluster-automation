// Package etcdrescue ports scripts/rescue-etcd.sh — rescues a k0s
// controller etcd that hit the backend quota.
//
// Symptom: every write fails with
//
//	Error from server: etcdserver: mvcc: database space exceeded
//
// (no new pods, no deletes, control plane crash-looping). Run as root
// ON the controller host. The flow is the script's:
//
//  1. print `endpoint status` + `alarm list` (before snapshot)
//  2. `compact --physical <head revision>` — drop MVCC history
//  3. try ONLINE `defrag`; re-read status — when it errored or
//     dbSize > dbSizeInUse*2, fall back to OFFLINE defrag (~2min
//     downtime: stop k0scontroller, run the same etcd standalone on
//     the same data-dir, defrag, kill it, restart the service)
//  4. print post-defrag status
//  5. `alarm disarm` — the NOSPACE alarm never self-clears
//  6. write canary (put/del /__rescue_canary) + final status/advice
//
// Field notes carried over from the script (PAS-382, 2026-08-23):
// online defrag can report OK yet reclaim nothing while the apiserver
// is crash-looping writes — hence the dbSize/dbSizeInUse comparison —
// and `alarm disarm` is mandatory because NOSPACE never clears itself.
package etcdrescue

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Defaults mirror rescue-etcd.sh.
const (
	defaultK0sDir    = "/var/lib/k0s"
	defaultEndpoint  = "https://127.0.0.1:2379"
	defaultProcRoot  = "/proc"
	defaultSvc       = "k0scontroller"
	defaultQuotaFlag = "8589934592" // --quota-backend-bytes reference default

	// Per-call etcdctl --command-timeout: the script's e() wrapper
	// used 600s on everything; the defrag calls get their own
	// budgets like the plan calls for.
	defaultEtcdTimeout   = "600s"
	onlineDefragTimeout  = "120s"
	offlineDefragTimeout = "180s"
	healthProbeTimeout   = "10s"

	// Wait budgets, in 1s tries (script slept 5s unconditionally,
	// then polled :2379 for 30s).
	pidExitWaitTries     = 30               // old etcd gone after systemctl stop
	tempEtcdHealthTries  = 30               // standalone etcd accepting clients
	postStartHealthTries = 60               // k0scontroller's etcd back up
	killGracePeriod      = 10 * time.Second // SIGTERM -> SIGKILL

	// CallTimeout caps every spawned command context — a hung
	// etcdctl must not wedge the rescue past its own
	// --command-timeout by much.
	defaultCallTimeout = 10 * time.Minute

	canaryKey = "/__rescue_canary"
)

// CmdRunner executes `name args...` and returns stdout with stderr
// captured separately — the single exec seam (etcdctl + systemctl).
// The default wires exec.CommandContext; ETCDCTL_API is NOT set
// (etcdctl >=3.7 warns on it and v3 is the default anyway).
type CmdRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// TempEtcd is a started standalone-etcd child process.
type TempEtcd interface {
	// Kill asks the process to stop — SIGTERM, like the script's
	// `kill "$STANDALONE"`, so etcd can flush and release the bbolt
	// data-dir lock cleanly before k0scontroller restarts.
	Kill() error
	// Wait reaps the process after Kill — escalating to SIGKILL if
	// the SIGTERM grace period (killGracePeriod) expires.
	Wait() error
}

// TempEtcdStarter spawns `<k0s>/bin/etcd` with the captured live
// flags, redirecting output to logPath — the script's
// `/var/lib/k0s/bin/etcd "${FLAGS[@]}" >/tmp/etcd-standalone.log 2>&1 &`.
type TempEtcdStarter func(ctx context.Context, bin string,
	args []string, logPath string) (TempEtcd, error)

// Config carries the rescue inputs — every field test-injectable.
type Config struct {
	K0sDir   string // "" → /var/lib/k0s (derives bin/etcd*, pki paths)
	Endpoint string // "" → https://127.0.0.1:2379
	ProcRoot string // "" → /proc (scanned for the running etcd)
	Svc      string // "" → k0scontroller (systemd unit stop/start)
	// ForceOffline skips the online-defrag attempt entirely.
	ForceOffline bool
	// OnlineOnly forbids the offline-defrag path outright —
	// background auto-maintenance must never stop k0scontroller.
	// When the run still needs offline (the online defrag errored or
	// reclaimed too little) the remaining online steps (disarm +
	// write canary) still complete and Run returns an error noting
	// the required manual follow-up instead of taking the downtime.
	// Wins over ForceOffline.
	OnlineOnly bool
	// CallTimeout caps each spawned command's context; <=0 → 10min.
	CallTimeout time.Duration

	// --- injectable seams (defaults follow) ---
	CmdRunner     CmdRunner
	StartTempEtcd TempEtcdStarter
	SleepFn       func(time.Duration)
}

func (c *Config) applyDefaults() {
	if c.K0sDir == "" {
		c.K0sDir = defaultK0sDir
	}
	if c.Endpoint == "" {
		c.Endpoint = defaultEndpoint
	}
	if c.ProcRoot == "" {
		c.ProcRoot = defaultProcRoot
	}
	if c.Svc == "" {
		c.Svc = defaultSvc
	}
	if c.CallTimeout <= 0 {
		c.CallTimeout = defaultCallTimeout
	}
	if c.CmdRunner == nil {
		c.CmdRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			cmd := exec.CommandContext(ctx, name, args...)
			// etcdctl >=3.7 warns "unrecognized environment variable
			// ETCDCTL_API" on stderr — v3 is the default API anyway.
			// stderr is kept separate: -w json output must parse, so
			// CombinedOutput would poison the payload.
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil {
				return out, fmt.Errorf("%w: %s", err,
					strings.TrimSpace(stderr.String()))
			}
			return out, nil
		}
	}
	if c.StartTempEtcd == nil {
		c.StartTempEtcd = startTempEtcdExec
	}
	if c.SleepFn == nil {
		c.SleepFn = time.Sleep
	}
}

// endpointStatus is the slice of `endpoint status -w json` element[0]
// the script extracted via python3.
type endpointStatus struct {
	DBSize      int64
	DBSizeInUse int64
	Revision    int64
}

// parseStatusJSON decodes `etcdctl endpoint status -w json` (a JSON
// array of per-endpoint entries; the script read [0].Status).
func parseStatusJSON(b []byte) (endpointStatus, error) {
	var arr []struct {
		Status struct {
			Header struct {
				Revision int64 `json:"revision"`
			} `json:"header"`
			DBSize      int64 `json:"dbSize"`
			DBSizeInUse int64 `json:"dbSizeInUse"`
		} `json:"Status"`
	}
	if err := json.Unmarshal(b, &arr); err != nil {
		return endpointStatus{}, fmt.Errorf("parse status json: %w", err)
	}
	if len(arr) == 0 {
		return endpointStatus{}, errors.New("parse status json: empty endpoint list")
	}
	st := arr[0].Status
	return endpointStatus{
		DBSize:      st.DBSize,
		DBSizeInUse: st.DBSizeInUse,
		Revision:    st.Header.Revision,
	}, nil
}

// rescuer bundles cfg + output with the derived binary/cert paths.
type rescuer struct {
	cfg        Config
	out        io.Writer
	etcdctlBin string
	etcdBin    string
	certArgs   []string
}

func newRescuer(cfg Config, out io.Writer) *rescuer {
	return &rescuer{
		cfg:        cfg,
		out:        out,
		etcdctlBin: filepath.Join(cfg.K0sDir, "bin", "etcdctl"),
		etcdBin:    filepath.Join(cfg.K0sDir, "bin", "etcd"),
		// The script's CERTS array — apiserver etcd client certs,
		// not the etcd server certs (ground truth: rescue-etcd.sh).
		certArgs: []string{
			"--cacert=" + filepath.Join(cfg.K0sDir, "pki", "etcd", "ca.crt"),
			"--cert=" + filepath.Join(cfg.K0sDir, "pki", "apiserver-etcd-client.crt"),
			"--key=" + filepath.Join(cfg.K0sDir, "pki", "apiserver-etcd-client.key"),
			"--endpoints=" + cfg.Endpoint,
		},
	}
}

// etcdctl runs `etcdctl <certs> --command-timeout=<timeout> args...`
// (the script's e() wrapper). Empty timeout → 600s like e().
func (r *rescuer) etcdctl(ctx context.Context, timeout string,
	args ...string) ([]byte, error) {
	if timeout == "" {
		timeout = defaultEtcdTimeout
	}
	argv := make([]string, 0, len(r.certArgs)+len(args)+1)
	argv = append(argv, r.certArgs...)
	argv = append(argv, "--command-timeout="+timeout)
	argv = append(argv, args...)
	cctx, cancel := context.WithTimeout(ctx, r.cfg.CallTimeout)
	defer cancel()
	return r.cfg.CmdRunner(cctx, r.etcdctlBin, argv...)
}

func (r *rescuer) systemctl(ctx context.Context, action string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, r.cfg.CallTimeout)
	defer cancel()
	return r.cfg.CmdRunner(cctx, "systemctl", action, r.cfg.Svc)
}

// status fetches `endpoint status -w json` and parses element[0].
func (r *rescuer) status(ctx context.Context) (endpointStatus, error) {
	b, err := r.etcdctl(ctx, "", "endpoint", "status", "-w", "json")
	if err != nil {
		return endpointStatus{}, err
	}
	return parseStatusJSON(b)
}

// printAlarmList streams `alarm list` output (tolerated — the
// script's `|| true`); empty output prints the fallback note.
func (r *rescuer) printAlarmList(ctx context.Context, emptyNote string) {
	al, err := r.etcdctl(ctx, "", "alarm", "list")
	if err != nil {
		fmt.Fprintf(r.out, "(alarm list error: %v)\n", err)
		return
	}
	if len(bytes.TrimSpace(al)) == 0 {
		fmt.Fprintln(r.out, emptyNote)
		return
	}
	_, _ = r.out.Write(al)
}

// waitHealthy polls `endpoint health` up to tries times (1s cadence)
// — the post-stop/start equivalent of the script's `ss -tln | grep
// :2379` loop, but asserting an actual healthy member.
func (r *rescuer) waitHealthy(ctx context.Context, tries int) error {
	for i := 0; i < tries; i++ {
		if _, err := r.etcdctl(ctx, healthProbeTimeout,
			"endpoint", "health"); err == nil {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		r.cfg.SleepFn(time.Second)
	}
	return fmt.Errorf("etcd still unhealthy after %ds", tries)
}

// waitPidExit polls /proc/<pid> until the process is gone — the old
// etcd must be fully dead before the standalone opens the same
// data-dir. A zombie keeps its /proc entry but is already dead (fds
// and the bbolt lock released), so state Z counts as exited instead
// of stalling the full wait budget.
func (r *rescuer) waitPidExit(ctx context.Context, pid int) error {
	procDir := filepath.Join(r.cfg.ProcRoot, strconv.Itoa(pid))
	statFile := filepath.Join(procDir, "stat")
	for i := 0; i < pidExitWaitTries; i++ {
		if _, err := os.Stat(procDir); os.IsNotExist(err) {
			return nil
		}
		if procZombie(statFile) {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		r.cfg.SleepFn(time.Second)
	}
	return fmt.Errorf("etcd pid %d did not exit after %ds",
		pid, pidExitWaitTries)
}

// procZombie reports whether a /proc/<pid>/stat file shows process
// state Z. comm is parenthesised and may itself contain spaces or
// parens, so the state field is the first token after the LAST ')'.
func procZombie(statFile string) bool {
	data, err := os.ReadFile(statFile)
	if err != nil {
		return false
	}
	i := bytes.LastIndexByte(data, ')')
	if i < 0 {
		return false
	}
	f := strings.Fields(string(data[i+1:]))
	return len(f) > 0 && f[0] == "Z"
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
	entries, err := os.ReadDir(r.cfg.ProcRoot)
	if err != nil {
		return 0, nil, fmt.Errorf("read %s: %w", r.cfg.ProcRoot, err)
	}
	var pids []int
	for _, e := range entries {
		if pid, cerr := strconv.Atoi(e.Name()); cerr == nil && e.IsDir() {
			pids = append(pids, pid)
		}
	}
	slices.Sort(pids)
	for _, pid := range pids {
		cl, rerr := os.ReadFile(filepath.Join(r.cfg.ProcRoot,
			strconv.Itoa(pid), "cmdline"))
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

// offlineDefrag is the script's `systemctl stop -> standalone etcd ->
// defrag -> kill -> systemctl start` block. Once the service is
// stopped the deferred restart ALWAYS runs — the script under set -e
// would have left the control plane down on any mid-block failure.
func (r *rescuer) offlineDefrag(ctx context.Context) (err error) {
	pid, flags, err := r.findEtcdProcess()
	if err != nil {
		return err // service never stopped — nothing to restore
	}
	fmt.Fprintf(r.out,
		">>> etcd pid=%d data-dir=%s quota-backend-bytes=%s\n",
		pid,
		flagValue(flags, "--data-dir", filepath.Join(r.cfg.K0sDir, "etcd")),
		flagValue(flags, "--quota-backend-bytes", defaultQuotaFlag))

	if _, serr := r.systemctl(ctx, "stop"); serr != nil {
		return fmt.Errorf("systemctl stop %s: %w", r.cfg.Svc, serr)
	}
	fmt.Fprintf(r.out, ">>> %s stopped — starting standalone etcd\n",
		r.cfg.Svc)
	// From here the service is down: ALWAYS start it again and wait
	// for the k0s-managed etcd to come back healthy, even when a
	// later step fails or the caller's ctx got cancelled mid-wait.
	defer func() {
		dctx := context.WithoutCancel(ctx)
		if _, serr := r.systemctl(dctx, "start"); serr != nil {
			fmt.Fprintf(r.out, ">>> systemctl start %s failed: %v\n",
				r.cfg.Svc, serr)
			if err == nil {
				err = fmt.Errorf("systemctl start %s: %w", r.cfg.Svc, serr)
			}
			return
		}
		if herr := r.waitHealthy(dctx, postStartHealthTries); herr != nil {
			fmt.Fprintf(r.out,
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

	// Fixed log path like the script's /tmp/etcd-standalone.log —
	// survives the run for post-mortem and never accumulates tempdirs.
	logPath := filepath.Join(os.TempDir(), "etcd-standalone.log")
	fmt.Fprintf(r.out, ">>> standalone etcd log: %s\n", logPath)
	tmp, terr := r.cfg.StartTempEtcd(ctx, r.etcdBin, flags, logPath)
	if terr != nil {
		return fmt.Errorf("start standalone etcd: %w", terr)
	}
	if herr := r.waitHealthy(ctx, tempEtcdHealthTries); herr != nil {
		if kerr := tmp.Kill(); kerr != nil { // SIGTERM — grace before reap
			fmt.Fprintf(r.out, "(kill standalone etcd: %v)\n", kerr)
		}
		_ = tmp.Wait()
		return fmt.Errorf("standalone etcd never came up: %w", herr)
	}

	_, derr := r.etcdctl(ctx, offlineDefragTimeout, "defrag")
	if kerr := tmp.Kill(); kerr != nil {
		fmt.Fprintf(r.out, "(kill standalone etcd: %v)\n", kerr)
	}
	_ = tmp.Wait()
	if derr != nil {
		return fmt.Errorf("offline defrag: %w", derr)
	}
	fmt.Fprintln(r.out, ">>> offline defrag done")
	return nil
}

// Run executes the six-step rescue flow, printing progress in the
// script's phrasing. Returns an error (→ exit 1) on any fatal step —
// including a failed write canary, matching the script's exit-1 tail.
func Run(ctx context.Context, cfg Config, out io.Writer) error {
	cfg.applyDefaults()
	r := newRescuer(cfg, out)

	// [1/6] Before-snapshot: table for humans, json for the numbers,
	// then the alarm list (|| true in the script).
	fmt.Fprintln(out, "[1/6] ===== BEFORE RESCUE =====")
	tbl, err := r.etcdctl(ctx, "", "endpoint", "status", "-w", "table")
	if err != nil {
		return fmt.Errorf("endpoint status: %w", err)
	}
	_, _ = out.Write(tbl)
	st, err := r.status(ctx)
	if err != nil {
		return fmt.Errorf("endpoint status -w json: %w", err)
	}
	fmt.Fprintf(out, "dbSize=%d dbSizeInUse=%d revision=%d\n",
		st.DBSize, st.DBSizeInUse, st.Revision)
	r.printAlarmList(ctx, "alarm list: (none)")

	// [2/6] Compact all MVCC history to the head revision. The
	// script's `|| echo` tolerated ANY compact failure — keep that,
	// but print the real error: a timeout/auth/network failure must
	// not masquerade as "already compacted".
	fmt.Fprintf(out, "[2/6] >>> compact to revision %d\n", st.Revision)
	if _, err := r.etcdctl(ctx, "", "compact", "--physical",
		strconv.FormatInt(st.Revision, 10)); err != nil {
		fmt.Fprintf(out, "(compact error — skipping: %v)\n", err)
	}

	// [3/6] Online defrag first (no downtime). Field-proven caveat:
	// it can report OK yet reclaim nothing while the apiserver is
	// crash-looping writes, so the decision uses dbSize vs
	// dbSizeInUse — and a defrag error also forces offline.
	needOffline := cfg.ForceOffline
	switch {
	case cfg.ForceOffline && cfg.OnlineOnly:
		// Contradictory flags — OnlineOnly is the safety promise
		// (no control-plane stop), so it degrades the flag pair to
		// a plain online attempt.
		fmt.Fprintln(out, "[3/6] >>> --force-offline ignored under OnlineOnly")
		needOffline = false
	case cfg.ForceOffline:
		fmt.Fprintln(out, "[3/6] >>> --force-offline: skipping online defrag")
	}
	if !needOffline {
		fmt.Fprintln(out, "[3/6] >>> trying online defrag...")
		if _, err := r.etcdctl(ctx, onlineDefragTimeout, "defrag"); err != nil {
			fmt.Fprintln(out,
				">>> online defrag failed/missing — falling back to offline")
			needOffline = true
		} else if st2, serr := r.status(ctx); serr != nil {
			return fmt.Errorf("endpoint status after defrag: %w", serr)
		} else if st2.DBSize > st2.DBSizeInUse*2 {
			fmt.Fprintf(out,
				">>> online defrag reclaimed too little "+
					"(file=%d, in-use=%d) → OFFLINE DEFRAG\n",
				st2.DBSize, st2.DBSizeInUse)
			needOffline = true
		}
	}
	offlinePending := false
	if needOffline {
		if cfg.OnlineOnly {
			// The systemctl-stop + standalone-etcd block is a
			// planned-downtime action — never taken by a background
			// loop. Disarm + canary still run below (they often
			// restore writes already); the tail then reports the
			// remaining bloat as an error.
			fmt.Fprintln(out, ">>> ONLINE-ONLY: offline defrag "+
				"required but forbidden — needs a manual rescue-etcd run")
			offlinePending = true
		} else if err := r.offlineDefrag(ctx); err != nil {
			return err // service restart already handled by the defer
		}
	}

	// [4/6] Post-defrag numbers (display only — a flaky read here
	// must not mask the real health check, the canary).
	fmt.Fprintln(out, "[4/6] Post-defrag status:")
	if st3, serr := r.status(ctx); serr == nil {
		fmt.Fprintf(out, "dbSize=%d dbSizeInUse=%d revision=%d\n",
			st3.DBSize, st3.DBSizeInUse, st3.Revision)
	} else {
		fmt.Fprintf(out, "(endpoint status error: %v)\n", serr)
	}

	// [5/6] NOSPACE alarms never self-clear after space is freed —
	// disarm is mandatory. Fatal like the script's `set -e`.
	fmt.Fprintln(out, "[5/6] >>> alarm disarm (NOSPACE never self-clears)")
	if _, err := r.etcdctl(ctx, "", "alarm", "disarm"); err != nil {
		return fmt.Errorf("alarm disarm: %w", err)
	}
	r.printAlarmList(ctx, "alarm list: (clean)")

	// [6/6] Write canary — the actual proof etcd accepts writes
	// again. A failure exits 1 like the script.
	fmt.Fprintln(out, "[6/6] >>> verifying writes (canary put/del)")
	if _, err := r.etcdctl(ctx, "", "put", canaryKey, "ok"); err != nil {
		return fmt.Errorf(">>> WRITE STILL FAILING — "+
			"check alarm/status manually! (put: %w)", err)
	}
	if _, err := r.etcdctl(ctx, "", "del", canaryKey); err != nil {
		return fmt.Errorf(">>> WRITE STILL FAILING — "+
			"check alarm/status manually! (del: %w)", err)
	}
	fmt.Fprintln(out, ">>> WRITE OK — etcd is back")

	fmt.Fprintln(out, "===== AFTER RESCUE =====")
	if tbl, err := r.etcdctl(ctx, "",
		"endpoint", "status", "-w", "table"); err == nil {
		_, _ = out.Write(tbl)
	}
	fmt.Fprintf(out, `
===== DONE =====
Next steps:
- After TTL GC finishes reaping events (a few hours), re-run this to reclaim more
- Check control-plane crash-loops: systemctl status %s
- If the service keeps restarting: journalctl -u %s and dmesg | grep -i oom
`, r.cfg.Svc, r.cfg.Svc)
	if offlinePending {
		return errors.New("etcd still bloated — offline defrag " +
			"required (rerun rescue-etcd manually, without OnlineOnly)")
	}
	return nil
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
// stderr land in logPath like the script's /tmp/etcd-standalone.log.
// CommandContext (not a bare Command) means a cancelled ctx also
// kills the standalone — it holds the data-dir lock, and leaving it
// would block the deferred `systemctl start` from recovering etcd.
func startTempEtcdExec(ctx context.Context, bin string,
	args []string, logPath string) (TempEtcd, error) {
	// logPath is a predictable name under the shared /tmp opened as
	// root — a pre-planted symlink would have O_TRUNC clobber its
	// target before the Chmod below ever runs. Two layers: the
	// Lstat gives a diagnosable refusal, and O_NOFOLLOW closes the
	// plant-between-check-and-open race.
	if fi, err := os.Lstat(logPath); err == nil &&
		fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("temp etcd log %s is a symlink — refusing",
			logPath)
	}
	f, err := os.OpenFile(logPath,
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	// 0o600 only applies on O_CREATE — a leftover log from a prior
	// run keeps its old mode. Force it: the etcd output can carry
	// peer URLs/flags and must not stay world-readable.
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, err
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = f
	cmd.Stderr = f
	if err := cmd.Start(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &tempEtcdProc{cmd: cmd, log: f}, nil
}

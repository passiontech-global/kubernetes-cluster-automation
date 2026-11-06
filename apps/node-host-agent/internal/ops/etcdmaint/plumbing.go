// plumbing.go — shared plumbing every rescue stage runs through:
// the script's defaults, Config + the injectable exec seams
// (CmdRunner, TempEtcd/TempEtcdStarter), the rescuer's
// etcdctl/systemctl wrappers, and the alarm-list output helper.
// Stage machinery lives in status.go (endpoint-status decode),
// procscan.go (/proc scanning) and offline_defrag.go (the
// planned-downtime defrag + standalone-etcd impl).
package etcdmaint

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostexec"
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
// The default wires hostexec.Run; ETCDCTL_API is NOT set
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
			// etcdctl >=3.7 warns "unrecognized environment variable
			// ETCDCTL_API" on stderr — v3 is the default API anyway.
			// stderr stays a separate stream (hostexec.Run): -w json
			// output must parse, so a combined capture would poison
			// the payload.
			out, serr, err := hostexec.Run(ctx,
				append([]string{name}, args...), "")
			if err != nil {
				return []byte(out), fmt.Errorf("%w: %s", err,
					strings.TrimSpace(serr))
			}
			return []byte(out), nil
		}
	}
	if c.StartTempEtcd == nil {
		c.StartTempEtcd = startTempEtcdExec
	}
	if c.SleepFn == nil {
		c.SleepFn = time.Sleep
	}
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

// printAlarmList streams `alarm list` output (tolerated — the
// script's `|| true`); empty output prints the fallback note.
func (r *rescuer) printAlarmList(ctx context.Context, emptyNote string) {
	al, err := r.etcdctl(ctx, "", "alarm", "list")
	if err != nil {
		_, _ = fmt.Fprintf(r.out, "(alarm list error: %v)\n", err)
		return
	}
	if len(bytes.TrimSpace(al)) == 0 {
		_, _ = fmt.Fprintln(r.out, emptyNote)
		return
	}
	_, _ = r.out.Write(al)
}

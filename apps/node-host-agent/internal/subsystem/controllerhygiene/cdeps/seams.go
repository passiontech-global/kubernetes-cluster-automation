// seams.go — the Seams test-seam surface, grouped by concern
// (wdeps.Seams parity). The fields used to be unexported
// Config.xxxFn slots; they promote now so the domain test packages
// (external package X_test files driving a full Hygiene through the
// cdepstest fixture) can re-stub them after New. Field names keep
// the old xxxFn names capitalised and every default is the same
// nil → production impl the flat applyDefaults filled — only the
// organization moved.
package cdeps

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/etcdmaint"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/eventpurge"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostexec"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/probee"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// Probe holds the evidence-read seams — every call that fetches a
// verdict or body over the network/TLS: the any-code liveness GET,
// the rv LIST, the pg-wire probe, the KCM/scheduler healthz and
// metrics reads, and the presented-cert TLS dial.
type Probe struct {
	// ProbeFn reports whether url answers ANY HTTP code — the
	// "apiserver event loop alive" verdict (curl -s -o /dev/null
	// parity). nil → probee.HTTPAnyCode at Feeder.ProbeTO.
	ProbeFn func(ctx context.Context, url string) bool
	// ListRVFn is the rv LIST probe seam — nil → the mTLS client
	// path (EnsureClient + the ?resourceVersion= LIST).
	ListRVFn func(ctx context.Context, endpoint string, cached bool) (rv int64, ok bool)
	// PgWireFn is the kine-DB dead-fallback probe — lib.sh
	// pg_wire_ok parity. nil → PGWireOK.
	PgWireFn func(ctx context.Context, hostport string) bool
	// CPHealthFn is the KCM/scheduler healthz probe: true on a 2xx
	// response. nil → probee.HTTP2xx.
	CPHealthFn func(ctx context.Context, url string) bool
	// KCMMetricsFn fetches the KCM /metrics body (leader-without-
	// workers evidence). nil → probee.HTTPBodyInsecure.
	KCMMetricsFn func(ctx context.Context, url string) (string, error)
	// TLSCertFn returns the leaf certificate a TLS listener
	// presents. nil → tlsDialCert (InsecureSkipVerify — only the
	// presented cert is wanted, chain trust is irrelevant).
	TLSCertFn func(ctx context.Context, addr string) (*x509.Certificate, error)
}

// Host holds the host-primitive seams — the calls that touch the
// host itself rather than a remote endpoint: sleeps, signals, the
// journald reads, the systemctl prop/is-active/restart calls, the
// sd_notify datagram and the `ss -K` zombie-stream kill.
type Host struct {
	SleepFn func(d time.Duration)
	KillFn  func(pid int, sig syscall.Signal) error
	// JournalFn returns the unit journal window since `since` —
	// `journalctl -u <unit> --since <ts> --no-pager` parity. nil →
	// the shared systemd client via hostExecCtx.
	JournalFn func(ctx context.Context, unit string, since time.Time) (string, error)
	// JournalAnyFn is the unfiltered second probe used to classify an
	// empty unit-window read — `journalctl -n 1 --no-pager` with
	// stderr folded in. A quiet unit on a healthy journald must NOT
	// count as blindness; only when journald itself has nothing (or
	// only "No journal files") to say does the empty window count.
	// nil → the shared systemd client (hostExecCtx, ExecCombined).
	JournalAnyFn func(ctx context.Context) (string, error)
	RestartFn    func(ctx context.Context, unit string) error
	PropFn       func(ctx context.Context, unit, prop string) (string, error)
	IsActiveFn   func(ctx context.Context, unit string) (string, error)
	NotifyFn     func(msg string) error
	// SSKillFn runs `ss -K sport = :6443` — kills hung HTTP/2 watch
	// streams before a wedge restart (W8-CP1).
	SSKillFn func(ctx context.Context) error
}

// Etcd holds the etcdguard seams — the etcdctl probe exec and the
// two domain libs the remediation drives.
type Etcd struct {
	// EtcdctlFn runs `<K0sDir>/bin/etcdctl <certs> <args>` — the
	// etcdguard probe seam (default adds the apiserver-etcd-client
	// cert triple + --endpoints + --command-timeout and execs
	// container-side through hostexec.Run; stdout-only — stderr
	// captured separately so -w json parses).
	EtcdctlFn func(ctx context.Context, args ...string) ([]byte, error)
	// EvpurgeRunFn / EtcdRescueFn are the guard's remediation seams —
	// nil → eventpurge.Run / etcdmaint.Run.
	EvpurgeRunFn func(ctx context.Context, cfg eventpurge.Config,
		cutoff time.Time, out io.Writer) error
	EtcdRescueFn func(ctx context.Context, cfg etcdmaint.Config,
		out io.Writer) error
}

// Seams groups the injectable test-seam funcs. Every one has a
// production default filled by ApplyDefaults; tests re-stub them on
// the live Hygiene after New.
//
// The three concern groups are EMBEDDED rather than named fields and
// Seams itself is embedded in Config, so every access path resolves
// to the same storage: the explicit d.Cfg.Seams.<Group>.<name>, the
// promoted d.Cfg.Seams.<name> and the flat d.Cfg.<name> the checks
// use. Field names are unique across the groups, so promotion stays
// unambiguous.
type Seams struct {
	// Probe — HTTP/pg-wire/TLS evidence reads.
	Probe
	// Host — signals, sleeps, journal, systemctl, sd_notify, ss.
	Host
	// Etcd — etcdctl + the evpurge/rescue domain libs.
	Etcd
}

// applyDefaults fills the production implementations of every test
// seam — same nil → default logic and order the flat pass had (the
// journal/systemd closures capture c.Systemd up front; the probe
// defaults read their knobs lazily at call time).
func (s *Seams) applyDefaults(c *Config) {
	if c.Clock == nil {
		c.Clock = timex.NewCell(nil)
	}
	if s.SleepFn == nil {
		s.SleepFn = time.Sleep
	}
	if s.KillFn == nil {
		s.KillFn = func(pid int, sig syscall.Signal) error {
			return syscall.Kill(pid, sig)
		}
	}
	sd := c.Systemd
	if s.JournalFn == nil {
		// `timeout 15 journalctl -u <unit> --since <ts> --no-pager` —
		// routed through the shared client: nsenter-wrapped to the
		// HOST journald (the previous raw exec read the container's
		// journal view, empty in the DaemonSet), stderr folded in so
		// the corrupt/no-journal-files diagnostics stay visible to
		// classifyJournalRead, env-scrubbed via `env -u` argv
		// (scrubArgv — ScrubSystemdEnv parity; the exec seam carries
		// no env slot) and bounded at 16MiB by hostexec's capture
		// cap (the old maxJournalBytes).
		s.JournalFn = func(ctx context.Context, unit string, since time.Time) (string, error) {
			cctx, cancel := context.WithTimeout(ctx, defaultJournalTimeout)
			defer cancel()
			return hostExecCtx(cctx, sd, true, "journalctl",
				"-u", unit, "--since",
				since.Format(journalSinceLayout), "--no-pager")
		}
	}
	if s.JournalAnyFn == nil {
		// `timeout 15 journalctl -n 1 --no-pager` — same routing as
		// JournalFn: stderr folded in so journald's own diagnostics
		// ("No journal files were found.", "File ... is corrupt")
		// are visible to the empty-window classifier.
		s.JournalAnyFn = func(ctx context.Context) (string, error) {
			cctx, cancel := context.WithTimeout(ctx, defaultJournalTimeout)
			defer cancel()
			return hostExecCtx(cctx, sd, true,
				"journalctl", "-n", "1", "--no-pager")
		}
	}
	if s.PgWireFn == nil {
		s.PgWireFn = PGWireOK
	}
	if s.RestartFn == nil {
		s.RestartFn = func(ctx context.Context, unit string) error {
			// The remediate gate's `timeout 90` budget survives as a
			// per-call ExecBounded — a tighter wrap SIGKILLed a slow
			// restart mid-flight while systemd finished
			// asynchronously and the gate logged FAIL. Routed
			// through the host exec so the restart reaches the HOST
			// systemd — the old raw exec had no dbus socket inside
			// the DaemonSet and could never work.
			_, err := hostExecCtxBounded(ctx, sd, true,
				defaultRestartBudget, "systemctl", "restart", unit)
			return err
		}
	}
	if s.PropFn == nil {
		s.PropFn = func(ctx context.Context, unit, prop string) (string, error) {
			cctx, cancel := context.WithTimeout(ctx, defaultSystemctlBudget)
			defer cancel()
			out, err := hostExecCtx(cctx, sd, false, "systemctl",
				"show", unit, "-p", prop, "--value")
			return strings.TrimSpace(out), err
		}
	}
	if s.IsActiveFn == nil {
		s.IsActiveFn = func(ctx context.Context, unit string) (string, error) {
			// is-active exits non-zero for inactive — the output is
			// the value, not an error (shell `|| true` parity).
			cctx, cancel := context.WithTimeout(ctx, defaultSystemctlBudget)
			defer cancel()
			out, _ := hostExecCtx(cctx, sd, false, "systemctl", "is-active", unit)
			return strings.TrimSpace(out), nil
		}
	}
	if s.NotifyFn == nil && c.Feeder.NotifySocket != "" {
		sock := c.Feeder.NotifySocket
		s.NotifyFn = func(msg string) error { return sdNotify(sock, msg) }
	}
	if s.ProbeFn == nil {
		to := c.Feeder.ProbeTO
		s.ProbeFn = func(ctx context.Context, url string) bool {
			return probee.HTTPAnyCode(ctx, url, to)
		}
	}
	if s.EtcdctlFn == nil {
		k0sDir, endpoint := c.K0sDir, c.EtcdGuard.Endpoint
		bin := filepath.Join(k0sDir, "bin", "etcdctl")
		certArgs := []string{
			// The apiserver's etcd client certs — the same triple
			// rescue-etcd.sh uses (not the etcd server certs).
			"--cacert=" + filepath.Join(k0sDir, "pki", "etcd", "ca.crt"),
			"--cert=" + filepath.Join(k0sDir, "pki", "apiserver-etcd-client.crt"),
			"--key=" + filepath.Join(k0sDir, "pki", "apiserver-etcd-client.key"),
			"--endpoints=" + endpoint,
			"--command-timeout=" + etcdctlCmdTimeout,
		}
		s.EtcdctlFn = func(ctx context.Context, args ...string) ([]byte, error) {
			argv := append(append([]string{bin}, certArgs...), args...)
			cctx, cancel := context.WithTimeout(ctx, defaultEtcdctlBudget)
			defer cancel()
			// Deliberately container-side via hostexec.Run, NOT the
			// nsenter-wrapped Config seam: bin is a hostPath-prefixed
			// path (<hostRoot>/var/lib/k0s/bin/etcdctl) that only
			// exists in the pod's mount view — an nsenter -m wrap
			// would look for "/host/..." on the host fs where it
			// does not exist. The endpoint is loopback, reachable
			// because the DaemonSet is hostNetwork. etcdctl >=3.7
			// warns "unrecognized environment variable ETCDCTL_API"
			// on stderr — v3 is the default API anyway — so stderr
			// stays a separate stream: -w json output must parse;
			// a combined capture would poison the payload.
			out, serr, err := hostexec.Run(cctx, argv, "")
			if err != nil {
				return []byte(out), fmt.Errorf("%w: %s", err,
					strings.TrimSpace(serr))
			}
			return []byte(out), nil
		}
	}
	if s.EvpurgeRunFn == nil {
		s.EvpurgeRunFn = eventpurge.Run
	}
	if s.EtcdRescueFn == nil {
		s.EtcdRescueFn = etcdmaint.Run
	}
	if s.SSKillFn == nil {
		s.SSKillFn = func(ctx context.Context) error {
			// `ss -K sport = :6443` is a HOST command — it drops the
			// apiserver's hung HTTP/2 watch streams in the host
			// network namespace, so it goes through the shared
			// client (host ss binary + host netns) rather than
			// relying on an ss binary inside the agent image (the
			// old raw exec only worked because the pod is
			// hostNetwork AND happened to carry ss).
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			out, err := hostExecCtx(cctx, sd, true,
				"ss", "-K", "sport", "=", ":6443")
			if err != nil {
				return fmt.Errorf("%w: %s", err, strings.TrimSpace(out))
			}
			return nil
		}
	}
	if s.CPHealthFn == nil {
		s.CPHealthFn = func(ctx context.Context, url string) bool {
			return probee.HTTP2xx(ctx, url, 5*time.Second)
		}
	}
	if s.KCMMetricsFn == nil {
		s.KCMMetricsFn = func(ctx context.Context, url string) (string, error) {
			return probee.HTTPBodyInsecure(ctx, url, 8*time.Second)
		}
	}
	if s.TLSCertFn == nil {
		s.TLSCertFn = tlsDialCert
	}
}

// seams.go — the Seams test-seam surface, grouped by concern
// (wdeps.Seams parity). The fields used to be unexported
// Config.xxxFn slots; they promote now so the domain test packages
// (external package X_test files driving a full Hygiene through the
// cdepstest fixture) can re-stub them after New. Field names keep
// the old xxxFn names capitalised and every default is the same
// nil → production impl the flat applyDefaults filled — only the
// organization moved.
//
// The seam surface stays LOW-LEVEL on purpose: a field that only
// composed a lower seam with parsing was deleted rather than
// re-stubbed. The rv LIST probe rides the injected Config.HTTPClient
// seam through Deps.ListRV (no ListRVFn), and the six
// journalctl/systemctl/ss wrappers collapsed into the single
// HostExecFn — the named Deps helpers (journalRead/journalAnyRead
// in journal.go, Restart/UnitProp/UnitActiveState/SSKill in
// exec.go) build argv + parse, the seam does the I/O.
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
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/netlinkx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/probee"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// Probe holds the evidence-read seams — every call that fetches a
// verdict or body over the network/TLS: the any-code liveness GET,
// the pg-wire probe, the KCM/scheduler healthz and metrics reads,
// and the presented-cert TLS dial. (The rv LIST probe has no func
// field — it is the injected Config.HTTPClient seam plus the
// ?resourceVersion= parse, consumed as Deps.ListRV.)
type Probe struct {
	// ProbeFn reports whether url answers ANY HTTP code — the
	// "apiserver event loop alive" verdict (curl -s -o /dev/null
	// parity). nil → probee.HTTPAnyCode at Feeder.ProbeTO.
	ProbeFn func(ctx context.Context, url string) bool
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
// sd_notify datagram and the ONE exec transport every
// journalctl/systemctl/ss call shares. The per-command wrappers
// that used to be seams (journal reads, prop/is-active/restart,
// `ss -K`) are Deps methods now — they only built fixed argv and
// trimmed output, so stubbing the single exec seam underneath
// covers them identically.
type Host struct {
	SleepFn func(d time.Duration)
	KillFn  func(pid int, sig syscall.Signal) error
	// HostExecFn runs `name args...` on the host through the shared
	// systemd client — the single exec seam behind every
	// journalctl/systemctl/ss call the checks make. combined folds
	// stderr into the returned output (journald's own diagnostics
	// — "No journal files were found." — live there); budget >0 is
	// the per-call ExecBounded override (the remediate `timeout 90`
	// parity), <=0 keeps the client's Config.Timeout. nil →
	// hostExecCtxBounded, which nsenter-wraps to host PID 1's
	// namespaces inside the DaemonSet and prefixes argv with the
	// `env -u NOTIFY_SOCKET -u WATCHDOG_* --` scrub.
	HostExecFn func(ctx context.Context, combined bool,
		budget time.Duration, name string, args ...string) (string, error)
	// SockDestroyFn kills TCP listeners on a port in the host
	// netns — the netlinkx SOCK_DESTROY path that replaced the
	// `ss -K` fork (no ss binary needed in the agent image). nil →
	// netlinkx.DestroyListenersOnPort(1, port): pid 1 is host init
	// under hostPID:true in the DaemonSet and plain /proc
	// standalone.
	SockDestroyFn func(port uint16) (int, error)
	NotifyFn      func(msg string) error
	// StatFSFn returns (free, total) bytes of the filesystem holding
	// path — the etcdguard pre-maintenance snapshot headroom gate
	// reads it (the kine backup verifier has the same gate shape over
	// kdeps.StatFSFn). nil → statfsFreeBytes.
	StatFSFn func(path string) (freeBytes, totalBytes int64, err error)
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
	// Host — signals, sleeps, the one host-exec seam, sd_notify.
	Host
	// Etcd — etcdctl + the evpurge/rescue domain libs.
	Etcd
}

// applyDefaults fills the production implementations of every test
// seam — same nil → default logic and order the flat pass had (the
// exec closure captures c.Systemd up front; the probe defaults read
// their knobs lazily at call time).
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
	if s.HostExecFn == nil {
		// Every journalctl/systemctl/ss call lands here — the
		// scrubArgv env fix (ScrubSystemdEnv parity in argv form;
		// the seam carries no env slot) and the nsenter wrap to the
		// HOST systemd/journald/netns both live inside
		// hostExecCtxBounded.
		s.HostExecFn = func(ctx context.Context, combined bool,
			budget time.Duration, name string, args ...string) (string, error) {
			return hostExecCtxBounded(ctx, sd, combined, budget,
				name, args...)
		}
	}
	if s.SockDestroyFn == nil {
		s.SockDestroyFn = func(port uint16) (int, error) {
			return netlinkx.DestroyListenersOnPort(1, port)
		}
	}
	if s.PgWireFn == nil {
		s.PgWireFn = PGWireOK
	}
	if s.NotifyFn == nil && c.Feeder.NotifySocket != "" {
		sock := c.Feeder.NotifySocket
		s.NotifyFn = func(msg string) error { return sdNotify(sock, msg) }
	}
	if s.StatFSFn == nil {
		s.StatFSFn = statfsFreeBytes
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

// statfsFreeBytes returns the free and total byte counts of the
// filesystem holding path — the StatFSFn production default.
func statfsFreeBytes(path string) (freeBytes, totalBytes int64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	return st.Bsize * int64(st.Bfree),
		st.Bsize * int64(st.Blocks), nil
}

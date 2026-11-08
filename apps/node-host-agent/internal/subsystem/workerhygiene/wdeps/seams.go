// seams.go — the Seams test-seam surface, grouped by concern. The
// flat ~24-func list outgrew readability, so the fields now live in
// the four embedded groups below: Probe (evidence reads over
// HTTP/DNS/unix/kubelet-metrics/pod-log), Host (signals, clock,
// fs/scheduling/journal/proc primitives), Ctr (the one containerd
// exec) and Cilium (the one agent unix-API GET). Field names are
// unchanged inside each group and every default is the same nil →
// production impl the flat applyDefaults filled — only the
// organization moved.
//
// DERIVED reads are not seams: a (low-level seam + fixed argv +
// parsing) composition adds no test coverage a stub of the
// low-level seam doesn't already give, so those live as named
// methods on their group instead of func fields — Ctr.RmImage /
// RmIngest / PruneContent build argv over the single Ctr.Exec seam,
// and Cilium.WGAllowedIPs / EncryptPeers / ServiceBackends compose
// Cilium.UnixGet (or Config.Systemd for `wg`) with the parsers.
package wdeps

import (
	"context"
	"errors"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/probee"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// Probe holds the evidence-read seams — every call that fetches a
// verdict or body over the network: the HTTP GET variants, the
// unix-socket dial, the :53 DNS datapath probes, the kubelet
// :10250 /metrics scrape and the pod-log tail.
type Probe struct {
	// ProbeHTTP does one GET and returns nil only on a 2xx response
	// (BUG-H7 — a 500/503 means the probed service is wedged, not
	// "the listener is alive"). Seam.
	ProbeHTTP func(ctx context.Context, url string, timeout time.Duration) error
	// ProbeBodyOK does one GET and reports whether the trimmed body is
	// exactly "ok" — the :10248 healthz contract (curl -s body compare
	// parity: a wedged kubelet can still answer HTTP with a non-ok
	// body, so any-HTTP-code-alive is not enough here). Seam.
	ProbeBodyOK func(ctx context.Context, url string, timeout time.Duration) bool
	// ProbeHTTPStatus does one GET and returns the status code — the
	// ProbeHTTP variant for endpoints where the CODE is the verdict
	// (syncloop 500 vs healthz 200, envoy /ready 503) or where ANY
	// answer proves liveness (kubelet :10250 /healthz, api /livez —
	// a 401/403 is an auth denial, not a dead listener). bearer != ""
	// attaches an Authorization header (kubelet :10250 requires
	// auth). Seam.
	ProbeHTTPStatus func(ctx context.Context, url, bearer string, timeout time.Duration) (int, error)
	// ProbeUnixSock connects to a unix socket under a deadline — the
	// containerd-socket hang probe (A4). Seam.
	ProbeUnixSock func(ctx context.Context, socket string, timeout time.Duration) error
	// HTTPGetBody GETs a plain-HTTP endpoint and returns the body —
	// the envoy admin stats page (W7-H3 xDS NACK guard). Seam.
	HTTPGetBody func(ctx context.Context, url string, timeout time.Duration) ([]byte, error)
	// DNSProbe sends one UDP DNS query for a fixed cluster name to
	// addr and reports whether a well-formed answer returns before
	// the deadline — the node-local-dns :53 datapath probe
	// (W7-H3). Seam.
	DNSProbe func(addr, name string, timeout time.Duration) bool
	// PodLogFn returns a tail of one pod's current log — the
	// clock-jump healer's konnectivity evidence read. Default the
	// kube-client GetLogs call; tests stub with canned output.
	PodLogFn func(ctx context.Context, ns, name string, tailLines int64) (string, error)
	// DNSProbeTCP sends one TCP DNS query — the :53 datapath
	// probe's TCP half (a wedged TCP listener still serves UDP,
	// and truncated/large answers ride TCP). Seam.
	DNSProbeTCP func(addr, name string, timeout time.Duration) bool
	// KubeletMetricsFn GETs the kubelet :10250 /metrics body with
	// the SA bearer — the syncloop check's PLEG relist/last-seen
	// series source. Insecure TLS + Authorization header: kubelet
	// cert SANs never cover the loopback and anonymous /metrics is
	// denied. Seam.
	KubeletMetricsFn func(ctx context.Context, url, bearer string, timeout time.Duration) (string, error)
}

// Host holds the host-primitive seams — the calls that touch the
// host itself rather than a remote endpoint: signal delivery, the
// clock, fs usage, CPU/IO scheduling drops, the journald reads and
// the deleted-fd stat.
type Host struct {
	// KillFn delivers signals — seam for tests (SIGKILL on pause /
	// proxy-agent/shim/cilium pids, and signal-0 liveness probes).
	KillFn func(pid int, sig syscall.Signal) error
	// Clock supplies the current time — the shared timex.Cell seam.
	Clock *timex.Cell
	// JournalFn returns the k0sworker journal window — the runner's
	// shared -10min snapshot (05/06). nil → Systemd.Journal.
	JournalFn func(ctx context.Context) (string, error)
	// JournalAnyFn is the A5 second probe — `journalctl -n 1
	// --no-pager` with NO unit filter. An empty k0sworker window is
	// only corruption evidence when journald ITSELF has nothing (or
	// only corrupt warnings) to say — a quiet unit on a healthy
	// journald must not trigger the rotate+vacuum remedy. nil →
	// Systemd.ExecCombined (stderr folded in — journald's own
	// diagnostics, e.g. "File ... is corrupt", never reach stdout).
	JournalAnyFn func(ctx context.Context) (string, error)
	// StatfsFn reads fs usage for the ingest-GC disk trigger (A3).
	// Seam for tests (default unix.Statfs).
	StatfsFn func(string, *unix.Statfs_t) error
	// ReniceFn drops one pid to the lowest CPU scheduling priority
	// (renice +19) — the io-pressure throttler's CPU half. Default
	// syscall.Setpriority; tests record instead of renicing.
	ReniceFn func(pid int) error
	// IoniceIdleFn puts one pid in the idle I/O scheduling class
	// (ionice -c 3) — the io-pressure throttler's I/O half. Default
	// the ioprio_set syscall (ionice_other.go reports unsupported
	// off-Linux). Seam.
	IoniceIdleFn func(pid int) error
	// DeletedFDStatFn stats a /proc/<pid>/fd link whose readlink
	// target ends in " (deleted)" — the kernel resolves the magic
	// link to the still-open inode, so the fd's dev/ino/size are
	// readable even though the path is gone (the
	// unlinked-open-files guard's evidence source and (dev,ino)
	// dedup key). ok=false when the fd vanished mid-walk or isn't
	// a regular file. Seam.
	DeletedFDStatFn func(path string) (dev, ino uint64, size int64, ok bool)
}

// Ctr holds the ONE containerd content seam — the exec every `k0s
// ctr` mutation (image removal, stale ingest ref GC,
// watermark-gated content prune) shares through the systemd exec
// wrapper. The named methods below build each command's argv, so
// call sites keep their readable names and tests stub exactly one
// func.
type Ctr struct {
	// Exec runs one argv through the systemd exec wrapper — a
	// full-argv passthrough (argv[0] is the binary name, the
	// Systemd.Exec name+args shape). nil → Systemd.Exec default; a
	// nil Systemd client errors the same "no systemd client wired".
	// Seam.
	Exec func(ctx context.Context, argv ...string) error
	// ExecOut is Exec for the `k0s ctr` READS that need stdout back
	// (lease listing) — the same transport, output returned. nil →
	// Systemd.Exec default. Seam.
	ExecOut func(ctx context.Context, argv ...string) (string, error)
}

// RmImage removes one image from the k8s.io containerd namespace —
// the corrupted-layer remedy (37), `k0s ctr --namespace k8s.io
// images rm --sync <image>` over the Exec seam.
func (s *Ctr) RmImage(ctx context.Context, image string) error {
	return s.Exec(ctx,
		"k0s", "ctr", "--namespace", "k8s.io", "images", "rm", "--sync", image)
}

// RmIngest removes one stale ingest ref — `k0s ctr -n k8s.io
// content ingest rm <ref>` over the Exec seam (A3).
func (s *Ctr) RmIngest(ctx context.Context, ref string) error {
	return s.Exec(ctx,
		"k0s", "ctr", "-n", "k8s.io", "content", "ingest", "rm", ref)
}

// PruneContent runs the store-wide content GC — `k0s ctr -n k8s.io
// content prune` over the Exec seam (W9). It only fires while
// /var/lib/k0s sits above the high watermark, on the
// last-content-gc 6h budget.
func (s *Ctr) PruneContent(ctx context.Context) error {
	return s.Exec(ctx,
		"k0s", "ctr", "-n", "k8s.io", "content", "prune")
}

// CtrLease is one `k0s ctr -n k8s.io leases ls` row — the lease id,
// its created-at stamp and whether it carries a gc.expire label
// (containerd's own "may GC after T" annotation — a lease WITHOUT
// the label is orphaned forever unless a caller deletes it).
type CtrLease struct {
	ID       string
	Created  time.Time
	HasGCExp bool
}

// Leases lists the containerd leases — `k0s ctr -n k8s.io leases ls`
// over the ExecOut seam, ParseCtrLeases'd. The orphan-lease reaper's
// derived read: stubbing the one exec covers the parser for real.
func (s *Ctr) Leases(ctx context.Context) ([]CtrLease, error) {
	out, err := s.ExecOut(ctx,
		"k0s", "ctr", "-n", "k8s.io", "leases", "ls")
	if err != nil {
		return nil, err
	}
	return ParseCtrLeases(out), nil
}

// RmLease removes one lease — `k0s ctr -n k8s.io leases rm <id>`
// over the Exec seam (no output needed).
func (s *Ctr) RmLease(ctx context.Context, id string) error {
	return s.Exec(ctx,
		"k0s", "ctr", "-n", "k8s.io", "leases", "rm", id)
}

// ParseCtrLeases parses `ctr leases ls` table output: a header row,
// then one lease per line — "ID CREATED-AT-STAMP LABELS" where the
// stamp is Go's time.String form ("2006-01-02 15:04:05.999999999
// +0000 UTC") and LABELS is the trailing key=value blob (possibly
// empty). Unparseable rows are skipped — a garbled line is never
// lease evidence.
func ParseCtrLeases(out string) []CtrLease {
	var leases []CtrLease
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "ID") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		var l CtrLease
		l.ID = f[0]
		l.HasGCExp = strings.Contains(line, "containerd.io/gc.expire")
		// The created-at stamp is the first "YYYY-MM-DD" field plus
		// the time field that follows it; fractional seconds and the
		// trailing zone fields are optional noise.
		for i := 1; i+1 < len(f); i++ {
			if len(f[i]) != 10 || f[i][4] != '-' || f[i][7] != '-' {
				continue
			}
			ts := f[i] + " " + f[i+1]
			if j := strings.Index(ts, "+"); j > 0 {
				ts = strings.TrimSpace(ts[:j])
			}
			if t, err := time.ParseInLocation("2006-01-02 15:04:05", ts, time.UTC); err == nil {
				l.Created = t
			}
			break
		}
		leases = append(leases, l)
	}
	return leases
}

// Cilium holds the ONE cilium seam — the unix-socket GET every
// agent endpoint shares. The WireGuard allowed-ips / encrypt-peers /
// BPF service-map evidence reads are derived from it (or from
// Config.Systemd for the `wg` exec): they are methods below, not
// seams — stubbing UnixGet and testing the parsers directly gives
// equal coverage with less surface.
type Cilium struct {
	// UnixGet GETs path over a unix socket and returns the body —
	// the cilium-dbg endpoint list replacement (35). Seam.
	UnixGet func(ctx context.Context, socket, path string) ([]byte, error)
}

// WGAllowedIPs returns how many cilium_wg0 peers carry a real
// allowed-ips set — `wg show cilium_wg0 allowed-ips` through the
// systemd exec wrapper (sd is Config.Systemd), ParseWGAllowedIPs'd
// (peers at "(none)" are wiped). The W5.6 check's derived read —
// tests drive it through the systemd exec fake.
func (s *Cilium) WGAllowedIPs(ctx context.Context, sd *systemd.Client) (int, error) {
	if sd == nil {
		return 0, errors.New("no systemd client wired")
	}
	out, err := sd.Exec(ctx, "wg", "show", "cilium_wg0", "allowed-ips")
	if err != nil {
		return 0, err
	}
	return ParseWGAllowedIPs(out), nil
}

// EncryptPeers returns the expected WG peer count — the agent's
// /v1/healthz cluster.nodes[] member count through the UnixGet
// seam. The agent's own API beats `cilium-dbg`: the binary only
// lives INSIDE the cilium-agent container — an sd.Exec on the host
// always fails and silently degrades every cycle to the
// ReadyNodes-1 fallback. /v1/healthz's cluster.nodes[] lists
// exactly the remote cilium members this node should peer with
// (virtual/liqo nodes run no agent, so they never appear). An error
// or a count <=0 makes the caller fall back to ReadyNodes-1.
func (s *Cilium) EncryptPeers(ctx context.Context, socket string) (int, error) {
	body, err := s.UnixGet(ctx, socket, "/v1/healthz")
	if err != nil {
		return 0, err
	}
	n, ok := ParseCiliumHealthNodes(body)
	if !ok {
		return 0, errors.New("no cluster.nodes in cilium healthz")
	}
	return n, nil
}

// ServiceBackends returns the local BPF service map's backend
// counts keyed "<namespace>/<name>" — the cilium-lrp desync
// evidence source. GET /v1/service off the agent socket through
// the UnixGet seam (`cilium-dbg service list -o json` equivalent —
// the CLI scrapes the same endpoint over the same socket; no
// container exec).
func (s *Cilium) ServiceBackends(ctx context.Context, socket string) (map[string]int, error) {
	body, err := s.UnixGet(ctx, socket, "/v1/service")
	if err != nil {
		return nil, err
	}
	return ParseCiliumServiceBackends(body)
}

// Seams groups the unexported test-seam funcs. Every one has a
// production default filled by applyDefaults; tests re-stub them on
// the live Hygiene after New.
//
// The four concern groups are EMBEDDED rather than named fields, so
// both access paths resolve to the same storage: the explicit
// d.Cfg.Seams.<Group>.<name> the checks use, and the promoted
// d.Cfg.Seams.<name> the wdepstest fixture and workerhygiene.go
// still write. Field names are unique across the groups, so
// promotion stays unambiguous.
type Seams struct {
	// Probe — HTTP/DNS/unix/kubelet-metrics/pod-log evidence reads.
	Probe
	// Host — signals, clock, fs/scheduling/journal/proc primitives.
	Host
	// Ctr — the containerd exec behind the named rm/prune methods.
	Ctr
	// Cilium — the agent unix-API GET behind the derived reads.
	Cilium
}

// applyDefaults fills the production implementations of every test
// seam. cfg carries the already-defaulted knob groups — the systemd
// exec default captures c.Systemd. The group calls are independent
// nil-checks, so their order is unobservable.
func (s *Seams) applyDefaults(c *Config) {
	s.Probe.applyDefaults(c)
	s.Host.applyDefaults(c)
	s.Ctr.applyDefaults(c)
	s.Cilium.applyDefaults(c)
}

// applyDefaults fills the Probe group's production implementations —
// same nil → default logic and order the flat pass had.
func (s *Probe) applyDefaults(c *Config) {
	if s.HTTPGetBody == nil {
		// Plain HTTP (no TLS) — the envoy admin stats page lives on
		// loopback :9901. A non-200 is an error: the reject-delta
		// verdict is unreadable, not "zero".
		s.HTTPGetBody = probee.HTTPBody
	}
	if s.DNSProbe == nil {
		s.DNSProbe = probee.DNSQuery
	}
	if s.ProbeHTTP == nil {
		// BUG-H7: an HTTP response no longer counts as alive on its
		// own — a wedged cilium-agent :9879/healthz answering 500/503
		// must read as DOWN. Only a 2xx is a pass; insecure TLS stays
		// (kubelet cert SANs don't cover 127.0.0.1, curl -ks parity).
		s.ProbeHTTP = probee.HTTPGet
	}
	if s.ProbeBodyOK == nil {
		// kubelet :10248 contract (curl -s parity): the healthz port is
		// unauthenticated plaintext and the body must be exactly "ok" —
		// a wedged kubelet can still answer HTTP with a non-ok body.
		s.ProbeBodyOK = probee.BodyOK
	}
	if s.ProbeHTTPStatus == nil {
		// Same insecure-TLS transport as ProbeHTTP — the status code
		// is the verdict (syncloop 500, envoy /ready 503).
		s.ProbeHTTPStatus = probee.HTTPStatus
	}
	if s.ProbeUnixSock == nil {
		// A successful dial IS the verdict — a close error (e.g. the
		// peer reset first) must not downgrade it.
		s.ProbeUnixSock = probee.UnixDial
	}
	if s.DNSProbeTCP == nil {
		s.DNSProbeTCP = tcpDNSQuery
	}
	if s.KubeletMetricsFn == nil {
		s.KubeletMetricsFn = kubeletMetricsGet
	}
	if s.PodLogFn == nil {
		s.PodLogFn = func(ctx context.Context, ns, name string, tail int64) (string, error) {
			if c.Client == nil {
				return "", errors.New("no kube client wired")
			}
			res := c.Client.CoreV1().Pods(ns).GetLogs(name,
				&corev1.PodLogOptions{TailLines: &tail}).Do(ctx)
			b, err := res.Raw()
			return string(b), err
		}
	}
}

// applyDefaults fills the Host group's production implementations —
// same nil → default logic and order the flat pass had.
func (s *Host) applyDefaults(c *Config) {
	if s.KillFn == nil {
		s.KillFn = func(pid int, sig syscall.Signal) error {
			return syscall.Kill(pid, sig)
		}
	}
	if s.Clock == nil {
		s.Clock = timex.NewCell(nil)
	}
	if s.JournalFn == nil {
		sd := c.Systemd
		s.JournalFn = func(ctx context.Context) (string, error) {
			if sd == nil {
				// Fail, not empty: a nil client fed the unreadable
				// tracker a fake "journald-wide empty reply" verdict.
				return "", errors.New("no systemd client wired")
			}
			return sd.Journal(ctx, "k0sworker.service", journalWindow)
		}
	}
	if s.JournalAnyFn == nil {
		sd := c.Systemd
		s.JournalAnyFn = func(ctx context.Context) (string, error) {
			if sd == nil {
				return "", errors.New("no systemd client wired")
			}
			return sd.ExecCombined(ctx,
				"journalctl", "-n", "1", "--no-pager")
		}
	}
	if s.StatfsFn == nil {
		s.StatfsFn = unix.Statfs
	}
	if s.ReniceFn == nil {
		s.ReniceFn = func(pid int) error {
			return syscall.Setpriority(syscall.PRIO_PROCESS, pid, 19)
		}
	}
	if s.IoniceIdleFn == nil {
		s.IoniceIdleFn = ioniceIdle // build-tag split: linux ioprio_set
	}
	if s.DeletedFDStatFn == nil {
		s.DeletedFDStatFn = deletedFDStat
	}
}

// applyDefaults fills the Ctr group's production implementation —
// the one exec seam: a full-argv passthrough onto Systemd.Exec,
// nil-safe the same way the three per-command defaults were (the
// named methods carry the argv each old default hardcoded).
func (s *Ctr) applyDefaults(c *Config) {
	if s.Exec == nil {
		sd := c.Systemd
		s.Exec = func(ctx context.Context, argv ...string) error {
			if sd == nil {
				return errors.New("no systemd client wired")
			}
			_, err := sd.Exec(ctx, argv[0], argv[1:]...)
			return err
		}
	}
	if s.ExecOut == nil {
		sd := c.Systemd
		s.ExecOut = func(ctx context.Context, argv ...string) (string, error) {
			if sd == nil {
				return "", errors.New("no systemd client wired")
			}
			return sd.Exec(ctx, argv[0], argv[1:]...)
		}
	}
}

// applyDefaults fills the Cilium group's production implementation —
// just the UnixGet socket GET now; the WG/service-map reads are the
// derived methods on the group (they read s.UnixGet at CALL time so
// a test re-stub of the socket GET still reaches them).
func (s *Cilium) applyDefaults(_ *Config) {
	if s.UnixGet == nil {
		s.UnixGet = probee.UnixGet
	}
}

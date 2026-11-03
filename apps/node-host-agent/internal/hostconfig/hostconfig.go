// Package hostconfig is the declarative host converger replacing the
// node-config-agent Ansible DaemonSet + hub-converge CronJob. It runs
// at startup, every Interval, and whenever the vars/nebula-certs
// mounts change (poll-watched via sha256 of the dir listing).
//
// Every managed file is rendered to bytes, sha256-compared with the
// on-disk file, and written atomically (tmp+rename, mode preserved)
// ONLY when changed; post-change hooks run only on real changes —
// the same contract the ansible play + handlers provided.
//
// Host file paths go through Config.HostRoot (default /host); host
// commands (systemctl/nft/sshd/modprobe/sysctl/dig/ip) go through
// Runner — nsenter into host PID 1 namespaces in production, fake in
// tests.
package hostconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/topology"
)

const (
	defaultInterval       = 30 * time.Minute
	defaultHostRoot       = "/host"
	defaultVarsDir        = "/config/vars"
	defaultNebulaCertsDir = "/config/nebula-certs"
	defaultWatchdogDir    = "/config/watchdog"
	defaultWatchPoll      = 15 * time.Second
)

// Runner executes a command inside the HOST namespaces.
type Runner interface {
	// Run returns combined stdout ("" on error).
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// NsenterRunner enters PID 1 mount/uts/ipc/net/pid namespaces —
// the same access community.docker.nsenter gave the ansible pod.
type NsenterRunner struct{}

func (NsenterRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	a := append([]string{"-t", "1", "-m", "-u", "-i", "-n", "-p", "--", name}, args...)
	out, err := exec.CommandContext(ctx, "nsenter", a...).CombinedOutput()
	return strings.TrimRight(string(out), "\n"), err
}

// DirectRunner runs commands unwrapped — the standalone systemd
// deployment (HostRoot "/") is already inside the host namespaces.
type DirectRunner struct{}

func (DirectRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimRight(string(out), "\n"), err
}

// Watcher detects input changes (injectable for tests).
type Watcher interface {
	Changed() bool            // one-shot edge
	Poll(ctx context.Context) // internal loop updating state
}

// DirWatcher polls a sha256 over (name,size,mtime,content-hash) of
// every file under the watched dirs every period.
type DirWatcher struct {
	Dirs   []string
	Period time.Duration

	mu     sync.Mutex // guards last, dirty, polled — Poll writes, Changed reads
	last   string
	dirty  bool // Poll-latched change edge, consumed by Changed
	polled bool // Poll has observed the dir at least once
}

func (w *DirWatcher) fingerprint() string {
	h := sha256.New()
	var files []string
	for _, d := range w.Dirs {
		_ = filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err == nil && !e.IsDir() {
				files = append(files, p)
			}
			return nil
		})
	}
	sort.Strings(files)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		h.Write([]byte(f))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (w *DirWatcher) Poll(ctx context.Context) {
	p := w.Period
	if p <= 0 {
		p = defaultWatchPoll
	}
	initFP := w.fingerprint()
	w.mu.Lock()
	if w.last == "" {
		w.last = initFP
	}
	w.polled = true
	w.mu.Unlock()

	t := time.NewTicker(p)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fp := w.fingerprint()
			w.mu.Lock()
			if fp != w.last {
				w.dirty = true
				w.last = fp
			}
			w.mu.Unlock()
		}
	}
}

// Changed reports a change edge. Once Poll has run it just consumes
// the edge Poll latched — the main loop does not re-read and re-hash
// every file a second time, and an edge observed between two Changed
// calls is never lost. When Poll has never run (unit tests calling
// Changed directly) it falls back to comparing a fresh fingerprint
// against the last snapshot.
func (w *DirWatcher) Changed() bool {
	w.mu.Lock()
	if w.polled {
		d := w.dirty
		w.dirty = false
		w.mu.Unlock()
		return d
	}
	w.mu.Unlock()

	// No Poll yet — fingerprint outside the lock (dir walk + file
	// reads) so a racing first Poll scan is not stalled on disk IO.
	fp := w.fingerprint()
	w.mu.Lock()
	defer w.mu.Unlock()
	// Poll may have started meanwhile — its dirty latch is then the
	// authoritative edge and the fingerprint is discarded.
	if w.polled {
		d := w.dirty
		w.dirty = false
		return d
	}
	changed := fp != w.last
	w.last = fp
	return changed
}

// Config — all injectable.
type Config struct {
	NodeName           string // registry key (NODE_NAME / OS hostname)
	Hostname           string // fallback OS hostname when NodeName unset
	HostRoot           string
	VarsDir            string
	NebulaCertsDir     string
	WatchdogScriptsDir string // optional: node-watchdog-scripts CM mount
	Interval           time.Duration
	Enabled            bool
	Runner             Runner
	Watcher            Watcher
	NowFn              func() time.Time
	HTTPTimeout        time.Duration
	// DownloadDir caches fetched archives (nebula/coredns/haproxy deb).
	DownloadDir string
	// Standalone marks the on-host systemd deployment (hub/infra/API-LB
	// VMs — HostRoot "/"). Derived from HostRoot in applyDefaults; a
	// test may force it true with a sandboxed HostRoot to exercise the
	// standalone-only groups.
	Standalone bool
}

func (c *Config) applyDefaults() {
	if c.Interval <= 0 {
		c.Interval = defaultInterval
	}
	if c.HostRoot == "" {
		c.HostRoot = defaultHostRoot
	}
	if c.VarsDir == "" {
		c.VarsDir = defaultVarsDir
	}
	if c.NebulaCertsDir == "" {
		c.NebulaCertsDir = defaultNebulaCertsDir
	}
	if c.WatchdogScriptsDir == "" {
		c.WatchdogScriptsDir = defaultWatchdogDir
	}
	if c.Runner == nil {
		c.Runner = NsenterRunner{}
	}
	if c.NowFn == nil {
		c.NowFn = time.Now
	}
	if c.HTTPTimeout <= 0 {
		c.HTTPTimeout = 60 * time.Second
	}
	if c.DownloadDir == "" {
		c.DownloadDir = "/tmp/hostconfig"
	}
	if c.NodeName == "" {
		c.NodeName = c.Hostname
	}
	if c.HostRoot == "/" {
		c.Standalone = true
	}
}

// Reconciler is the hostconfig subsystem.
type Reconciler struct {
	cfg Config

	cycles  *prometheus.CounterVec // group, result
	writes  *prometheus.CounterVec // file
	actions *prometheus.CounterVec // action
	lastOK  prometheus.Gauge
}

func New(cfg Config, reg prometheus.Registerer) (*Reconciler, error) {
	cfg.applyDefaults()
	r := &Reconciler{cfg: cfg}
	r.cycles = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_hostconfig_cycles_total",
		Help: "hostconfig converge cycles by group and result.",
	}, []string{"group", "result"})
	r.writes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_hostconfig_writes_total",
		Help: "Managed-file writes that changed on disk, by path.",
	}, []string{"path"})
	r.actions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_hostconfig_actions_total",
		Help: "hostconfig post-change actions (restart/reload/apply).",
	}, []string{"action"})
	r.lastOK = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_hostconfig_last_success_seconds",
		Help: "Unix time of the last fully-successful cycle.",
	})
	if reg != nil {
		for _, c := range []prometheus.Collector{r.cycles, r.writes, r.actions, r.lastOK} {
			if err := reg.Register(c); err != nil {
				return nil, fmt.Errorf("register hostconfig metrics: %w", err)
			}
		}
	}
	return r, nil
}

func (r *Reconciler) Name() string { return "hostconfig" }

// Run converges immediately, then on Interval or vars/cert changes.
func (r *Reconciler) Run(ctx context.Context) {
	if !r.cfg.Enabled {
		<-ctx.Done()
		return
	}
	if r.cfg.Watcher != nil {
		go r.cfg.Watcher.Poll(ctx)
	}
	r.Cycle(ctx)
	t := time.NewTicker(r.cfg.Interval)
	defer t.Stop()
	p := time.NewTicker(defaultWatchPoll)
	defer p.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.Cycle(ctx)
		case <-p.C:
			if r.cfg.Watcher != nil && r.cfg.Watcher.Changed() {
				slog.Info("hostconfig: vars/certs changed — converging", "subsystem", "hostconfig")
				r.Cycle(ctx)
			}
		}
	}
}

// hp joins HostRoot + host path.
func (r *Reconciler) hp(p string) string {
	return filepath.Join(r.cfg.HostRoot, p)
}

// run is a runner shorthand — failures are logged, not fatal.
func (r *Reconciler) run(ctx context.Context, name string, args ...string) (string, error) {
	return r.cfg.Runner.Run(ctx, name, args...)
}

// writeManaged writes content to HostRoot+path atomically when it
// differs (sha256). Returns changed. Preserves the existing file's
// mode; default mode when creating.
func (r *Reconciler) writeManaged(path string, content []byte, mode os.FileMode) (bool, error) {
	dst := r.hp(path)
	if old, err := os.ReadFile(dst); err == nil {
		sum := sha256.Sum256(old)
		nsum := sha256.Sum256(content)
		if sum == nsum {
			return false, nil
		}
		if st, err := os.Stat(dst); err == nil {
			mode = st.Mode().Perm()
		}
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return false, err
	}
	tmp := dst + ".hostconfig.tmp"
	if err := os.WriteFile(tmp, content, mode); err != nil {
		return false, err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return false, err
	}
	r.writes.WithLabelValues(path).Inc()
	slog.Info("hostconfig: wrote managed file", "path", path)
	return true, nil
}

func (r *Reconciler) removeManaged(path string) (bool, error) {
	dst := r.hp(path)
	fi, err := os.Lstat(dst)
	if err != nil {
		return false, nil
	}
	if fi.IsDir() {
		return false, fmt.Errorf("removeManaged: %s is a dir", path)
	}
	if err := os.Remove(dst); err != nil {
		return false, err
	}
	slog.Info("hostconfig: removed file", "path", path)
	return true, nil
}

func (r *Reconciler) ensureDir(path string, mode os.FileMode) error {
	return os.MkdirAll(r.hp(path), mode)
}

func (r *Reconciler) fileExists(path string) bool {
	_, err := os.Stat(r.hp(path))
	return err == nil
}

// render renders an embedded .j2 template against ctx.
func (r *Reconciler) render(name string, ctx map[string]any) ([]byte, error) {
	text, err := templates.ReadFile("templates/" + name)
	if err != nil {
		return nil, err
	}
	out, err := topology.Render(string(text), ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("render %s: %w", name, err)
	}
	return []byte(out), nil
}

// --- systemd helpers via runner ---

func (r *Reconciler) daemonReload(ctx context.Context) {
	r.actions.WithLabelValues("daemon-reload").Inc()
	if _, err := r.run(ctx, "systemctl", "daemon-reload"); err != nil {
		slog.Warn("daemon-reload failed", "err", err)
	}
}

func (r *Reconciler) isActive(ctx context.Context, unit string) bool {
	out, err := r.run(ctx, "systemctl", "is-active", unit)
	return err == nil && strings.TrimSpace(out) == "active"
}

func (r *Reconciler) serviceState(ctx context.Context, unit string) string {
	out, _ := r.run(ctx, "systemctl", "show", unit, "-p", "ActiveState", "--value")
	return strings.TrimSpace(out)
}

// ensureService ports systemd_service enabled+state.
func (r *Reconciler) ensureService(ctx context.Context, unit string, enable, start bool) {
	if enable {
		r.run(ctx, "systemctl", "enable", unit)
	}
	if start {
		r.run(ctx, "systemctl", "start", unit)
	} else {
		r.run(ctx, "systemctl", "stop", unit)
	}
}

func (r *Reconciler) restartService(ctx context.Context, unit string) {
	r.actions.WithLabelValues("restart:" + unit).Inc()
	if _, err := r.run(ctx, "systemctl", "restart", unit); err != nil {
		slog.Warn("restart failed", "unit", unit, "err", err)
	}
}

func (r *Reconciler) reloadService(ctx context.Context, unit string) {
	r.actions.WithLabelValues("reload:" + unit).Inc()
	if _, err := r.run(ctx, "systemctl", "reload", unit); err != nil {
		slog.Warn("reload failed", "unit", unit, "err", err)
	}
}

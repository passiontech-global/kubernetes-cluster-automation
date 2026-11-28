// kmsv2_guard.go — K10 KMSv2 encryption plugin unhealthy/hung socket guard.
//
// Discovers KMSv2 unix sockets (<K0sRunDir>/kms.sock plus any sockets declared
// in kube-apiserver's --encryption-provider-config or <HostRoot>/etc/k0s/k0s.yaml),
// probes each socket with a bounded non-blocking HTTP/2 preface check, and
// probes /healthz/kms-provider-* over the local apiserver mTLS client with
// bounded response reads. Auto-skips cleanly when KMSv2 is not configured.
// Enters StateKMSv2Unhealthy and gates k0scontroller restarts through
// RestartWithGates (honoring Sig13.Mode, quorum, maintenance hold, cooldown,
// and SPOF streak doubling).
package apiserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/httpx"
)

const (
	maxKMSConfigBytes    = 1 << 20
	kmsHealthzMaxRead    = 64 << 10
	kmsHealthzTimeout    = 2 * time.Second
	kmsMaxProvidersProbe = 16
	kmsLatchStreakNeeded = 2
	kmsRestartBaseStreak = 2
)

// KMSv2Check is the KMSv2 encryption plugin health & socket guard.
type KMSv2Check struct {
	d         *cdeps.Deps
	badCycles int
}

// Name returns the check label / log context.
func (c *KMSv2Check) Name() string { return cdeps.CheckKMSv2 }

// Run executes one KMSv2 guard cycle.
func (c *KMSv2Check) Run(ctx context.Context) {
	sockets, providerCount, kmsConfigured, cfgErr := c.discoverKMSv2()
	var reasons []string
	if cfgErr != "" {
		reasons = append(reasons, cfgErr)
	}

	probeCount := providerCount
	if probeCount <= 0 {
		probeCount = 1
	}
	if probeCount > kmsMaxProvidersProbe {
		probeCount = kmsMaxProvidersProbe
	}

	healthzConfigured, hzReasons := c.probeHealthzProviders(ctx, probeCount, kmsConfigured)
	reasons = append(reasons, hzReasons...)

	if !kmsConfigured && !healthzConfigured && len(reasons) == 0 {
		c.badCycles = 0
		c.d.StateExit(cdeps.StateKMSv2Unhealthy)
		c.d.Cycles.WithLabelValues(cdeps.CheckKMSv2, "ok").Inc()
		return
	}

	if c.d.Cfg.KMSProbeFn != nil {
		for _, sock := range sockets {
			if err := c.d.Cfg.KMSProbeFn(ctx, sock); err != nil {
				reasons = append(reasons, fmt.Sprintf("socket %s: %v", sock, err))
			}
		}
	}

	if len(reasons) == 0 {
		c.badCycles = 0
		c.d.StateExit(cdeps.StateKMSv2Unhealthy)
		c.d.Cycles.WithLabelValues(cdeps.CheckKMSv2, "ok").Inc()
		return
	}

	c.badCycles++
	reason := strings.Join(reasons, "; ")
	if c.badCycles < kmsLatchStreakNeeded {
		c.d.Cycles.WithLabelValues(cdeps.CheckKMSv2, "suspect").Inc()
		return
	}

	c.d.State.Enter(cdeps.StateKMSv2Unhealthy, reason)
	c.d.State.SuspectLog(cdeps.StateKMSv2Unhealthy,
		"suspect: kmsv2-unhealthy "+reason, c.d.Cfg.SuspectLogCadence)

	if c.badCycles < c.d.StreakCycles(kmsRestartBaseStreak) {
		c.d.Cycles.WithLabelValues(cdeps.CheckKMSv2, "suspect").Inc()
		return
	}

	outcome, _ := c.d.RestartWithGates(ctx, cdeps.RestartGateSpec{
		Check:         cdeps.CheckKMSv2,
		State:         cdeps.StateKMSv2Unhealthy,
		Budget:        cdeps.FileRateRestart,
		Cooldown:      c.d.Cfg.Sig13.MinRestart,
		NeedQuorum:    true,
		HoldPrefix:    "kmsv2-unhealthy " + reason,
		Unit:          c.d.Cfg.RestartUnit,
		Mode:          c.d.Cfg.Sig13.Mode,
		ActionLine:    "ACTION: restarting k0scontroller - kmsv2-unhealthy " + reason,
		DryRunLine:    "DRY-RUN: would restart k0scontroller - kmsv2-unhealthy " + reason,
		ActionLabel:   "restart_controller",
		DryRunLabel:   "dryrun_restart",
		BeforeRestart: func() { c.badCycles = 0 },
	})
	c.d.Cycles.WithLabelValues(cdeps.CheckKMSv2, outcome).Inc()
}

func (c *KMSv2Check) hostPath(p string) (string, error) {
	if p == "" || strings.ContainsRune(p, 0) {
		return "", errors.New("empty or NUL path")
	}
	for _, seg := range strings.Split(filepath.ToSlash(p), "/") {
		if seg == ".." {
			return "", fmt.Errorf("path %q contains traversal segment", p)
		}
	}
	cleaned := filepath.Clean(p)
	if cleaned == "." || cleaned == ".." {
		return "", fmt.Errorf("invalid path %q", p)
	}
	hr := c.d.Cfg.HostRoot
	if hr == "" || filepath.Clean(hr) == "/" {
		return cleaned, nil
	}
	hr = filepath.Clean(hr)

	var joined string
	if cleaned == hr || strings.HasPrefix(cleaned, hr+string(filepath.Separator)) {
		joined = cleaned
	} else {
		joined = filepath.Join(hr, cleaned)
	}
	if !withinDir(hr, joined) {
		return "", fmt.Errorf("path %q escapes HostRoot %q", p, hr)
	}

	hrReal, err := filepath.EvalSymlinks(hr)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return joined, nil
		}
		return "", fmt.Errorf("resolve HostRoot %q: %w", hr, err)
	}
	if err := checkSymlinkConfinement(hrReal, joined, p); err != nil {
		return "", err
	}
	return joined, nil
}

func withinDir(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func checkSymlinkConfinement(hrReal, joined, orig string) error {
	cur := joined
	for {
		fi, err := os.Lstat(cur)
		if err == nil {
			realCur, rerr := filepath.EvalSymlinks(cur)
			if rerr != nil {
				if fi.Mode()&os.ModeSymlink != 0 {
					return fmt.Errorf("path %q has unresolvable symlink %q: %w", orig, cur, rerr)
				}
				return fmt.Errorf("resolve path %q: %w", orig, rerr)
			}
			if !withinDir(hrReal, realCur) {
				return fmt.Errorf("path %q escapes HostRoot via symlink", orig)
			}
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat path %q: %w", orig, err)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return nil
		}
		cur = parent
	}
}

func readHostConfigBounded(path string, maxBytes int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("non-regular file %s (mode %s)", path, fi.Mode())
	}
	if fi.Size() > maxBytes {
		return nil, fmt.Errorf("file %s exceeds %d bytes (%d bytes)", path, maxBytes, fi.Size())
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file %s exceeds %d bytes", path, maxBytes)
	}
	return data, nil
}

func (c *KMSv2Check) discoverKMSv2() (sockets []string, providerCount int, configured bool, cfgErr string) {
	seenSock := map[string]bool{}
	addSock := func(p string) {
		p = filepath.Clean(p)
		if p == "" || p == "." || seenSock[p] {
			return
		}
		seenSock[p] = true
		sockets = append(sockets, p)
	}

	if c.d.Cfg.K0sRunDir != "" {
		defSock := filepath.Join(c.d.Cfg.K0sRunDir, "kms.sock")
		if _, err := os.Stat(defSock); err == nil {
			addSock(defSock)
			configured = true
		}
	}

	encCfgPath := c.findEncryptionConfigFromProc()
	if encCfgPath == "" && c.d.Cfg.HostRoot != "" {
		var k0sErr error
		encCfgPath, k0sErr = c.findEncryptionConfigFromK0sYAML()
		if k0sErr != nil {
			return sockets, providerCount, true, k0sErr.Error()
		}
	}
	if encCfgPath == "" {
		return sockets, providerCount, configured, ""
	}

	resolved, err := c.hostPath(encCfgPath)
	if err != nil {
		return sockets, providerCount, true, fmt.Sprintf("invalid encryption config path %q: %v", encCfgPath, err)
	}
	raw, err := readHostConfigBounded(resolved, maxKMSConfigBytes)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return sockets, providerCount, true, fmt.Sprintf("read encryption config %s: %v", resolved, err)
		}
		return sockets, providerCount, configured, ""
	}

	var encCfg struct {
		Resources []struct {
			Providers []struct {
				KMS *struct {
					Name     string `json:"name"`
					Endpoint string `json:"endpoint"`
				} `json:"kms"`
			} `json:"providers"`
		} `json:"resources"`
	}
	if err := yaml.Unmarshal(raw, &encCfg); err != nil {
		return sockets, providerCount, true, fmt.Sprintf("parse encryption config %s: %v", resolved, err)
	}
	var endpointErrs []string
	for _, res := range encCfg.Resources {
		for _, prov := range res.Providers {
			if prov.KMS == nil {
				continue
			}
			configured = true
			providerCount++
			if sock, ok := strings.CutPrefix(prov.KMS.Endpoint, "unix://"); ok && sock != "" {
				resolvedSock, err := c.hostPath(sock)
				if err != nil {
					endpointErrs = append(endpointErrs, fmt.Sprintf("invalid kms endpoint %q: %v", prov.KMS.Endpoint, err))
					continue
				}
				addSock(resolvedSock)
			}
		}
	}
	if len(endpointErrs) > 0 {
		return sockets, providerCount, configured, strings.Join(endpointErrs, "; ")
	}
	return sockets, providerCount, configured, ""
}

func procHasRootUID(statusPath string) bool {
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return false
	}
	for ln := range strings.SplitSeq(string(data), "\n") {
		if rest, ok := strings.CutPrefix(ln, "Uid:"); ok {
			fields := strings.Fields(rest)
			return len(fields) >= 2 && fields[0] == "0" && fields[1] == "0"
		}
	}
	return false
}

func (c *KMSv2Check) findEncryptionConfigFromProc() string {
	pids, err := c.d.Proc.PIDs()
	if err != nil {
		return ""
	}
	slices.Sort(pids)
	for _, pid := range pids {
		st, ok := c.d.Proc.Stat(pid)
		if !ok || len(st.Fields) == 0 {
			continue
		}
		// Never touch mm-backed cmdline on D/Z/X/x tasks.
		switch st.Fields[0] {
		case "D", "Z", "X", "x":
			continue
		}
		if !st.HasComm || st.Comm != "kube-apiserver" {
			continue
		}
		// Anti-spoof: only trust the real root-owned kube-apiserver inside
		// k0scontroller.service (never a container/unprivileged process
		// spoofing comm="kube-apiserver").
		if !c.d.Proc.CgroupContains(pid, cdeps.K0sControllerCgroupSubstr) ||
			c.d.Proc.CgroupContains(pid, "kubepods") ||
			!procHasRootUID(c.d.Proc.File(pid, "status")) {
			continue
		}
		argv := c.d.Proc.Cmdline(pid)
		for i, a := range argv {
			if v, ok := strings.CutPrefix(a, "--encryption-provider-config="); ok && v != "" {
				return v
			}
			if a == "--encryption-provider-config" && i+1 < len(argv) && argv[i+1] != "" {
				return argv[i+1]
			}
		}
		// The real kube-apiserver was found and has no encryption config flag;
		// stop here rather than falling through to later PIDs.
		return ""
	}
	return ""
}

func (c *KMSv2Check) findEncryptionConfigFromK0sYAML() (string, error) {
	k0sPath, err := c.hostPath("/etc/k0s/k0s.yaml")
	if err != nil {
		return "", fmt.Errorf("resolve k0s config path: %w", err)
	}
	raw, err := readHostConfigBounded(k0sPath, maxKMSConfigBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("read k0s config %s: %w", k0sPath, err)
	}
	var cfg struct {
		Spec struct {
			API struct {
				ExtraArgs map[string]string `json:"extraArgs"`
			} `json:"api"`
		} `json:"spec"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return "", fmt.Errorf("parse k0s config %s: %w", k0sPath, err)
	}
	return cfg.Spec.API.ExtraArgs["encryption-provider-config"], nil
}

func (c *KMSv2Check) probeHealthzProviders(ctx context.Context, count int, kmsConfigured bool) (configured bool, reasons []string) {
	client := c.d.EnsureClient()
	if client == nil {
		return false, nil
	}
	ep := c.d.Cfg.Hub.SelfAPI
	if ep == "" {
		ep = c.d.Cfg.Hub.SelfEndpoint
	}
	ep = strings.TrimPrefix(ep, "https://")
	ep = strings.TrimPrefix(ep, "http://")
	ep = strings.TrimSuffix(ep, "/")
	if ep == "" {
		return false, nil
	}

	timeout := kmsHealthzTimeout
	if c.d.Cfg.QueryTimeout > 0 && c.d.Cfg.QueryTimeout < timeout {
		timeout = c.d.Cfg.QueryTimeout
	}

	for i := range count {
		u := fmt.Sprintf("https://%s/healthz/kms-provider-%d", ep, i)
		qctx, cancel := context.WithTimeout(ctx, timeout)
		req, err := http.NewRequestWithContext(qctx, http.MethodGet, u, nil)
		if err != nil {
			cancel()
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			if kmsConfigured {
				reasons = append(reasons, fmt.Sprintf("/healthz/kms-provider-%d: %v", i, err))
			}
			continue
		}
		httpx.DrainAndClose(resp.Body, kmsHealthzMaxRead)
		_ = resp.Body.Close()
		cancel()

		if resp.StatusCode == http.StatusNotFound {
			continue
		}
		configured = true
		if resp.StatusCode/100 != 2 {
			reasons = append(reasons, fmt.Sprintf("/healthz/kms-provider-%d HTTP %d", i, resp.StatusCode))
		}
	}
	return configured, reasons
}

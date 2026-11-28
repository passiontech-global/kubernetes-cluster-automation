package main_test

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	eventsv1 "k8s.io/api/events/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
)

const e2eReqVersion = "v0.0.0-e2e-req"

func TestE2ERequirements(t *testing.T) {
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "node-host-agent")
	buildCmd := exec.CommandContext(t.Context(), "go", "build",
		"-ldflags=-X main.version="+e2eReqVersion,
		"-o", binPath, ".")
	buildCmd.Env = os.Environ()
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("compile agent binary: %v\n%s", err, out)
	}

	t.Run("Tier1", func(t *testing.T) {
		runTier1Tests(t, binPath)
	})
	t.Run("Tier2", func(t *testing.T) {
		runTier2Tests(t, binPath)
	})
	t.Run("Tier3", func(t *testing.T) {
		runTier3Tests(t, binPath)
	})
	t.Run("Tier4", func(t *testing.T) {
		runTier4Tests(t, binPath)
	})
}

type reqSandbox struct {
	root           string
	hostroot       string
	vars           string
	state          string
	logFile        string
	textfile       string
	openebs        string
	proc           string
	cgroup         string
	k0s            string
	kubeletPods    string
	pluginsReg     string
	ctrTaskRoot    string
	sandboxCtlRoot string
	wlayerDir      string
	coredumpDir    string
	devShmDir      string
	runDir         string
	fakebin        string
	toolLog        string
	envMap         map[string]string
}

func newReqSandbox(t *testing.T, overrides map[string]string) *reqSandbox {
	t.Helper()
	root := t.TempDir()
	sb := &reqSandbox{
		root:           root,
		hostroot:       filepath.Join(root, "hostroot"),
		vars:           filepath.Join(root, "vars"),
		state:          filepath.Join(root, "state"),
		logFile:        filepath.Join(root, "watchdog.log"),
		textfile:       filepath.Join(root, "textfile"),
		openebs:        filepath.Join(root, "openebs"),
		proc:           filepath.Join(root, "proc"),
		cgroup:         filepath.Join(root, "sys", "fs", "cgroup"),
		k0s:            filepath.Join(root, "k0s"),
		kubeletPods:    filepath.Join(root, "hostroot", "var", "lib", "k0s", "kubelet", "pods"),
		pluginsReg:     filepath.Join(root, "hostroot", "var", "lib", "k0s", "kubelet", "plugins_registry"),
		ctrTaskRoot:    filepath.Join(root, "hostroot", "run", "k0s", "containerd", "io.containerd.runtime.v2.task", "k8s.io"),
		sandboxCtlRoot: filepath.Join(root, "hostroot", "run", "k0s", "containerd", "io.containerd.sandbox.controller.v1.shim"),
		wlayerDir:      filepath.Join(root, "wlayer"),
		coredumpDir:    filepath.Join(root, "coredump"),
		devShmDir:      filepath.Join(root, "dev", "shm"),
		runDir:         filepath.Join(root, "run"),
		fakebin:        filepath.Join(root, "fakebin"),
		toolLog:        filepath.Join(root, "tool-calls.log"),
	}

	dirs := []string{
		sb.hostroot,
		filepath.Join(sb.hostroot, "etc", "systemd", "system"),
		filepath.Join(sb.hostroot, "etc", "kine"),
		filepath.Join(sb.hostroot, "etc", "k0s"),
		filepath.Join(sb.hostroot, "var", "lib", "k0s", "bin"),
		filepath.Join(sb.hostroot, "var", "lib", "k0s", "pki", "etcd"),
		filepath.Join(sb.hostroot, "var", "backups", "etcd"),
		filepath.Join(sb.hostroot, "var", "backups", "kine"),
		filepath.Join(sb.hostroot, "var", "lib", "kine-compact-guard"),
		filepath.Join(sb.hostroot, "opt", "apps", "postgres"),
		filepath.Join(sb.hostroot, "run", "k0s"),
		filepath.Join(sb.hostroot, "usr", "local", "bin"),
		sb.kubeletPods,
		sb.pluginsReg,
		sb.ctrTaskRoot,
		sb.sandboxCtlRoot,
		sb.vars,
		sb.state,
		sb.textfile,
		sb.openebs,
		sb.proc,
		filepath.Join(sb.proc, "1", "net"),
		filepath.Join(sb.proc, "net", "stat"),
		filepath.Join(sb.proc, "pressure"),
		filepath.Join(root, "sys", "clocksource0"),
		filepath.Join(root, "sys", "class", "net"),
		sb.cgroup,
		filepath.Join(root, "etc", "nebula"),
		filepath.Join(root, "etc", "k0s"),
		filepath.Join(root, "etc", "systemd", "system"),
		filepath.Join(sb.k0s, "bin"),
		filepath.Join(sb.k0s, "pki", "etcd"),
		sb.wlayerDir,
		sb.coredumpDir,
		sb.devShmDir,
		sb.runDir,
		filepath.Join(root, "journal"),
		filepath.Join(root, "keys"),
		filepath.Join(root, "wd-scripts"),
		sb.fakebin,
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// Default uptime >= 1200s so workerhygiene and controllerhygiene uptime gates pass.
	if err := os.WriteFile(filepath.Join(sb.proc, "uptime"), []byte("3600.00 3600.00\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Empty mountinfo and proc/stat defaults.
	if err := os.WriteFile(filepath.Join(sb.proc, "1", "mountinfo"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sb.proc, "stat"), []byte("cpu  100 0 100 1000 0 0 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Suppress dead local-port HTTP probes (:10248, :10250, :9879, :9962) by default
	// so workerhygiene cycles complete in milliseconds instead of burning ProbeGap retries.
	wdConf := filepath.Join(root, "etc", "node-watchdog.conf")
	wdBody := strings.Join([]string{
		"WD_SIG_KUBELET_STALL=off",
		"WD_SIG_KUBELET_SYNCLOOP=off",
		"WD_SIG_KUBELET_WATCHDOG=off",
		"WD_SIG_KUBELET_CERT=off",
		"WD_SIG_CILIUM=off",
		"WD_SIG_CILIUM_ENVOY=off",
		"WD_SIG_SPEGEL_MIRROR=off",
		"WD_SIG_CALICO_HYGIENE=off",
	}, "\n") + "\n"
	if err := os.WriteFile(wdConf, []byte(wdBody), 0o644); err != nil {
		t.Fatal(err)
	}

	installDefaultHostShims(t, sb)

	defaults := map[string]string{
		"NODE_HOST_AGENT_HOST_ROOT":                  sb.hostroot,
		"NODE_HOST_AGENT_WATCHDOG_CONF":              filepath.Join(root, "etc", "node-watchdog.conf"),
		"NODE_HOST_AGENT_WATCHDOG_STATE_DIR":         sb.state,
		"NODE_HOST_AGENT_WATCHDOG_LOG":               sb.logFile,
		"NODE_HOST_AGENT_WATCHDOG_LOG_FILE":          sb.logFile,
		"NODE_HOST_AGENT_JOURNAL_DIRS":               filepath.Join(root, "journal"),
		"NODE_HOST_AGENT_TEXTFILE_DIR":               sb.textfile,
		"NODE_HOST_AGENT_SWEEP_BASE_DIR":             sb.openebs,
		"NODE_HOST_AGENT_API_GUARD_CONF":             filepath.Join(root, "etc", "api-backend-guard.conf"),
		"NODE_HOST_AGENT_APIPROBER_SOCKET":           filepath.Join(sb.runDir, "api-lb.sock"),
		"NODE_HOST_AGENT_CONVERGE_SSH_KEY":           filepath.Join(root, "keys", "converge"),
		"NODE_HOST_AGENT_HOSTCONFIG_VARS_DIR":        sb.vars,
		"NODE_HOST_AGENT_PROC_ROOT":                  sb.proc,
		"NODE_HOST_AGENT_MOUNTINFO_FILE":             filepath.Join(sb.proc, "1", "mountinfo"),
		"NODE_HOST_AGENT_CGROUP_ROOT":                sb.cgroup,
		"NODE_HOST_AGENT_KUBELET_PODS_DIR":           sb.kubeletPods,
		"NODE_HOST_AGENT_CTR_TASK_ROOT":              sb.ctrTaskRoot,
		"NODE_HOST_AGENT_SANDBOX_CTL_ROOT":           sb.sandboxCtlRoot,
		"NODE_HOST_AGENT_CONTAINERD_SOCKET":          filepath.Join(sb.hostroot, "run", "k0s", "containerd.sock"),
		"NODE_HOST_AGENT_K0S_WORKER_UNIT":            filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"),
		"NODE_HOST_AGENT_K0S_UNIT":                   filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"),
		"NODE_HOST_AGENT_K0S_CONFIG":                 filepath.Join(sb.hostroot, "etc", "k0s", "k0s.yaml"),
		"NODE_HOST_AGENT_K0S_DIR":                    sb.k0s,
		"NODE_HOST_AGENT_HOST_RESOLV_CONF":           filepath.Join(root, "etc", "resolv.conf"),
		"NODE_HOST_AGENT_HOSTS_FILE":                 filepath.Join(root, "etc", "hosts"),
		"NODE_HOST_AGENT_CLOCKSOURCE_CURRENT_FILE":   filepath.Join(root, "sys", "clocksource0", "current_clocksource"),
		"NODE_HOST_AGENT_CLOCKSOURCE_AVAILABLE_FILE": filepath.Join(root, "sys", "clocksource0", "available_clocksource"),
		"NODE_HOST_AGENT_FILESYSTEM_TARGETS":         root,
		"NODE_HOST_AGENT_SYS_CLASS_NET":              filepath.Join(root, "sys", "class", "net"),
		"NODE_HOST_AGENT_NEBULA_CERT":                filepath.Join(root, "etc", "nebula", "host.crt"),
		"NODE_HOST_AGENT_NEBULA_CERTS_DIR":           filepath.Join(root, "etc", "nebula"),
		"NODE_HOST_AGENT_HOST_ROUTE_FILE":            filepath.Join(sb.proc, "net", "route"),
		"NODE_HOST_AGENT_PSI_FILE":                   filepath.Join(sb.proc, "pressure", "cpu"),
		"NODE_HOST_AGENT_KEY_USERS_FILE":             filepath.Join(sb.proc, "key-users"),
		"NODE_HOST_AGENT_CONNTRACK_STAT_FILE":        filepath.Join(sb.proc, "net", "stat", "nf_conntrack"),
		"NODE_HOST_AGENT_ARP_TABLE_FILE":             filepath.Join(sb.proc, "net", "arp"),
		"NODE_HOST_AGENT_PROC_NET_UDP":               filepath.Join(sb.proc, "net", "udp"),
		"NODE_HOST_AGENT_PROC_NET_UDP6":              filepath.Join(sb.proc, "net", "udp6"),
		"NODE_HOST_AGENT_UPTIME_FILE":                filepath.Join(sb.proc, "uptime"),
		"NODE_HOST_AGENT_HOST_RUN_DIR":               sb.runDir,
		"NODE_HOST_AGENT_DEV_SHM_DIR":                sb.devShmDir,
		"NODE_HOST_AGENT_LOCALPV_QUOTA_DIR":          sb.openebs,
		"NODE_HOST_AGENT_WLAYER_SNAPSHOTS_DIR":       sb.wlayerDir,
		"NODE_HOST_AGENT_COREDUMP_DIR":               sb.coredumpDir,
		"NODE_HOST_AGENT_WATCHDOG_SCRIPTS_DIR":       filepath.Join(root, "wd-scripts"),
		"NODE_HOST_AGENT_NETFILTER_GUARD_LOCK_PATH":  filepath.Join(sb.runDir, "xtables.lock"),
		"NODE_HOST_AGENT_CILIUM_SOCKET":              filepath.Join(sb.runDir, "cilium.sock"),
		"NODE_HOST_AGENT_LATCH_INTERVAL":             "24h",
		"NODE_HOST_AGENT_ENABLE_SWEEPER":             "false",
		"NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE":     "false",
		"NODE_HOST_AGENT_ENABLE_APIPROBER":           "false",
		"NODE_HOST_AGENT_ENABLE_HOSTMETRICS":         "false",
		"NODE_HOST_AGENT_ENABLE_HYGIENE":             "false",
		"NODE_HOST_AGENT_ENABLE_NETHEALTH":           "false",
		"NODE_HOST_AGENT_ENABLE_JANITOR":             "false",
		"NODE_HOST_AGENT_ENABLE_REPORTER":            "false",
		"NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE":   "false",
		"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":          "false",
		"NODE_HOST_AGENT_ENABLE_KINEDB":              "false",
	}
	for k, v := range overrides {
		if v == "" {
			delete(defaults, k)
		} else {
			defaults[k] = v
		}
	}
	sb.envMap = defaults
	return sb
}

func (sb *reqSandbox) envSlice() []string {
	scrub := map[string]bool{
		"KUBERNETES_SERVICE_HOST": true,
		"KUBERNETES_SERVICE_PORT": true,
		"KUBECONFIG":              true,
		"NOTIFY_SOCKET":           true,
		"DBUS_SYSTEM_BUS_ADDRESS": true,
		"WATCHDOG_PID":            true,
		"WATCHDOG_USEC":           true,
		"POD_NAME":                true,
		"POD_NAMESPACE":           true,
		"NODE_NAME":               true,
		"PATH":                    true,
	}
	var env []string
	for _, kv := range os.Environ() {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if scrub[k] || strings.HasPrefix(k, "NODE_HOST_AGENT_") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "PATH="+sb.fakebin+":"+os.Getenv("PATH"))
	keys := make([]string, 0, len(sb.envMap))
	for k := range sb.envMap {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		env = append(env, k+"="+sb.envMap[k])
	}
	return env
}

func installFakeTool(t *testing.T, fakebin, name, scriptBody string) string {
	t.Helper()
	p := filepath.Join(fakebin, name)
	if err := os.WriteFile(p, []byte(scriptBody), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func installDefaultHostShims(t *testing.T, sb *reqSandbox) {
	t.Helper()
	nsenterScript := fmt.Sprintf(`#!/bin/sh
echo "nsenter $*" >> %q
while [ $# -gt 0 ]; do
  case "$1" in
    --) shift; break ;;
    -t|-m|-u|-i|-n|-p|-U|-r|-w)
      if [ "$1" = "-t" ]; then shift; fi
      shift ;;
    *) shift ;;
  esac
done
if [ $# -gt 0 ]; then
  exec "$@"
fi
exit 0
`, sb.toolLog)
	installFakeTool(t, sb.fakebin, "nsenter", nsenterScript)

	systemctlScript := fmt.Sprintf(`#!/bin/sh
echo "systemctl $*" >> %q
if [ "$1" = "is-active" ]; then
  echo "active"
  exit 0
fi
exit 0
`, sb.toolLog)
	installFakeTool(t, sb.fakebin, "systemctl", systemctlScript)

	k0sScript := fmt.Sprintf(`#!/bin/sh
echo "k0s $*" >> %q
exit 0
`, sb.toolLog)
	installFakeTool(t, sb.fakebin, "k0s", k0sScript)

	umountScript := fmt.Sprintf(`#!/bin/sh
echo "umount $*" >> %q
exit 0
`, sb.toolLog)
	installFakeTool(t, sb.fakebin, "umount", umountScript)

	journalctlScript := fmt.Sprintf(`#!/bin/sh
echo "journalctl $*" >> %q
exit 0
`, sb.toolLog)
	installFakeTool(t, sb.fakebin, "journalctl", journalctlScript)

	iptScript := fmt.Sprintf(`#!/bin/sh
echo "iptables-legacy-save $*" >> %q
exit 0
`, sb.toolLog)
	installFakeTool(t, sb.fakebin, "iptables-legacy-save", iptScript)
}

type runningReqAgent struct {
	cmd      *exec.Cmd
	start    agentStartLog
	addrs    map[string]string
	stdout   *syncBuffer
	stderr   *syncBuffer
	waitDone chan struct{}
	waitErr  error
}

func startReqAgent(t *testing.T, bin string, env []string, extraArgs ...string) *runningReqAgent {
	t.Helper()
	args := []string{
		"--metrics-bind-address=127.0.0.1:0",
		"--health-probe-bind-address=127.0.0.1:0",
		"--pprof-bind-address=127.0.0.1:0",
	}
	args = append(args, extraArgs...)
	expectServers := []string{"metrics", "probe", "pprof-loopback"}

	cmd := exec.CommandContext(t.Context(), bin, args...)
	cmd.Env = env
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutBuf := &syncBuffer{}
	stderrBuf := &syncBuffer{}
	cmd.Stderr = stderrBuf

	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s %v: %v", bin, args, err)
	}

	waitDone := make(chan struct{})
	startCh := make(chan agentStartLog, 1)
	listenCh := make(chan listeningLog, 8)
	scanDone := make(chan struct{})

	go func() {
		defer close(scanDone)
		sc := bufio.NewScanner(stdoutPipe)
		sc.Buffer(make([]byte, 0, 64*1024), 2<<20)
		var startSent bool
		for sc.Scan() {
			line := sc.Text()
			_, _ = stdoutBuf.Write([]byte(line + "\n"))
			var probe struct {
				Msg string `json:"msg"`
			}
			if err := json.Unmarshal([]byte(line), &probe); err != nil {
				continue
			}
			switch probe.Msg {
			case "starting node-host-agent":
				var sl agentStartLog
				if err := json.Unmarshal([]byte(line), &sl); err == nil && !startSent {
					startSent = true
					startCh <- sl
				}
			case "listening":
				var ll listeningLog
				if err := json.Unmarshal([]byte(line), &ll); err == nil {
					listenCh <- ll
				}
			}
		}
	}()

	ra := &runningReqAgent{
		cmd:      cmd,
		addrs:    make(map[string]string),
		stdout:   stdoutBuf,
		stderr:   stderrBuf,
		waitDone: waitDone,
	}

	go func() {
		<-scanDone
		ra.waitErr = cmd.Wait()
		close(waitDone)
	}()

	t.Cleanup(func() {
		select {
		case <-waitDone:
			return
		default:
		}
		if cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-waitDone:
				return
			case <-time.After(4 * time.Second):
				_ = cmd.Process.Kill()
				<-waitDone
			}
		}
	})

	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()

	gotStart := false
	for !gotStart || len(ra.addrs) < len(expectServers) {
		select {
		case sl := <-startCh:
			ra.start = sl
			gotStart = true
		case ll := <-listenCh:
			ra.addrs[ll.Server] = ll.Addr
		case <-waitDone:
			t.Fatalf("agent exited before ready (err=%v)\nstdout:\n%s\nstderr:\n%s",
				ra.waitErr, stdoutBuf.String(), stderrBuf.String())
		case <-deadline.C:
			t.Fatalf("timed out waiting for agent startup/listeners (gotStart=%v addrs=%v)\nstdout:\n%s\nstderr:\n%s",
				gotStart, ra.addrs, stdoutBuf.String(), stderrBuf.String())
		}
	}

	drain := time.NewTimer(20 * time.Millisecond)
	defer drain.Stop()
	for {
		select {
		case ll := <-listenCh:
			ra.addrs[ll.Server] = ll.Addr
		case <-drain.C:
			return ra
		}
	}
}

func (ra *runningReqAgent) metricsURL() string {
	return "http://" + ra.addrs["metrics"] + "/metrics"
}

func (ra *runningReqAgent) healthzURL() string {
	return "http://" + ra.addrs["probe"] + "/healthz"
}

func (ra *runningReqAgent) readyzURL() string {
	return "http://" + ra.addrs["probe"] + "/readyz"
}

func (ra *runningReqAgent) pprofURL() string {
	return "http://" + ra.addrs["pprof-loopback"] + "/debug/pprof/"
}

func (ra *runningReqAgent) scrapeMetrics(t *testing.T) string {
	t.Helper()
	code, body := reqHTTPGet(t, ra.metricsURL())
	if code != http.StatusOK {
		t.Fatalf("GET /metrics status=%d body=%s", code, body)
	}
	return body
}

func (ra *runningReqAgent) logsCombined() string {
	return ra.stdout.String() + "\n" + ra.stderr.String()
}

func (ra *runningReqAgent) stopAndWait(t *testing.T) {
	t.Helper()
	if err := ra.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	select {
	case <-ra.waitDone:
		if ra.waitErr != nil {
			t.Fatalf("agent exited with non-zero status on SIGTERM: %v\nstdout:\n%s\nstderr:\n%s",
				ra.waitErr, ra.stdout.String(), ra.stderr.String())
		}
	case <-time.After(8 * time.Second):
		_ = ra.cmd.Process.Kill()
		<-ra.waitDone
		t.Fatal("timed out waiting for clean exit after SIGTERM")
	}
}

func reqHTTPGet(t *testing.T, url string) (int, string) {
	t.Helper()
	client := &http.Client{Timeout: 4 * time.Second}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request %s: %v", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		t.Fatalf("read body %s: %v", url, err)
	}
	return resp.StatusCode, string(body)
}

func eventually(t *testing.T, timeout, interval time.Duration, desc string, cond func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		lastErr = cond()
		if lastErr == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("eventually(%s) timed out after %v: %v", desc, timeout, lastErr)
		}
		time.Sleep(interval)
	}
}

func spawnDummySleep(t *testing.T, secs int) (<-chan error, int) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "sleep", strconv.Itoa(secs))
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn sleep: %v", err)
	}
	pid := cmd.Process.Pid
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		select {
		case <-done:
			return
		default:
		}
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
	})
	return done, pid
}

func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	statBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	stat := string(statBytes)
	idx := strings.LastIndex(stat, ") ")
	if idx < 0 || idx+2 >= len(stat) {
		return false
	}
	switch stat[idx+2] {
	case 'Z', 'X', 'x':
		return false
	}
	return syscall.Kill(pid, 0) == nil
}

func assertNoCtrShimKill(t *testing.T, ra *runningReqAgent) {
	t.Helper()
	if v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_actions_total", `check="ctr-tasks"`, `action="shim_kill"`); ok && v != 0 {
		t.Fatalf("unexpected ctr-tasks shim_kill action metric: %v", v)
	}
}

// parseMetricValue finds the first metric line matching name and all required substring labels (e.g. `check="foo"`).
func parseMetricValue(body, metricName string, labelContains ...string) (float64, bool) {
	for line := range strings.SplitSeq(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, metricName+"{") && !strings.HasPrefix(line, metricName+" ") {
			continue
		}
		matched := true
		for _, sub := range labelContains {
			if !strings.Contains(line, sub) {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		idx := strings.LastIndexByte(line, ' ')
		if idx < 0 {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(line[idx+1:]), 64)
		if err != nil {
			continue
		}
		return v, true
	}
	return 0, false
}

// sumMetricValues sums all metric lines matching name and all required substring labels
// (e.g. summing across all result="..." values for a workerhygiene check).
func sumMetricValues(body, metricName string, labelContains ...string) (float64, bool) {
	var total float64
	found := false
	for line := range strings.SplitSeq(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, metricName+"{") && !strings.HasPrefix(line, metricName+" ") {
			continue
		}
		matched := true
		for _, sub := range labelContains {
			if !strings.Contains(line, sub) {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		idx := strings.LastIndexByte(line, ' ')
		if idx < 0 {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(line[idx+1:]), 64)
		if err != nil {
			continue
		}
		total += v
		found = true
	}
	return total, found
}

func (ra *runningReqAgent) workerHygieneCycles(t *testing.T, check string) float64 {
	t.Helper()
	v, _ := sumMetricValues(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", fmt.Sprintf(`check=%q`, check))
	return v
}

func (ra *runningReqAgent) waitWorkerHygieneCycles(t *testing.T, check string, minCycles float64, timeout time.Duration) {
	t.Helper()
	eventually(t, timeout, 25*time.Millisecond, fmt.Sprintf("%s cycles >= %.0f", check, minCycles), func() error {
		v, ok := sumMetricValues(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", fmt.Sprintf(`check=%q`, check))
		if !ok || v < minCycles {
			return fmt.Errorf("%s cycles ok=%v v=%v want >= %.0f", check, ok, v, minCycles)
		}
		return nil
	})
}

func (ra *runningReqAgent) waitNextWorkerHygieneCycle(t *testing.T, check string, timeout time.Duration) float64 {
	t.Helper()
	prev := ra.workerHygieneCycles(t, check)
	target := prev + 1
	var got float64
	eventually(t, timeout, 25*time.Millisecond, fmt.Sprintf("%s cycle > %.0f", check, prev), func() error {
		v, ok := sumMetricValues(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", fmt.Sprintf(`check=%q`, check))
		if !ok || v < target {
			return fmt.Errorf("%s cycles ok=%v v=%v want >= %.0f", check, ok, v, target)
		}
		got = v
		return nil
	})
	return got
}

func hasK5WatchdogLatch(sb *reqSandbox) bool {
	if sb == nil {
		return false
	}
	latches, _ := filepath.Glob(filepath.Join(sb.state, "state-*"))
	for _, p := range latches {
		name := strings.ToLower(strings.TrimPrefix(filepath.Base(p), "state-"))
		switch name {
		case "cgroup-dying-leak", "pod-teardown-wedged", "netfilter-locked",
			"systemd-oomd-kill", "host-kernel-drift", "worker-kubelet-cert-expiring",
			"kubelet-runtime-stall", "kubelet-watch-wedge", "kubelet-healthz-down",
			"kubelet-syncloop-down", "kubelet-pleg-unhealthy":
			continue
		}
		if strings.Contains(name, "cgroup") ||
			strings.Contains(name, "k8s135") ||
			strings.Contains(name, "readiness") ||
			strings.Contains(name, "secret-pulled") ||
			strings.Contains(name, "kubelet") {
			return true
		}
	}
	return false
}

// hasK5ReadinessSignal detects K5-specific cgroup v2 / KubeletEnsureSecretPulledImages
// readiness signals while excluding pre-existing workerhygiene cgroup-pod-throttle,
// node_cgroup_pids_*, node_agent_pod_cgroup_*, and KCM extraArgs drift lines.
func hasK5ReadinessSignal(metricsBody string, sb *reqSandbox) bool {
	for line := range strings.SplitSeq(metricsBody, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, _, _ := strings.Cut(line, "{")
		if name == line {
			name, _, _ = strings.Cut(line, " ")
		}
		switch {
		case strings.HasPrefix(name, "node_host_agent_workerhygiene_"),
			strings.HasPrefix(name, "node_cgroup_pids_"),
			strings.HasPrefix(name, "node_agent_pod_cgroup_"),
			strings.HasPrefix(name, "node_host_agent_cgroup_pids_"),
			strings.HasPrefix(name, "node_host_agent_cgroup_memory_"),
			strings.HasPrefix(name, "node_host_agent_systemd_scopes_count"):
			continue
		}
		if name == "node_k0s_config_drift" {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "cgroup") ||
				strings.Contains(lower, "failcgroupv1") ||
				strings.Contains(lower, "kubeletensuresecretpulledimages") {
				idx := strings.LastIndexByte(line, ' ')
				if idx > 0 {
					if v, err := strconv.ParseFloat(strings.TrimSpace(line[idx+1:]), 64); err == nil && v != 0 {
						return true
					}
				}
			}
			continue
		}
		if name == "node_host_agent_watchdog_state" || name == "node_watchdog_state" {
			lower := strings.ToLower(line)
			if strings.Contains(lower, `state="cgroup-dying-leak"`) ||
				strings.Contains(lower, `state="kubelet-`) ||
				strings.Contains(lower, `state="worker-kubelet-`) {
				continue
			}
			if strings.Contains(lower, "cgroup") ||
				strings.Contains(lower, "k8s135") ||
				strings.Contains(lower, "readiness") ||
				strings.Contains(lower, "kubelet") {
				idx := strings.LastIndexByte(line, ' ')
				if idx > 0 {
					if v, err := strconv.ParseFloat(strings.TrimSpace(line[idx+1:]), 64); err == nil && v != 0 {
						return true
					}
				}
			}
			continue
		}
		lowerName := strings.ToLower(name)
		if strings.Contains(lowerName, "cgroup") ||
			strings.Contains(lowerName, "readiness") ||
			strings.Contains(lowerName, "k8s135") ||
			strings.Contains(lowerName, "kubelet_ensure") ||
			strings.Contains(lowerName, "secret_pulled") {
			idx := strings.LastIndexByte(line, ' ')
			if idx > 0 {
				if _, err := strconv.ParseFloat(strings.TrimSpace(line[idx+1:]), 64); err == nil {
					return true
				}
			}
		}
	}
	if hasK5WatchdogLatch(sb) {
		return true
	}
	if sb != nil {
		if logBytes, err := os.ReadFile(sb.logFile); err == nil {
			lowerLog := strings.ToLower(string(logBytes))
			if strings.Contains(lowerLog, "cgroup2") ||
				strings.Contains(lowerLog, "cgroupfs") ||
				strings.Contains(lowerLog, "failcgroupv1") ||
				strings.Contains(lowerLog, "kubeletensuresecretpulledimages") {
				return true
			}
		}
	}
	return false
}

type tarEntry struct {
	name     string
	body     []byte
	mode     int64
	linkname string
	typeflag byte
}

func sha256Bytes(in []byte) [32]byte {
	return sha256.Sum256(in)
}

func makeTarGz(t *testing.T, entries []tarEntry) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, e := range entries {
		tf := e.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		mode := e.mode
		if mode == 0 {
			mode = 0o755
		}
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     mode,
			Size:     int64(len(e.body)),
			Typeflag: tf,
			Linkname: e.linkname,
			ModTime:  time.Unix(1700000000, 0),
		}
		if tf == tar.TypeSymlink {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if tf == tar.TypeReg && len(e.body) > 0 {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:])
}

func writeHostconfigVars(t *testing.T, varsDir, defaultsYAML, clusterYAML, nodesYAML string) {
	t.Helper()
	if clusterYAML == "" {
		clusterYAML = "{}\n"
	}
	if nodesYAML == "" {
		nodesYAML = "{}\n"
	}
	if err := os.WriteFile(filepath.Join(varsDir, "interdc_nodes.yaml"), []byte(nodesYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(varsDir, "cluster.yaml"), []byte(clusterYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(varsDir, "defaults.yaml"), []byte(defaultsYAML), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeKubeconfigFile(t *testing.T, path, serverURL string, certPEM, keyPEM, caPEM []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: Config\nclusters:\n- name: e2e\n  cluster:\n    server: ")
	b.WriteString(serverURL)
	b.WriteString("\n")
	if len(caPEM) > 0 {
		b.WriteString("    certificate-authority-data: ")
		b.WriteString(encodeBase64(caPEM))
		b.WriteString("\n")
	} else {
		b.WriteString("    insecure-skip-tls-verify: true\n")
	}
	b.WriteString("contexts:\n- name: e2e\n  context:\n    cluster: e2e\n    user: admin\ncurrent-context: e2e\nusers:\n- name: admin\n  user:\n")
	if len(certPEM) > 0 && len(keyPEM) > 0 {
		b.WriteString("    client-certificate-data: ")
		b.WriteString(encodeBase64(certPEM))
		b.WriteString("\n    client-key-data: ")
		b.WriteString(encodeBase64(keyPEM))
		b.WriteString("\n")
	} else {
		b.WriteString("    token: e2e-token\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

func encodeBase64(in []byte) string {
	const tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out strings.Builder
	for i := 0; i < len(in); i += 3 {
		b0 := in[i]
		var b1, b2 byte
		rem := len(in) - i
		if rem > 1 {
			b1 = in[i+1]
		}
		if rem > 2 {
			b2 = in[i+2]
		}
		out.WriteByte(tbl[b0>>2])
		out.WriteByte(tbl[((b0&0x03)<<4)|(b1>>4)])
		if rem > 1 {
			out.WriteByte(tbl[((b1&0x0f)<<2)|(b2>>6)])
		} else {
			out.WriteByte('=')
		}
		if rem > 2 {
			out.WriteByte(tbl[b2&0x3f])
		} else {
			out.WriteByte('=')
		}
	}
	return out.String()
}

func newSelfSignedTLSServer(t *testing.T, handler http.Handler) (srv *httptest.Server, certPEM, keyPEM, caPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	caPEM = certPEM

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srv = httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, certPEM, keyPEM, caPEM
}

type recordedK8sReq struct {
	Method   string
	Path     string
	RawQuery string
}

type fakeE2EAPIServer struct {
	srv    *httptest.Server
	codecs serializer.CodecFactory

	mu                sync.Mutex
	nextRV            atomic.Int64
	nodes             map[string]*corev1.Node
	pods              map[string]*corev1.Pod // key ns/name
	endpointSlices    []discoveryv1.EndpointSlice
	endpoints         map[string]*corev1.Endpoints // key ns/name
	pvs               map[string]*corev1.PersistentVolume
	pvcs              map[string]*corev1.PersistentVolumeClaim
	csiNodes          map[string]*storagev1.CSINode
	secrets           map[string]*corev1.Secret
	leases            map[string]*coordinationv1.Lease
	events            []*eventsv1.Event
	requests          []recordedK8sReq
	nodesStatusCode   int
	podsStatusCode    int
	csiNodeStatusCode int
	podLogs           map[string]string
}

func newFakeE2EAPIServer(t *testing.T) *fakeE2EAPIServer {
	t.Helper()
	f := &fakeE2EAPIServer{
		codecs:    serializer.NewCodecFactory(clientgoscheme.Scheme),
		nodes:     map[string]*corev1.Node{},
		pods:      map[string]*corev1.Pod{},
		endpoints: map[string]*corev1.Endpoints{},
		pvs:       map[string]*corev1.PersistentVolume{},
		pvcs:      map[string]*corev1.PersistentVolumeClaim{},
		csiNodes:  map[string]*storagev1.CSINode{},
		secrets:   map[string]*corev1.Secret{},
		leases:    map[string]*coordinationv1.Lease{},
		podLogs:   map[string]string{},
	}
	f.nextRV.Store(100)
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeE2EAPIServer) writeKubeconfig(t *testing.T, path string) {
	t.Helper()
	writeKubeconfigFile(t, path, f.srv.URL, nil, nil, nil)
}

func (f *fakeE2EAPIServer) setNode(n *corev1.Node) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := n.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = fmt.Sprintf("%d", f.nextRV.Add(1))
	}
	f.nodes[cp.Name] = cp
}

func (f *fakeE2EAPIServer) setPod(p *corev1.Pod) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := p.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = fmt.Sprintf("%d", f.nextRV.Add(1))
	}
	f.pods[cp.Namespace+"/"+cp.Name] = cp
}

func (f *fakeE2EAPIServer) setCSINode(c *storagev1.CSINode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.csiNodes[c.Name] = c.DeepCopy()
}

func (f *fakeE2EAPIServer) getNode(name string) (*corev1.Node, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.nodes[name]
	if !ok {
		return nil, false
	}
	return n.DeepCopy(), true
}

func (f *fakeE2EAPIServer) getEvents() []eventsv1.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]eventsv1.Event, 0, len(f.events))
	for _, ev := range f.events {
		out = append(out, *ev.DeepCopy())
	}
	return out
}

func (f *fakeE2EAPIServer) getRequests() []recordedK8sReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

func (f *fakeE2EAPIServer) countRequests(method, pathPrefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if r.Method == method && strings.HasPrefix(r.Path, pathPrefix) {
			n++
		}
	}
	return n
}

func (f *fakeE2EAPIServer) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, recordedK8sReq{
		Method:   r.Method,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	})
	nodesCode := f.nodesStatusCode
	podsCode := f.podsStatusCode
	csiCode := f.csiNodeStatusCode
	f.mu.Unlock()

	p := r.URL.Path

	switch {
	case p == "/api/v1/nodes" && r.Method == http.MethodGet:
		if nodesCode != 0 {
			f.writeStatus(w, r, nodesCode, metav1.StatusReasonInternalError, "injected node list error")
			return
		}
		f.mu.Lock()
		items := make([]corev1.Node, 0, len(f.nodes))
		for _, n := range f.nodes {
			items = append(items, *n.DeepCopy())
		}
		f.mu.Unlock()
		list := &corev1.NodeList{
			ListMeta: metav1.ListMeta{ResourceVersion: fmt.Sprintf("%d", f.nextRV.Load())},
			Items:    items,
		}
		f.writeObject(w, r, http.StatusOK, corev1.SchemeGroupVersion, list)

	case strings.HasPrefix(p, "/api/v1/nodes/") && strings.HasSuffix(p, "/status") && r.Method == http.MethodPatch:
		name := strings.TrimSuffix(strings.TrimPrefix(p, "/api/v1/nodes/"), "/status")
		f.handleNodeStatusPatch(w, r, name)

	case strings.HasPrefix(p, "/api/v1/nodes/") && r.Method == http.MethodGet:
		name := strings.TrimPrefix(p, "/api/v1/nodes/")
		if nodesCode != 0 {
			f.writeStatus(w, r, nodesCode, metav1.StatusReasonInternalError, "injected node get error")
			return
		}
		f.mu.Lock()
		n, ok := f.nodes[name]
		f.mu.Unlock()
		if !ok {
			f.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, "node not found")
			return
		}
		f.writeObject(w, r, http.StatusOK, corev1.SchemeGroupVersion, n.DeepCopy())

	case p == "/api/v1/pods" && r.Method == http.MethodGet:
		if podsCode != 0 {
			f.writeStatus(w, r, podsCode, metav1.StatusReasonInternalError, "injected pod list error")
			return
		}
		nodeFilter := ""
		if fs := r.URL.Query().Get("fieldSelector"); strings.HasPrefix(fs, "spec.nodeName=") {
			nodeFilter = strings.TrimPrefix(fs, "spec.nodeName=")
		}
		f.mu.Lock()
		items := make([]corev1.Pod, 0, len(f.pods))
		for _, pod := range f.pods {
			if nodeFilter != "" && pod.Spec.NodeName != nodeFilter {
				continue
			}
			items = append(items, *pod.DeepCopy())
		}
		f.mu.Unlock()
		list := &corev1.PodList{
			ListMeta: metav1.ListMeta{ResourceVersion: fmt.Sprintf("%d", f.nextRV.Load())},
			Items:    items,
		}
		f.writeObject(w, r, http.StatusOK, corev1.SchemeGroupVersion, list)

	case strings.HasPrefix(p, "/api/v1/namespaces/") && strings.Contains(p, "/pods/"):
		f.handleNamespacedPod(w, r, p)

	case p == "/apis/discovery.k8s.io/v1/endpointslices" && r.Method == http.MethodGet:
		f.mu.Lock()
		items := slices.Clone(f.endpointSlices)
		f.mu.Unlock()
		list := &discoveryv1.EndpointSliceList{
			ListMeta: metav1.ListMeta{ResourceVersion: fmt.Sprintf("%d", f.nextRV.Load())},
			Items:    items,
		}
		f.writeObject(w, r, http.StatusOK, discoveryv1.SchemeGroupVersion, list)

	case strings.HasPrefix(p, "/apis/discovery.k8s.io/v1/namespaces/") && strings.HasSuffix(p, "/endpointslices") && r.Method == http.MethodGet:
		rest := strings.TrimPrefix(p, "/apis/discovery.k8s.io/v1/namespaces/")
		ns := strings.TrimSuffix(rest, "/endpointslices")
		f.mu.Lock()
		var items []discoveryv1.EndpointSlice
		for _, es := range f.endpointSlices {
			if es.Namespace == ns {
				items = append(items, es)
			}
		}
		f.mu.Unlock()
		list := &discoveryv1.EndpointSliceList{
			ListMeta: metav1.ListMeta{ResourceVersion: fmt.Sprintf("%d", f.nextRV.Load())},
			Items:    items,
		}
		f.writeObject(w, r, http.StatusOK, discoveryv1.SchemeGroupVersion, list)

	case strings.HasPrefix(p, "/api/v1/namespaces/") && strings.Contains(p, "/endpoints/") && r.Method == http.MethodGet:
		rest := strings.TrimPrefix(p, "/api/v1/namespaces/")
		ns, name, _ := strings.Cut(rest, "/endpoints/")
		f.mu.Lock()
		ep, ok := f.endpoints[ns+"/"+name]
		f.mu.Unlock()
		if !ok {
			f.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, "endpoints not found")
			return
		}
		f.writeObject(w, r, http.StatusOK, corev1.SchemeGroupVersion, ep.DeepCopy())

	case p == "/api/v1/persistentvolumes" && r.Method == http.MethodGet:
		f.mu.Lock()
		items := make([]corev1.PersistentVolume, 0, len(f.pvs))
		for _, pv := range f.pvs {
			items = append(items, *pv.DeepCopy())
		}
		f.mu.Unlock()
		f.writeObject(w, r, http.StatusOK, corev1.SchemeGroupVersion, &corev1.PersistentVolumeList{
			ListMeta: metav1.ListMeta{ResourceVersion: fmt.Sprintf("%d", f.nextRV.Load())},
			Items:    items,
		})

	case strings.HasPrefix(p, "/api/v1/persistentvolumes/"):
		name := strings.TrimPrefix(p, "/api/v1/persistentvolumes/")
		f.mu.Lock()
		pv, ok := f.pvs[name]
		if !ok {
			f.mu.Unlock()
			f.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, "pv not found")
			return
		}
		if r.Method == http.MethodDelete {
			delete(f.pvs, name)
			f.mu.Unlock()
			f.writeObject(w, r, http.StatusOK, corev1.SchemeGroupVersion, pv.DeepCopy())
			return
		}
		cp := pv.DeepCopy()
		f.mu.Unlock()
		f.writeObject(w, r, http.StatusOK, corev1.SchemeGroupVersion, cp)

	case p == "/api/v1/persistentvolumeclaims" && r.Method == http.MethodGet:
		f.mu.Lock()
		items := make([]corev1.PersistentVolumeClaim, 0, len(f.pvcs))
		for _, pvc := range f.pvcs {
			items = append(items, *pvc.DeepCopy())
		}
		f.mu.Unlock()
		f.writeObject(w, r, http.StatusOK, corev1.SchemeGroupVersion, &corev1.PersistentVolumeClaimList{
			ListMeta: metav1.ListMeta{ResourceVersion: fmt.Sprintf("%d", f.nextRV.Load())},
			Items:    items,
		})

	case strings.HasPrefix(p, "/api/v1/namespaces/") && strings.Contains(p, "/persistentvolumeclaims/") && r.Method == http.MethodGet:
		rest := strings.TrimPrefix(p, "/api/v1/namespaces/")
		ns, name, _ := strings.Cut(rest, "/persistentvolumeclaims/")
		f.mu.Lock()
		pvc, ok := f.pvcs[ns+"/"+name]
		f.mu.Unlock()
		if !ok {
			f.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, "pvc not found")
			return
		}
		f.writeObject(w, r, http.StatusOK, corev1.SchemeGroupVersion, pvc.DeepCopy())

	case strings.HasPrefix(p, "/apis/storage.k8s.io/v1/csinodes/") && r.Method == http.MethodGet:
		name := strings.TrimPrefix(p, "/apis/storage.k8s.io/v1/csinodes/")
		if csiCode == http.StatusForbidden {
			f.writeStatus(w, r, http.StatusForbidden, metav1.StatusReasonForbidden, "csinodes forbidden")
			return
		}
		if csiCode != 0 {
			f.writeStatus(w, r, csiCode, metav1.StatusReasonInternalError, "csinodes err")
			return
		}
		f.mu.Lock()
		cn, ok := f.csiNodes[name]
		f.mu.Unlock()
		if !ok {
			f.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, "csinode not found")
			return
		}
		f.writeObject(w, r, http.StatusOK, storagev1.SchemeGroupVersion, cn.DeepCopy())

	case strings.HasPrefix(p, "/api/v1/namespaces/") && strings.Contains(p, "/secrets/") && r.Method == http.MethodGet:
		rest := strings.TrimPrefix(p, "/api/v1/namespaces/")
		ns, name, _ := strings.Cut(rest, "/secrets/")
		f.mu.Lock()
		sec, ok := f.secrets[ns+"/"+name]
		f.mu.Unlock()
		if !ok {
			f.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, "secret not found")
			return
		}
		f.writeObject(w, r, http.StatusOK, corev1.SchemeGroupVersion, sec.DeepCopy())

	case strings.HasPrefix(p, "/apis/coordination.k8s.io/v1/namespaces/") && strings.Contains(p, "/leases"):
		f.handleLease(w, r, p)

	case strings.HasPrefix(p, "/apis/events.k8s.io/v1/namespaces/") && strings.Contains(p, "/events"):
		f.handleEvent(w, r, p)

	default:
		f.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, "unhandled route: "+r.Method+" "+p)
	}
}

func (f *fakeE2EAPIServer) handleNodeStatusPatch(w http.ResponseWriter, r *http.Request, name string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		f.writeStatus(w, r, http.StatusBadRequest, metav1.StatusReasonBadRequest, err.Error())
		return
	}
	var patch struct {
		Status struct {
			Conditions []corev1.NodeCondition `json:"conditions"`
		} `json:"status"`
	}
	if err := json.Unmarshal(body, &patch); err != nil {
		f.writeStatus(w, r, http.StatusBadRequest, metav1.StatusReasonBadRequest, err.Error())
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.nodes[name]
	if !ok {
		f.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, "node not found")
		return
	}
	byType := map[corev1.NodeConditionType]corev1.NodeCondition{}
	for _, c := range n.Status.Conditions {
		byType[c.Type] = c
	}
	for _, c := range patch.Status.Conditions {
		byType[c.Type] = c
	}
	merged := make([]corev1.NodeCondition, 0, len(byType))
	for _, c := range byType {
		merged = append(merged, c)
	}
	n.Status.Conditions = merged
	n.ResourceVersion = fmt.Sprintf("%d", f.nextRV.Add(1))
	f.writeObject(w, r, http.StatusOK, corev1.SchemeGroupVersion, n.DeepCopy())
}

func (f *fakeE2EAPIServer) handleNamespacedPod(w http.ResponseWriter, r *http.Request, p string) {
	rest := strings.TrimPrefix(p, "/api/v1/namespaces/")
	ns, tail, ok := strings.Cut(rest, "/pods/")
	if !ok {
		f.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, "bad pod path")
		return
	}
	if strings.HasSuffix(tail, "/log") && r.Method == http.MethodGet {
		name := strings.TrimSuffix(tail, "/log")
		f.mu.Lock()
		logs := f.podLogs[ns+"/"+name]
		f.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, logs)
		return
	}
	key := ns + "/" + tail
	f.mu.Lock()
	pod, exists := f.pods[key]
	if !exists {
		f.mu.Unlock()
		f.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, "pod not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		cp := pod.DeepCopy()
		f.mu.Unlock()
		f.writeObject(w, r, http.StatusOK, corev1.SchemeGroupVersion, cp)
	case http.MethodDelete:
		delete(f.pods, key)
		cp := pod.DeepCopy()
		f.mu.Unlock()
		f.writeObject(w, r, http.StatusOK, corev1.SchemeGroupVersion, cp)
	case http.MethodPatch:
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var mp struct {
			Metadata struct {
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(body, &mp); err == nil && len(mp.Metadata.Annotations) > 0 {
			if pod.Annotations == nil {
				pod.Annotations = map[string]string{}
			}
			for k, v := range mp.Metadata.Annotations {
				pod.Annotations[k] = v
			}
		}
		pod.ResourceVersion = fmt.Sprintf("%d", f.nextRV.Add(1))
		cp := pod.DeepCopy()
		f.mu.Unlock()
		f.writeObject(w, r, http.StatusOK, corev1.SchemeGroupVersion, cp)
	default:
		f.mu.Unlock()
		f.writeStatus(w, r, http.StatusMethodNotAllowed, metav1.StatusReasonMethodNotAllowed, "method not allowed")
	}
}

func (f *fakeE2EAPIServer) handleLease(w http.ResponseWriter, r *http.Request, p string) {
	rest := strings.TrimPrefix(p, "/apis/coordination.k8s.io/v1/namespaces/")
	ns, tail, _ := strings.Cut(rest, "/leases")
	name := strings.TrimPrefix(tail, "/")
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method == http.MethodGet && name != "" {
		l, ok := f.leases[ns+"/"+name]
		if !ok {
			f.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, "lease not found")
			return
		}
		f.writeObject(w, r, http.StatusOK, coordinationv1.SchemeGroupVersion, l.DeepCopy())
		return
	}
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		var l coordinationv1.Lease
		if err := f.decodeRequest(r, &l); err != nil {
			f.writeStatus(w, r, http.StatusBadRequest, metav1.StatusReasonBadRequest, err.Error())
			return
		}
		l.Namespace = ns
		if l.Name == "" {
			l.Name = name
		}
		l.ResourceVersion = fmt.Sprintf("%d", f.nextRV.Add(1))
		f.leases[ns+"/"+l.Name] = l.DeepCopy()
		code := http.StatusOK
		if r.Method == http.MethodPost {
			code = http.StatusCreated
		}
		f.writeObject(w, r, code, coordinationv1.SchemeGroupVersion, &l)
		return
	}
	f.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, "lease not found")
}

func (f *fakeE2EAPIServer) handleEvent(w http.ResponseWriter, r *http.Request, p string) {
	rest := strings.TrimPrefix(p, "/apis/events.k8s.io/v1/namespaces/")
	ns, tail, _ := strings.Cut(rest, "/events")
	name := strings.TrimPrefix(tail, "/")
	if r.Method == http.MethodPost {
		var ev eventsv1.Event
		if err := f.decodeRequest(r, &ev); err != nil {
			f.writeStatus(w, r, http.StatusBadRequest, metav1.StatusReasonBadRequest, err.Error())
			return
		}
		if ev.Namespace == "" {
			ev.Namespace = ns
		}
		ev.ResourceVersion = fmt.Sprintf("%d", f.nextRV.Add(1))
		f.mu.Lock()
		f.events = append(f.events, ev.DeepCopy())
		f.mu.Unlock()
		f.writeObject(w, r, http.StatusCreated, eventsv1.SchemeGroupVersion, &ev)
		return
	}
	if r.Method == http.MethodPatch && name != "" {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, ev := range f.events {
			if ev.Namespace == ns && ev.Name == name {
				f.writeObject(w, r, http.StatusOK, eventsv1.SchemeGroupVersion, ev.DeepCopy())
				return
			}
		}
		f.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, "event not found")
		return
	}
	f.writeStatus(w, r, http.StatusMethodNotAllowed, metav1.StatusReasonMethodNotAllowed, "method not allowed")
}

func (f *fakeE2EAPIServer) decodeRequest(r *http.Request, into runtime.Object) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		return err
	}
	ct := r.Header.Get("Content-Type")
	if idx := strings.IndexByte(ct, ';'); idx >= 0 {
		ct = strings.TrimSpace(ct[:idx])
	}
	if ct != "" {
		if info, ok := runtime.SerializerInfoForMediaType(f.codecs.SupportedMediaTypes(), ct); ok {
			if _, _, err := info.Serializer.Decode(body, nil, into); err == nil {
				return nil
			}
		}
	}
	_, _, err = f.codecs.UniversalDeserializer().Decode(body, nil, into)
	return err
}

func (f *fakeE2EAPIServer) writeStatus(w http.ResponseWriter, r *http.Request, code int, reason metav1.StatusReason, msg string) {
	status := &metav1.Status{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
		Status:   metav1.StatusFailure,
		Reason:   reason,
		Message:  msg,
		Code:     int32(code),
	}
	f.writeObject(w, r, code, corev1.SchemeGroupVersion, status)
}

func (f *fakeE2EAPIServer) writeObject(w http.ResponseWriter, r *http.Request, code int, gv schema.GroupVersion, obj runtime.Object) {
	accept := r.Header.Get("Accept")
	supported := f.codecs.SupportedMediaTypes()

	if strings.Contains(accept, "application/vnd.kubernetes.protobuf") {
		if info, ok := runtime.SerializerInfoForMediaType(supported, "application/vnd.kubernetes.protobuf"); ok {
			enc := f.codecs.EncoderForVersion(info.Serializer, gv)
			var buf bytes.Buffer
			if err := enc.Encode(obj, &buf); err == nil {
				w.Header().Set("Content-Type", "application/vnd.kubernetes.protobuf")
				w.WriteHeader(code)
				_, _ = w.Write(buf.Bytes())
				return
			}
		}
	}

	info, ok := runtime.SerializerInfoForMediaType(supported, runtime.ContentTypeJSON)
	if !ok {
		http.Error(w, "json serializer unavailable", http.StatusInternalServerError)
		return
	}
	enc := f.codecs.EncoderForVersion(info.Serializer, gv)
	var buf bytes.Buffer
	if err := enc.Encode(obj, &buf); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", runtime.ContentTypeJSON)
	w.WriteHeader(code)
	_, _ = w.Write(buf.Bytes())
}

func makeNode(name, podCIDR string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: map[string]string{},
		},
		Spec: corev1.NodeSpec{
			PodCIDR:  podCIDR,
			PodCIDRs: []string{podCIDR},
		},
	}
}

func makePod(ns, name, uid, nodeName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   ns,
			Name:        name,
			UID:         types.UID(uid),
			Annotations: map[string]string{},
		},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
		},
	}
}

func writeProcTask(t *testing.T, procRoot string, pid int, comm, state string, uid int, cgroup string, cmdline []string, age time.Duration) {
	t.Helper()
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(filepath.Join(dir, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	statLine := fmt.Sprintf("%d (%s) %s 1 %d %d 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n",
		pid, comm, state, pid, pid)
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(statLine), 0o644); err != nil {
		t.Fatal(err)
	}
	status := fmt.Sprintf("Name:\t%s\nState:\t%s\nUid:\t%d\t%d\t%d\t%d\nGid:\t%d\t%d\t%d\t%d\n",
		comm, state, uid, uid, uid, uid, uid, uid, uid, uid)
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(cgroup), 0o644); err != nil {
		t.Fatal(err)
	}
	if len(cmdline) > 0 {
		var buf bytes.Buffer
		for _, a := range cmdline {
			buf.WriteString(a)
			buf.WriteByte(0)
		}
		if err := os.WriteFile(filepath.Join(dir, "cmdline"), buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if age > 0 {
		past := time.Now().Add(-age)
		if err := os.Chtimes(dir, past, past); err != nil {
			t.Fatal(err)
		}
	}
}

func shortTempBase() string {
	if len(os.TempDir()) >= 75 {
		return "/tmp"
	}
	return ""
}

func (sb *reqSandbox) ensureShortHostRoot(t *testing.T) {
	t.Helper()
	if len(filepath.Join(sb.hostroot, "run", "k0s", "kms.sock")) < 95 {
		return
	}
	shortDir, err := os.MkdirTemp(shortTempBase(), "hr-")
	if err != nil {
		t.Fatalf("mkdtemp short hostroot dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shortDir) })

	oldHost := sb.hostroot
	newHost := filepath.Join(shortDir, "h")
	newKubeletPods := filepath.Join(newHost, "var", "lib", "k0s", "kubelet", "pods")
	newPluginsReg := filepath.Join(newHost, "var", "lib", "k0s", "kubelet", "plugins_registry")
	newCtrTaskRoot := filepath.Join(newHost, "run", "k0s", "containerd", "io.containerd.runtime.v2.task", "k8s.io")
	newSandboxCtlRoot := filepath.Join(newHost, "run", "k0s", "containerd", "io.containerd.sandbox.controller.v1.shim")

	for _, d := range []string{
		newHost,
		filepath.Join(newHost, "etc", "systemd", "system"),
		filepath.Join(newHost, "etc", "kine"),
		filepath.Join(newHost, "etc", "k0s"),
		filepath.Join(newHost, "var", "lib", "k0s", "bin"),
		filepath.Join(newHost, "var", "lib", "k0s", "pki", "etcd"),
		filepath.Join(newHost, "var", "backups", "etcd"),
		filepath.Join(newHost, "var", "backups", "kine"),
		filepath.Join(newHost, "var", "lib", "kine-compact-guard"),
		filepath.Join(newHost, "opt", "apps", "postgres"),
		filepath.Join(newHost, "run", "k0s"),
		filepath.Join(newHost, "usr", "local", "bin"),
		newKubeletPods,
		newPluginsReg,
		newCtrTaskRoot,
		newSandboxCtlRoot,
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	sb.hostroot = newHost
	sb.kubeletPods = newKubeletPods
	sb.pluginsReg = newPluginsReg
	sb.ctrTaskRoot = newCtrTaskRoot
	sb.sandboxCtlRoot = newSandboxCtlRoot
	for k, v := range sb.envMap {
		if v == oldHost {
			sb.envMap[k] = newHost
		} else if strings.HasPrefix(v, oldHost+string(filepath.Separator)) {
			sb.envMap[k] = newHost + strings.TrimPrefix(v, oldHost)
		}
	}
}

func writeLiveCtrTaskDir(t *testing.T, ctrTaskRoot, sid string, initPID int) {
	t.Helper()
	taskDir := filepath.Join(ctrTaskRoot, sid)
	if err := os.MkdirAll(taskDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(taskDir, "init.pid"), []byte(strconv.Itoa(initPID)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(taskDir, "log.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(taskDir, "config.json"), []byte(`{"annotations":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

// listenShortUnixSocket binds a Unix domain socket at targetSockPath. If
// targetSockPath approaches Linux's 108-byte sun_path limit (>= 95 bytes),
// it listens on a short temp socket (falling back to /tmp when $TMPDIR >= 75
// chars), symlinks targetSockPath to it, and returns (ln, actualShortPath).
func listenShortUnixSocket(t *testing.T, targetSockPath string) (net.Listener, string) {
	t.Helper()
	_ = os.Remove(targetSockPath)
	listenPath := targetSockPath
	if len(targetSockPath) >= 95 {
		shortDir, err := os.MkdirTemp(shortTempBase(), "ks-")
		if err != nil {
			t.Fatalf("mkdtemp short unix socket dir: %v", err)
		}
		listenPath = filepath.Join(shortDir, "k.sock")
		t.Cleanup(func() { _ = os.RemoveAll(shortDir) })
	}
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", listenPath)
	if err != nil {
		t.Fatalf("listen unix %s: %v", listenPath, err)
	}
	if listenPath != targetSockPath {
		if err := os.Symlink(listenPath, targetSockPath); err != nil {
			_ = ln.Close()
			t.Fatalf("symlink unix socket %s -> %s: %v", targetSockPath, listenPath, err)
		}
		t.Cleanup(func() { _ = os.Remove(targetSockPath) })
	}
	return ln, listenPath
}

func startMockHAProxyUnixSocket(t *testing.T, sockPath, backendName, serverName, backendAddr string) string {
	t.Helper()
	ln, actualPath := listenShortUnixSocket(t, sockPath)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 512)
				n, _ := c.Read(buf)
				cmd := strings.TrimSpace(string(buf[:n]))
				if strings.HasPrefix(cmd, "show stat") {
					_, _ = fmt.Fprintf(c, "# pxname,svname,status,addr\n%s,%s,UP,%s\n", backendName, serverName, backendAddr)
				} else {
					_, _ = fmt.Fprintln(c, "")
				}
			}(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})
	return actualPath
}

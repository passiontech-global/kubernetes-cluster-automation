// e2e_blackbox_test.go — opaque-box E2E tests for the compiled node-host-agent binary.
package main_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const e2eVersion = "v0.0.0-e2e"

type agentStartLog struct {
	Msg               string   `json:"msg"`
	Version           string   `json:"version"`
	Node              string   `json:"node"`
	Pod               string   `json:"pod"`
	Standalone        bool     `json:"standalone"`
	MetricsAddr       string   `json:"metricsAddr"`
	ProbeAddr         string   `json:"probeAddr"`
	PprofLoopbackAddr string   `json:"pprofLoopbackAddr"`
	Subsystems        []string `json:"subsystems"`
	Off               []string `json:"off"`
	Skipped           []string `json:"skipped"`
}

type listeningLog struct {
	Msg    string `json:"msg"`
	Server string `json:"server"`
	Addr   string `json:"addr"`
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// sandboxEnv builds a hermetic process environment rooted in t.TempDir() so
// neither standalone nor pod mode can touch systemd sockets, D-Bus, host
// configs, or live Kubernetes clusters. Because --standalone forces HostRoot="/"
// in main.go, host-mutating and systemd/D-Bus-probing subsystems (janitor,
// nethealth, controllerhygiene, kinedb, hostconfig) are explicitly disabled,
// systemd/D-Bus/kube env vars are scrubbed, and NODE_HOST_AGENT_LATCH_INTERVAL
// is set to 24h to keep hostmetrics's 30s kernelfail/sysctl tick from firing
// during short E2E runs; hostmetrics still reads read-only kernel
// procfs/sysfs/mounts for /metrics and hostmetrics-textfile exposition.
func sandboxEnv(t *testing.T, overrides map[string]string) []string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{
		"hostroot", "etc", "state", "journal", "textfile", "openebs",
		"run", "keys", "vars", "proc", "proc/1", "proc/net", "proc/net/stat",
		"proc/pressure", "sys/clocksource0", "sys/class/net", "sys/fs/cgroup",
		"etc/nebula", "etc/k0s", "etc/systemd/system", "k0s", "dev/shm", "wd-scripts",
	} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}

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

	defaults := map[string]string{
		"NODE_HOST_AGENT_HOST_ROOT":                  filepath.Join(root, "hostroot"),
		"NODE_HOST_AGENT_WATCHDOG_CONF":              filepath.Join(root, "etc", "node-watchdog.conf"),
		"NODE_HOST_AGENT_WATCHDOG_STATE_DIR":         filepath.Join(root, "state"),
		"NODE_HOST_AGENT_WATCHDOG_LOG":               filepath.Join(root, "watchdog.log"),
		"NODE_HOST_AGENT_WATCHDOG_LOG_FILE":          filepath.Join(root, "watchdog.log"),
		"NODE_HOST_AGENT_JOURNAL_DIRS":               filepath.Join(root, "journal"),
		"NODE_HOST_AGENT_TEXTFILE_DIR":               filepath.Join(root, "textfile"),
		"NODE_HOST_AGENT_SWEEP_BASE_DIR":             filepath.Join(root, "openebs"),
		"NODE_HOST_AGENT_API_GUARD_CONF":             filepath.Join(root, "etc", "api-backend-guard.conf"),
		"NODE_HOST_AGENT_APIPROBER_SOCKET":           filepath.Join(root, "run", "api-lb.sock"),
		"NODE_HOST_AGENT_CONVERGE_SSH_KEY":           filepath.Join(root, "keys", "converge"),
		"NODE_HOST_AGENT_HOSTCONFIG_VARS_DIR":        filepath.Join(root, "vars"),
		"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":          "false",
		"NODE_HOST_AGENT_ENABLE_JANITOR":             "false",
		"NODE_HOST_AGENT_ENABLE_NETHEALTH":           "false",
		"NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE":   "false",
		"NODE_HOST_AGENT_ENABLE_KINEDB":              "false",
		"NODE_HOST_AGENT_LATCH_INTERVAL":             "24h",
		"NODE_HOST_AGENT_PROC_ROOT":                  filepath.Join(root, "proc"),
		"NODE_HOST_AGENT_HOST_RESOLV_CONF":           filepath.Join(root, "etc", "resolv.conf"),
		"NODE_HOST_AGENT_HOSTS_FILE":                 filepath.Join(root, "etc", "hosts"),
		"NODE_HOST_AGENT_K0S_UNIT":                   filepath.Join(root, "etc", "systemd", "system", "k0scontroller.service"),
		"NODE_HOST_AGENT_K0S_CONFIG":                 filepath.Join(root, "etc", "k0s", "k0s.yaml"),
		"NODE_HOST_AGENT_CLOCKSOURCE_CURRENT_FILE":   filepath.Join(root, "sys", "clocksource0", "current_clocksource"),
		"NODE_HOST_AGENT_CLOCKSOURCE_AVAILABLE_FILE": filepath.Join(root, "sys", "clocksource0", "available_clocksource"),
		"NODE_HOST_AGENT_FILESYSTEM_TARGETS":         root,
		"NODE_HOST_AGENT_SYS_CLASS_NET":              filepath.Join(root, "sys", "class", "net"),
		"NODE_HOST_AGENT_NEBULA_CERT":                filepath.Join(root, "etc", "nebula", "host.crt"),
		"NODE_HOST_AGENT_NEBULA_CERTS_DIR":           filepath.Join(root, "etc", "nebula"),
		"NODE_HOST_AGENT_HOST_ROUTE_FILE":            filepath.Join(root, "proc", "net", "route"),
		"NODE_HOST_AGENT_PSI_FILE":                   filepath.Join(root, "proc", "pressure", "cpu"),
		"NODE_HOST_AGENT_KEY_USERS_FILE":             filepath.Join(root, "proc", "key-users"),
		"NODE_HOST_AGENT_CONNTRACK_STAT_FILE":        filepath.Join(root, "proc", "net", "stat", "nf_conntrack"),
		"NODE_HOST_AGENT_ARP_TABLE_FILE":             filepath.Join(root, "proc", "net", "arp"),
		"NODE_HOST_AGENT_PROC_NET_UDP":               filepath.Join(root, "proc", "net", "udp"),
		"NODE_HOST_AGENT_PROC_NET_UDP6":              filepath.Join(root, "proc", "net", "udp6"),
		"NODE_HOST_AGENT_UPTIME_FILE":                filepath.Join(root, "proc", "uptime"),
		"NODE_HOST_AGENT_K0S_DIR":                    filepath.Join(root, "k0s"),
		"NODE_HOST_AGENT_HOST_RUN_DIR":               filepath.Join(root, "run"),
		"NODE_HOST_AGENT_DEV_SHM_DIR":                filepath.Join(root, "dev", "shm"),
		"NODE_HOST_AGENT_MOUNTINFO_FILE":             filepath.Join(root, "proc", "1", "mountinfo"),
		"NODE_HOST_AGENT_CGROUP_ROOT":                filepath.Join(root, "sys", "fs", "cgroup"),
		"NODE_HOST_AGENT_LOCALPV_QUOTA_DIR":          filepath.Join(root, "openebs"),
		"NODE_HOST_AGENT_WATCHDOG_SCRIPTS_DIR":       filepath.Join(root, "wd-scripts"),
	}
	for k, v := range overrides {
		defaults[k] = v
	}
	for k, v := range defaults {
		env = append(env, k+"="+v)
	}
	return env
}

func runCLI(t *testing.T, bin string, env []string, args ...string) (string, string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.String(), stderr.String(), 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return stdout.String(), stderr.String(), exitErr.ExitCode()
	}
	t.Fatalf("exec %s %v failed unexpectedly: %v\nstdout: %s\nstderr: %s",
		bin, args, err, stdout.String(), stderr.String())
	return "", "", -1
}

type runningAgent struct {
	cmd      *exec.Cmd
	start    agentStartLog
	addrs    map[string]string
	stdout   *syncBuffer
	stderr   *syncBuffer
	waitDone chan struct{}
	waitErr  error
}

func startAgent(t *testing.T, bin string, env []string, expectServers []string, args ...string) *runningAgent {
	t.Helper()
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
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
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

	ra := &runningAgent{
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
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill()
				<-waitDone
			}
		}
	})

	deadline := time.NewTimer(20 * time.Second)
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

	// Drain any unexpected extra listening log briefly (e.g. verifying pprof disabled).
	drain := time.NewTimer(25 * time.Millisecond)
	defer drain.Stop()
	for {
		select {
		case ll := <-listenCh:
			ra.addrs[ll.Server] = ll.Addr
		case <-drain.C:
			for _, want := range expectServers {
				if ra.addrs[want] == "" {
					t.Fatalf("missing expected listener %q in %v\nstdout:\n%s",
						want, ra.addrs, stdoutBuf.String())
				}
			}
			return ra
		}
	}
}

func (ra *runningAgent) stopAndWait(t *testing.T) {
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
	case <-time.After(15 * time.Second):
		_ = ra.cmd.Process.Kill()
		<-ra.waitDone
		t.Fatal("timed out waiting for clean exit after SIGTERM")
	}
}

func httpGet(t *testing.T, url string) (int, string) {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request %s: %v", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body %s: %v", url, err)
	}
	return resp.StatusCode, string(body)
}

func parseGaugeMetric(body, metricName string) (float64, bool) {
	prefix := metricName + " "
	for line := range strings.SplitSeq(body, "\n") {
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, prefix) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		v, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return 0, false
		}
		return v, true
	}
	return 0, false
}

func TestE2EAgent(t *testing.T) {
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "node-host-agent")
	buildCmd := exec.CommandContext(t.Context(), "go", "build",
		"-ldflags=-X main.version="+e2eVersion,
		"-o", binPath, ".")
	buildCmd.Env = os.Environ()
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("compile agent binary: %v\n%s", err, out)
	}

	t.Run("CLI/Version", func(t *testing.T) {
		env := sandboxEnv(t, nil)
		for _, args := range [][]string{{"--version"}, {"-version"}, {"version"}} {
			stdout, stderr, code := runCLI(t, binPath, env, args...)
			if code != 0 {
				t.Fatalf("args %v exit=%d want 0; stderr:\n%s", args, code, stderr)
			}
			if got := strings.TrimSpace(stdout); got != e2eVersion {
				t.Fatalf("args %v stdout=%q want %q", args, got, e2eVersion)
			}
		}
	})

	t.Run("CLI/Help", func(t *testing.T) {
		env := sandboxEnv(t, nil)
		_, stderr, code := runCLI(t, binPath, env, "-h")
		if code != 0 {
			t.Fatalf("-h exit=%d want 0; stderr:\n%s", code, stderr)
		}
		for _, want := range []string{
			"-pprof-bind-address",
			`default "127.0.0.1:9116"`,
			"-metrics-bind-address",
			"-health-probe-bind-address",
			"-standalone",
			"-node-name",
		} {
			if !strings.Contains(stderr, want) {
				t.Fatalf("-h stderr missing %q:\n%s", want, stderr)
			}
		}
	})

	t.Run("CLI/UnknownSubcommand", func(t *testing.T) {
		env := sandboxEnv(t, nil)
		_, stderr, code := runCLI(t, binPath, env, "no-such-subcommand")
		if code != 2 {
			t.Fatalf("unknown subcommand exit=%d want 2; stderr:\n%s", code, stderr)
		}
		for _, want := range []string{
			`unknown subcommand "no-such-subcommand"`,
			"usage:",
			"version",
			"concourse-worker-init",
			"concourse-runc-wrapper",
			"converge-once",
			"nebula-sign",
			"purge-events",
			"check-kine-db",
			"check-k0s-drift",
			"rescue-etcd",
		} {
			if !strings.Contains(stderr, want) {
				t.Fatalf("unknown subcommand stderr missing %q:\n%s", want, stderr)
			}
		}
	})

	t.Run("CLI/CheckK0sDrift", func(t *testing.T) {
		env := sandboxEnv(t, nil)
		dir := t.TempDir()
		absentUnit := filepath.Join(dir, "missing-k0scontroller.service")

		stdout, stderr, code := runCLI(t, binPath, env,
			"check-k0s-drift", "--unit-file="+absentUnit)
		if code != 0 {
			t.Fatalf("absent unit exit=%d want 0; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
		}
		if !strings.Contains(stdout, "not a k0s controller, skip") {
			t.Fatalf("absent unit stdout=%q want skip notice", stdout)
		}

		unitFile := filepath.Join(dir, "k0scontroller.service")
		if err := os.WriteFile(unitFile, []byte("[Unit]\nDescription=k0s\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		cleanConfig := filepath.Join(dir, "k0s-clean.yaml")
		cleanYAML := `apiVersion: k0s.k0sproject.io/v1beta1
kind: ClusterConfig
spec:
  controllerManager:
    extraArgs:
      concurrent-deployment-syncs: "10"
      concurrent-gc-syncs: "20"
      concurrent-replicaset-syncs: "10"
      kube-api-burst: "200"
      kube-api-qps: "100"
      leader-elect-lease-duration: "30s"
      leader-elect-renew-deadline: "20s"
      leader-elect-retry-period: "5s"
      node-monitor-grace-period: "40s"
      node-monitor-period: "5s"
      terminated-pod-gc-threshold: "100"
`
		if err := os.WriteFile(cleanConfig, []byte(cleanYAML), 0o644); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, code = runCLI(t, binPath, env,
			"check-k0s-drift", "--unit-file="+unitFile, "--config="+cleanConfig)
		if code != 0 {
			t.Fatalf("clean k0s.yaml exit=%d want 0; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
		}
		if !strings.Contains(stdout, "OK (no drift)") {
			t.Fatalf("clean k0s.yaml stdout=%q want OK (no drift)", stdout)
		}

		driftedConfig := filepath.Join(dir, "k0s-drifted.yaml")
		driftedYAML := `apiVersion: k0s.k0sproject.io/v1beta1
kind: ClusterConfig
spec:
  controllerManager:
    extraArgs:
      concurrent-service-syncs: "20"
      bogus-extra-flag: "true"
      kube-api-burst: "200"
`
		if err := os.WriteFile(driftedConfig, []byte(driftedYAML), 0o644); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, code = runCLI(t, binPath, env,
			"check-k0s-drift", "--unit-file="+unitFile, "--config="+driftedConfig)
		if code != 1 {
			t.Fatalf("drifted k0s.yaml exit=%d want 1; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
		}
		for _, want := range []string{
			"REMOVED-FLAG",
			"concurrent-service-syncs",
			"key present on node but not in expected set: bogus-extra-flag",
			"key in expected set but missing on node:",
		} {
			if !strings.Contains(stdout, want) {
				t.Fatalf("drifted stdout missing %q:\n%s", want, stdout)
			}
		}

		_, _, helpCode := runCLI(t, binPath, env, "check-k0s-drift", "-h")
		if helpCode != 0 {
			t.Fatalf("check-k0s-drift -h exit=%d want 0", helpCode)
		}
		_, _, bogusCode := runCLI(t, binPath, env, "check-k0s-drift", "--bogus")
		if bogusCode != 2 {
			t.Fatalf("check-k0s-drift --bogus exit=%d want 2", bogusCode)
		}
	})

	t.Run("CLI/ConcourseWorkerInitAndRuncArgv0", func(t *testing.T) {
		env := sandboxEnv(t, nil)

		// Help and usage flag validation for concourse-worker-init.
		_, helpStderr, code := runCLI(t, binPath, env, "concourse-worker-init", "-h")
		if code != 0 {
			t.Fatalf("concourse-worker-init -h exit=%d want 0; stderr:\n%s", code, helpStderr)
		}
		for _, flagName := range []string{"-work-dir", "-runc-dir", "-runc-source", "-wrapper-source"} {
			if !strings.Contains(helpStderr, flagName) {
				t.Fatalf("concourse-worker-init -h missing %q:\n%s", flagName, helpStderr)
			}
		}
		_, _, bogusCode := runCLI(t, binPath, env, "concourse-worker-init", "--bogus")
		if bogusCode != 2 {
			t.Fatalf("concourse-worker-init --bogus exit=%d want 2", bogusCode)
		}

		// Selective wipe + shared-cache scaffold inside t.TempDir().
		initDir := t.TempDir()
		workDir := filepath.Join(initDir, "work")
		runcDir := filepath.Join(initDir, "runc")
		runcSrc := filepath.Join(initDir, "runc-real")
		for _, d := range []string{
			filepath.Join(workDir, "volumes"),
			filepath.Join(workDir, "shared-cache", "go-mod"),
			filepath.Join(workDir, "shared-cache", "stale-cache"),
			runcDir,
		} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(workDir, "volumes", "ephemeral"), []byte("drop"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(workDir, "shared-cache", "go-mod", "keep.txt"), []byte("keep"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(workDir, "shared-cache", "stale-cache", "old.txt"), []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(runcSrc, []byte("fake-runc"), 0o755); err != nil {
			t.Fatal(err)
		}

		// Unprivileged runs fail at chown(4294967294:4294967294) after wiping & scaffolding;
		// privileged runs still exit 1 on missing --wrapper-source.
		_, initStderr, initCode := runCLI(t, binPath, env,
			"concourse-worker-init",
			"--work-dir="+workDir,
			"--runc-dir="+runcDir,
			"--runc-source="+runcSrc,
			"--wrapper-source="+filepath.Join(initDir, "missing-wrapper"),
		)
		if initCode != 1 {
			t.Fatalf("concourse-worker-init exit=%d want 1; stderr:\n%s", initCode, initStderr)
		}
		if _, err := os.Stat(filepath.Join(workDir, "volumes")); !os.IsNotExist(err) {
			t.Fatalf("top-level volumes dir should have been wiped (err=%v)", err)
		}
		if _, err := os.Stat(filepath.Join(workDir, "shared-cache", "stale-cache")); !os.IsNotExist(err) {
			t.Fatalf("non-persistent shared-cache/stale-cache should have been wiped (err=%v)", err)
		}
		if data, err := os.ReadFile(filepath.Join(workDir, "shared-cache", "go-mod", "keep.txt")); err != nil || string(data) != "keep" {
			t.Fatalf("persistent go-mod cache lost: data=%q err=%v", data, err)
		}
		if _, err := os.Stat(filepath.Join(workDir, "shared-cache", "go-build")); err != nil {
			t.Fatalf("scaffold dir go-build missing after init: %v", err)
		}

		// argv[0]=runc via symlink and copy inside t.TempDir().
		if _, err := os.Stat("/concourse-runc/runc.real"); err == nil {
			t.Skip("/concourse-runc/runc.real exists on host; skipping exec-fail runc argv[0] subcheck")
		}

		runcExecDir := t.TempDir()
		runcSymlink := filepath.Join(runcExecDir, "runc")
		if err := os.Symlink(binPath, runcSymlink); err != nil {
			t.Fatal(err)
		}

		bundleDir := filepath.Join(runcExecDir, "bundle-unpriv")
		if err := os.MkdirAll(bundleDir, 0o755); err != nil {
			t.Fatal(err)
		}
		origSpec := `{
  "ociVersion": "1.0.2",
  "linux": {
    "uidMappings": [{"containerID": 0, "hostID": 4294967294, "size": 65536}]
  },
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/scratch", "type": "bind", "source": "/tmp/scratch", "options": ["rbind", "rw"]}
  ]
}`
		configPath := filepath.Join(bundleDir, "config.json")
		if err := os.WriteFile(configPath, []byte(origSpec), 0o644); err != nil {
			t.Fatal(err)
		}

		_, runcStderr, runcCode := runCLI(t, runcSymlink, env,
			"create", "--bundle", bundleDir, "task-1")
		if runcCode != 1 {
			t.Fatalf("argv[0]=runc symlink exit=%d want 1; stderr:\n%s", runcCode, runcStderr)
		}
		if !strings.Contains(runcStderr, "concourse-runc-wrapper: exec /concourse-runc/runc.real:") {
			t.Fatalf("argv[0]=runc stderr missing wrapper exec message:\n%s", runcStderr)
		}

		rewritten, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatal(err)
		}
		var parsed struct {
			Mounts []struct {
				Destination string   `json:"destination"`
				Type        string   `json:"type"`
				Source      string   `json:"source"`
				Options     []string `json:"options"`
			} `json:"mounts"`
		}
		if err := json.Unmarshal(rewritten, &parsed); err != nil {
			t.Fatalf("parse rewritten config.json: %v\n%s", err, rewritten)
		}
		if len(parsed.Mounts) != 3 {
			t.Fatalf("mounts count=%d want 3: %+v", len(parsed.Mounts), parsed.Mounts)
		}
		if parsed.Mounts[1].Destination != "/shared-cache" ||
			parsed.Mounts[1].Source != "/concourse-work-dir/shared-cache" ||
			parsed.Mounts[2].Destination != "/scratch" {
			t.Fatalf("unexpected mounts order/content after injection: %+v", parsed.Mounts)
		}

		// Copy invocation with privileged uidMappings (hostID 0) must not inject /shared-cache.
		copyDir := filepath.Join(runcExecDir, "copybin")
		if err := os.MkdirAll(copyDir, 0o755); err != nil {
			t.Fatal(err)
		}
		runcCopy := filepath.Join(copyDir, "runc")
		srcBytes, err := os.ReadFile(binPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(runcCopy, srcBytes, 0o755); err != nil {
			t.Fatal(err)
		}
		privBundle := filepath.Join(runcExecDir, "bundle-priv")
		if err := os.MkdirAll(privBundle, 0o755); err != nil {
			t.Fatal(err)
		}
		privSpec := `{"linux":{"uidMappings":[{"containerID":0,"hostID":0,"size":1}]},"mounts":[{"destination":"/scratch","type":"bind","source":"/s"}]}`
		privConfig := filepath.Join(privBundle, "config.json")
		if err := os.WriteFile(privConfig, []byte(privSpec), 0o644); err != nil {
			t.Fatal(err)
		}
		_, privStderr, privCode := runCLI(t, runcCopy, env, "create", "--bundle="+privBundle, "priv-1")
		if privCode != 1 || !strings.Contains(privStderr, "concourse-runc-wrapper: exec /concourse-runc/runc.real:") {
			t.Fatalf("argv[0]=runc copy exit=%d stderr:\n%s", privCode, privStderr)
		}
		afterPriv, err := os.ReadFile(privConfig)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(afterPriv), "/shared-cache") {
			t.Fatalf("privileged bundle was unexpectedly modified:\n%s", afterPriv)
		}
	})

	t.Run("Wiring/NodeNamePrecedenceAndStandalone", func(t *testing.T) {
		listenArgs := []string{
			"--metrics-bind-address=127.0.0.1:0",
			"--health-probe-bind-address=127.0.0.1:0",
			"--pprof-bind-address=127.0.0.1:0",
		}
		expect3 := []string{"metrics", "probe", "pprof-loopback"}

		t.Run("flag_only", func(t *testing.T) {
			env := sandboxEnv(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTCONFIG": "false",
			})
			ra := startAgent(t, binPath, env, expect3,
				append(slices.Clone(listenArgs), "--standalone", "--node-name=flag-node")...)
			defer ra.stopAndWait(t)

			if ra.start.Node != "flag-node" {
				t.Fatalf("node=%q want %q", ra.start.Node, "flag-node")
			}
			if !ra.start.Standalone {
				t.Fatal("standalone=false want true")
			}
			if !slices.Contains(ra.start.Subsystems, "hostmetrics-textfile") {
				t.Fatalf("standalone subsystems missing hostmetrics-textfile: %v", ra.start.Subsystems)
			}
			for _, offSub := range []string{
				"sweeper", "concourse-cache", "workerhygiene", "nodereporter", "hubsync",
				"nethealth", "janitor", "controllerhygiene", "hostconfig", "kinedb",
			} {
				if !slices.Contains(ra.start.Off, offSub) {
					t.Fatalf("standalone expected %q in off list, got off=%v subsystems=%v",
						offSub, ra.start.Off, ra.start.Subsystems)
				}
			}
		})

		t.Run("NODE_NAME_beats_flag", func(t *testing.T) {
			env := sandboxEnv(t, map[string]string{
				"NODE_NAME":                  "downward-node",
				"NODE_HOST_AGENT_STANDALONE": "1",
			})
			ra := startAgent(t, binPath, env, expect3,
				append(slices.Clone(listenArgs), "--node-name=flag-node")...)
			defer ra.stopAndWait(t)

			if ra.start.Node != "downward-node" {
				t.Fatalf("node=%q want %q", ra.start.Node, "downward-node")
			}
			if !ra.start.Standalone {
				t.Fatal("NODE_HOST_AGENT_STANDALONE=1 did not enable standalone mode")
			}
			if !slices.Contains(ra.start.Subsystems, "hostmetrics-textfile") {
				t.Fatalf("standalone env subsystems missing hostmetrics-textfile: %v", ra.start.Subsystems)
			}
			for _, offSub := range []string{
				"sweeper", "concourse-cache", "workerhygiene", "nodereporter", "hubsync",
				"nethealth", "janitor", "controllerhygiene", "hostconfig", "kinedb",
			} {
				if !slices.Contains(ra.start.Off, offSub) {
					t.Fatalf("standalone env expected %q in off list, got off=%v", offSub, ra.start.Off)
				}
			}
		})

		t.Run("NODE_HOST_AGENT_NODE_NAME_beats_NODE_NAME_and_flag", func(t *testing.T) {
			env := sandboxEnv(t, map[string]string{
				"NODE_HOST_AGENT_NODE_NAME": "explicit-node",
				"NODE_NAME":                 "downward-node",
				"POD_NAME":                  "agent-pod-e2e",
			})
			ra := startAgent(t, binPath, env, expect3,
				append(slices.Clone(listenArgs), "--node-name=flag-node")...)
			defer ra.stopAndWait(t)

			if ra.start.Node != "explicit-node" {
				t.Fatalf("node=%q want %q", ra.start.Node, "explicit-node")
			}
			if ra.start.Standalone {
				t.Fatal("pod mode reported standalone=true")
			}
			if slices.Contains(ra.start.Subsystems, "hostmetrics-textfile") {
				t.Fatalf("pod mode unexpectedly wired hostmetrics-textfile: %v", ra.start.Subsystems)
			}
			if !slices.Contains(ra.start.Subsystems, "concourse-cache") {
				t.Fatalf("pod mode expected concourse-cache in subsystems: %v", ra.start.Subsystems)
			}
			for _, offSub := range []string{"nethealth", "janitor", "controllerhygiene", "hostconfig", "kinedb"} {
				if !slices.Contains(ra.start.Off, offSub) {
					t.Fatalf("pod sandbox expected %q in off list, got off=%v", offSub, ra.start.Off)
				}
			}
			// Without kube credentials, kube-dependent subsystems resolve ON and are skipped.
			for _, kubeSub := range []string{"sweeper", "workerhygiene", "nodereporter", "hubsync"} {
				if !slices.Contains(ra.start.Skipped, kubeSub) {
					t.Fatalf("pod mode without kubeconfig expected %q in skipped, got skipped=%v off=%v",
						kubeSub, ra.start.Skipped, ra.start.Off)
				}
			}
		})
	})

	t.Run("HTTP/HealthzReadyzMetricsAndPprofLoopback", func(t *testing.T) {
		t.Run("endpoints_metrics_pprof_signals", func(t *testing.T) {
			env := sandboxEnv(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTCONFIG": "false",
			})
			ra := startAgent(t, binPath, env, []string{"metrics", "probe", "pprof-loopback"},
				"--metrics-bind-address=127.0.0.1:0",
				"--health-probe-bind-address=127.0.0.1:0",
				"--pprof-bind-address=127.0.0.1:0",
				"--standalone",
				"--node-name=http-e2e",
			)

			metricsAddr := ra.addrs["metrics"]
			probeAddr := ra.addrs["probe"]
			pprofAddr := ra.addrs["pprof-loopback"]

			// /healthz and /readyz return 200.
			if code, _ := httpGet(t, fmt.Sprintf("http://%s/healthz", probeAddr)); code != http.StatusOK {
				t.Fatalf("/healthz status=%d want 200", code)
			}
			if code, _ := httpGet(t, fmt.Sprintf("http://%s/readyz", probeAddr)); code != http.StatusOK {
				t.Fatalf("/readyz status=%d want 200", code)
			}

			// /metrics exposes identity info and strictly increasing uptime_seconds.
			code1, body1 := httpGet(t, fmt.Sprintf("http://%s/metrics", metricsAddr))
			if code1 != http.StatusOK {
				t.Fatalf("/metrics status=%d want 200", code1)
			}
			for _, want := range []string{
				"node_host_agent_info{",
				`node="http-e2e"`,
				`version="` + e2eVersion + `"`,
				"node_host_agent_uptime_seconds",
			} {
				if !strings.Contains(body1, want) {
					t.Fatalf("/metrics missing %q", want)
				}
			}
			up1, ok := parseGaugeMetric(body1, "node_host_agent_uptime_seconds")
			if !ok || up1 <= 0 {
				t.Fatalf("first uptime scrape ok=%v val=%v want >0", ok, up1)
			}

			time.Sleep(60 * time.Millisecond)

			code2, body2 := httpGet(t, fmt.Sprintf("http://%s/metrics", metricsAddr))
			if code2 != http.StatusOK {
				t.Fatalf("second /metrics status=%d want 200", code2)
			}
			up2, ok := parseGaugeMetric(body2, "node_host_agent_uptime_seconds")
			if !ok || up2 <= up1 {
				t.Fatalf("uptime did not strictly increase: up1=%v up2=%v (ok=%v)", up1, up2, ok)
			}

			// Metrics listener must not expose /debug/pprof/*.
			for _, path := range []string{"/debug/pprof/", "/debug/pprof/heap?debug=1"} {
				if code, _ := httpGet(t, fmt.Sprintf("http://%s%s", metricsAddr, path)); code != http.StatusNotFound {
					t.Fatalf("metrics listener %s status=%d want 404", path, code)
				}
			}

			// Dedicated pprof-loopback listener binds 127.0.0.1 and serves pprof.
			pprofHost, _, err := net.SplitHostPort(pprofAddr)
			if err != nil {
				t.Fatalf("split pprof addr %q: %v", pprofAddr, err)
			}
			if pprofHost != "127.0.0.1" {
				t.Fatalf("pprof host=%q want 127.0.0.1", pprofHost)
			}
			if code, _ := httpGet(t, fmt.Sprintf("http://%s/debug/pprof/cmdline", pprofAddr)); code != http.StatusOK {
				t.Fatalf("pprof cmdline status=%d want 200", code)
			}
			codeHeap, bodyHeap := httpGet(t, fmt.Sprintf("http://%s/debug/pprof/heap?debug=1", pprofAddr))
			if codeHeap != http.StatusOK || !strings.Contains(bodyHeap, "heap profile:") {
				t.Fatalf("pprof heap status=%d body_prefix=%.120q", codeHeap, bodyHeap)
			}

			// SIGHUP must be ignored: process remains alive and /healthz stays 200.
			if err := ra.cmd.Process.Signal(syscall.SIGHUP); err != nil {
				t.Fatalf("send SIGHUP: %v", err)
			}
			time.Sleep(50 * time.Millisecond)
			select {
			case <-ra.waitDone:
				t.Fatalf("agent terminated on SIGHUP (err=%v)", ra.waitErr)
			default:
			}
			if code, _ := httpGet(t, fmt.Sprintf("http://%s/healthz", probeAddr)); code != http.StatusOK {
				t.Fatalf("/healthz after SIGHUP status=%d want 200", code)
			}

			// SIGTERM drives clean exit 0.
			ra.stopAndWait(t)

			// Sandboxed standalone mode must never dial systemd/D-Bus or invoke systemctl.
			logs := ra.stdout.String() + "\n" + ra.stderr.String()
			for _, forbidden := range []string{"/run/systemd/private", "systemctl", "dbus"} {
				if strings.Contains(logs, forbidden) {
					t.Fatalf("unexpected systemd/D-Bus log %q in sandboxed run:\n%s", forbidden, logs)
				}
			}
		})

		t.Run("pprof_env_override_without_flag", func(t *testing.T) {
			env := sandboxEnv(t, map[string]string{
				"NODE_HOST_AGENT_PPROF_BIND_ADDRESS": "127.0.0.1:0",
				"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":  "false",
			})
			ra := startAgent(t, binPath, env, []string{"metrics", "probe", "pprof-loopback"},
				"--metrics-bind-address=127.0.0.1:0",
				"--health-probe-bind-address=127.0.0.1:0",
				"--standalone",
				"--node-name=pprof-env-e2e",
			)
			defer ra.stopAndWait(t)

			pprofAddr := ra.addrs["pprof-loopback"]
			pprofHost, _, err := net.SplitHostPort(pprofAddr)
			if err != nil {
				t.Fatalf("split pprof addr %q: %v", pprofAddr, err)
			}
			if pprofHost != "127.0.0.1" {
				t.Fatalf("pprof env host=%q want 127.0.0.1", pprofHost)
			}
			if code, _ := httpGet(t, fmt.Sprintf("http://%s/debug/pprof/cmdline", pprofAddr)); code != http.StatusOK {
				t.Fatalf("pprof env cmdline status=%d want 200", code)
			}
		})

		t.Run("pprof_disabled_with_empty_flag", func(t *testing.T) {
			env := sandboxEnv(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTCONFIG": "false",
			})
			ra := startAgent(t, binPath, env, []string{"metrics", "probe"},
				"--metrics-bind-address=127.0.0.1:0",
				"--health-probe-bind-address=127.0.0.1:0",
				"--pprof-bind-address=",
				"--standalone",
				"--node-name=pprof-off-e2e",
			)
			defer ra.stopAndWait(t)

			if ra.start.PprofLoopbackAddr != "" {
				t.Fatalf("pprofLoopbackAddr=%q want empty", ra.start.PprofLoopbackAddr)
			}
			if addr, ok := ra.addrs["pprof-loopback"]; ok {
				t.Fatalf("pprof-loopback unexpectedly bound at %q when disabled", addr)
			}
			if code, _ := httpGet(t, fmt.Sprintf("http://%s/healthz", ra.addrs["probe"])); code != http.StatusOK {
				t.Fatalf("/healthz status=%d want 200", code)
			}
		})
	})
}

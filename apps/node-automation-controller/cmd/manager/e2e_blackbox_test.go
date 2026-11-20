// e2e_blackbox_test.go — opaque-box end-to-end tests for the compiled
// node-automation-controller manager binary.
//
// No TestMain is defined here: main_test.go re-executes os.Args[0] with
// -test.run=TestHelperProcess, so a TestMain would run inside every helper
// child process. Instead, TestE2EManager compiles the binary once into
// t.TempDir() and drives all CLI, HTTP, pprof, and leader-election scenarios
// as subtests against an in-process protobuf+JSON fake Kubernetes APIServer.
package main_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	authv1 "k8s.io/api/authorization/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
)

const (
	e2eLeaseNamespace = "node-ops"
	e2eLeaseName      = "node-automation-controller.passiontech.dev"
)

func TestE2EManager(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not found in PATH")
	}

	binPath := filepath.Join(t.TempDir(), "manager")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	buildCmd.Env = os.Environ()
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("compile manager binary: %v\n%s", err, out)
	}

	t.Run("CLI/Version", func(t *testing.T) {
		stdout, stderr, code := runManagerOnce(t, binPath, 10*time.Second, nil, "-version")
		if code != 0 {
			t.Fatalf("exit code = %d, want 0 (stdout=%q stderr=%q)", code, stdout, stderr)
		}
		if !strings.Contains(stdout, "node-automation-controller") {
			t.Fatalf("stdout = %q, want substring %q", stdout, "node-automation-controller")
		}
	})

	t.Run("CLI/Help", func(t *testing.T) {
		stdout, stderr, code := runManagerOnce(t, binPath, 10*time.Second, nil, "-help")
		if code != 0 {
			t.Fatalf("exit code = %d, want 0 (stdout=%q stderr=%q)", code, stdout, stderr)
		}
		combined := stdout + stderr
		for _, wantFlag := range []string{
			"-metrics-bind-address",
			"-health-probe-bind-address",
			"-leader-elect",
			"-modules",
		} {
			if !strings.Contains(combined, wantFlag) {
				t.Fatalf("help output missing %q:\n%s", wantFlag, combined)
			}
		}
	})

	t.Run("CLI/UnknownFlag", func(t *testing.T) {
		stdout, stderr, code := runManagerOnce(t, binPath, 10*time.Second, nil, "-no-such-flag")
		if code != 1 {
			t.Fatalf("exit code = %d, want 1 (stdout=%q stderr=%q)", code, stdout, stderr)
		}
	})

	t.Run("CLI/InvalidModules", func(t *testing.T) {
		emptyHome := t.TempDir()
		for _, modArg := range []string{"no-such-module", "@bogus", "@"} {
			t.Run(modArg, func(t *testing.T) {
				stdout, stderr, code := runManagerOnce(
					t, binPath, 10*time.Second,
					scrubbedKubeEnv("HOME="+emptyHome),
					"-modules="+modArg,
				)
				if code != 1 {
					t.Fatalf("exit code = %d, want 1 (stdout=%q stderr=%q)", code, stdout, stderr)
				}
				if !strings.Contains(stderr, "invalid -modules allowlist") {
					t.Fatalf("stderr = %q, want substring %q", stderr, "invalid -modules allowlist")
				}
			})
		}
	})

	t.Run("CLI/MissingKubeconfig", func(t *testing.T) {
		emptyHome := t.TempDir()
		stdout, stderr, code := runManagerOnce(
			t, binPath, 10*time.Second,
			scrubbedKubeEnv("HOME="+emptyHome),
		)
		if code != 1 {
			t.Fatalf("exit code = %d, want 1 (stdout=%q stderr=%q)", code, stdout, stderr)
		}
		if !strings.Contains(stderr, "unable to get kubeconfig") {
			t.Fatalf("stderr = %q, want substring %q", stderr, "unable to get kubeconfig")
		}
	})

	t.Run("CLI/UnreachableAPIServer", func(t *testing.T) {
		kubeconfig := writeE2EKubeconfig(t, "https://127.0.0.1:1")
		stdout, stderr, code := runManagerOnce(
			t, binPath, 15*time.Second,
			scrubbedKubeEnv("KUBECONFIG="+kubeconfig),
		)
		if code != 1 {
			t.Fatalf("exit code = %d, want 1 (stdout=%q stderr=%q)", code, stdout, stderr)
		}
		if !strings.Contains(stderr, "unable to create manager") {
			t.Fatalf("stderr = %q, want substring %q", stderr, "unable to create manager")
		}
	})

	t.Run("CLI/InvalidBindAddress", func(t *testing.T) {
		srv := newFakeE2EAPIServer(t)
		kubeconfig := writeE2EKubeconfig(t, srv.URL())
		pprofPort := freeLoopbackPort(t)
		stdout, stderr, code := runManagerOnce(
			t, binPath, 15*time.Second,
			scrubbedKubeEnv(
				"KUBECONFIG="+kubeconfig,
				"NODE_AUTOMATION_PPROF_BIND_ADDRESS=127.0.0.1:"+pprofPort,
			),
			"-metrics-bind-address=bad-address",
			"-health-probe-bind-address=127.0.0.1:0",
		)
		if code != 1 {
			t.Fatalf("exit code = %d, want 1 (stdout=%q stderr=%q)", code, stdout, stderr)
		}
		if !strings.Contains(stderr, "manager exited") {
			t.Fatalf("stderr = %q, want substring %q", stderr, "manager exited")
		}
	})

	t.Run("CLI/InvalidLeaderElectTiming", func(t *testing.T) {
		srv := newFakeE2EAPIServer(t)
		kubeconfig := writeE2EKubeconfig(t, srv.URL())
		pprofPort := freeLoopbackPort(t)
		stdout, stderr, code := runManagerOnce(
			t, binPath, 15*time.Second,
			scrubbedKubeEnv(
				"KUBECONFIG="+kubeconfig,
				"NODE_AUTOMATION_PPROF_BIND_ADDRESS=127.0.0.1:"+pprofPort,
			),
			"-leader-elect=true",
			"-leader-elect-lease-duration=2s",
			"-leader-elect-renew-deadline=5s",
			"-metrics-bind-address=127.0.0.1:0",
			"-health-probe-bind-address=127.0.0.1:0",
			"-modules=evicted-pod-janitor",
		)
		if code != 1 {
			t.Fatalf("exit code = %d, want 1 (stdout=%q stderr=%q)", code, stdout, stderr)
		}
	})

	t.Run("HTTP/ProbesMetricsAndPprof", func(t *testing.T) {
		srv := newFakeE2EAPIServer(t)
		kubeconfig := writeE2EKubeconfig(t, srv.URL())
		metricsAddr := "127.0.0.1:" + freeLoopbackPort(t)
		probeAddr := "127.0.0.1:" + freeLoopbackPort(t)
		pprofAddr := "127.0.0.1:" + freeLoopbackPort(t)

		proc := startManagerProcess(
			t, binPath,
			scrubbedKubeEnv(
				"KUBECONFIG="+kubeconfig,
				"NODE_AUTOMATION_PPROF_BIND_ADDRESS="+pprofAddr,
			),
			"-metrics-bind-address="+metricsAddr,
			"-health-probe-bind-address="+probeAddr,
			"-modules=evicted-pod-janitor",
		)

		waitHTTP200(t, "http://"+probeAddr+"/healthz", 20*time.Second, proc)
		waitHTTP200(t, "http://"+probeAddr+"/readyz", 20*time.Second, proc)

		metricsCode, metricsBody, err := httpGetBody("http://" + metricsAddr + "/metrics")
		if err != nil {
			t.Fatalf("GET /metrics: %v", err)
		}
		if metricsCode != http.StatusOK {
			t.Fatalf("GET /metrics status = %d, want 200", metricsCode)
		}
		for _, wantFamily := range []string{
			"go_memstats_alloc_bytes",
			"go_goroutines",
			"process_resident_memory_bytes",
			"shell_operator_hook_run_errors_total",
			"node_automation_",
		} {
			if !strings.Contains(metricsBody, wantFamily) {
				t.Errorf("/metrics missing expected family %q", wantFamily)
			}
		}

		// F16: /debug/pprof must be served ONLY on the dedicated loopback pprof listener,
		// and return 404 on the metrics listener.
		if code, _, err := httpGetBody("http://" + metricsAddr + "/debug/pprof/"); err != nil {
			t.Errorf("GET metrics /debug/pprof/: %v", err)
		} else if code != http.StatusNotFound {
			t.Errorf("metrics listener /debug/pprof/ status = %d, want 404", code)
		}

		if code, body, err := httpGetBody("http://" + pprofAddr + "/debug/pprof/heap?debug=1"); err != nil {
			t.Errorf("GET pprof /debug/pprof/heap?debug=1: %v", err)
		} else if code != http.StatusOK {
			t.Errorf("pprof /debug/pprof/heap?debug=1 status = %d, want 200", code)
		} else if !strings.Contains(body, "heap profile:") {
			t.Errorf("pprof heap body missing header: %.200s", body)
		}

		if code, _, err := httpGetBody("http://" + pprofAddr + "/debug/pprof/cmdline"); err != nil {
			t.Errorf("GET pprof /debug/pprof/cmdline: %v", err)
		} else if code != http.StatusOK {
			t.Errorf("pprof /debug/pprof/cmdline status = %d, want 200", code)
		}

		proc.stopWithSIGINTAndAssertZero(t, 20*time.Second)
	})

	t.Run("Pprof/LoopbackEnforcement", func(t *testing.T) {
		// Assert F16 directly without t.Skip: fails pre-M3, passes post-M3.
		stdout, stderr, code := runManagerOnce(t, binPath, 10*time.Second, nil, "-help")
		if code != 0 {
			t.Fatalf("-help exit code = %d, want 0 (stderr=%q)", code, stderr)
		}
		helpText := stdout + stderr
		if !strings.Contains(helpText, "-pprof-bind-address") {
			t.Errorf("-help missing -pprof-bind-address flag:\n%s", helpText)
		}
		if !strings.Contains(helpText, "127.0.0.1:9116") {
			t.Errorf("-help missing default 127.0.0.1:9116:\n%s", helpText)
		}

		srv := newFakeE2EAPIServer(t)
		kubeconfig := writeE2EKubeconfig(t, srv.URL())

		t.Run("rejects 0.0.0.0 via flag", func(t *testing.T) {
			badAddr := "0.0.0.0:" + freeLoopbackPort(t)
			out, errOut, rc := runManagerOnce(
				t, binPath, 5*time.Second,
				scrubbedKubeEnv("KUBECONFIG="+kubeconfig),
				"-metrics-bind-address=127.0.0.1:0",
				"-health-probe-bind-address=127.0.0.1:0",
				"-pprof-bind-address="+badAddr,
				"-modules=evicted-pod-janitor",
			)
			if rc == 0 {
				t.Fatalf("expected non-zero exit for non-loopback -pprof-bind-address=%s (stdout=%q stderr=%q)",
					badAddr, out, errOut)
			}
			if strings.Contains(errOut, "flag provided but not defined") {
				t.Fatalf("-pprof-bind-address flag not supported yet: %s", errOut)
			}
		})

		t.Run("rejects 0.0.0.0 via env", func(t *testing.T) {
			badAddr := "0.0.0.0:" + freeLoopbackPort(t)
			out, errOut, rc := runManagerOnce(
				t, binPath, 5*time.Second,
				scrubbedKubeEnv(
					"KUBECONFIG="+kubeconfig,
					"NODE_AUTOMATION_PPROF_BIND_ADDRESS="+badAddr,
				),
				"-metrics-bind-address=127.0.0.1:0",
				"-health-probe-bind-address=127.0.0.1:0",
				"-modules=evicted-pod-janitor",
			)
			if rc == 0 {
				t.Fatalf("expected non-zero exit for non-loopback NODE_AUTOMATION_PPROF_BIND_ADDRESS=%s (stdout=%q stderr=%q)",
					badAddr, out, errOut)
			}
		})

		t.Run("serves loopback via flag and hides from metrics", func(t *testing.T) {
			metricsAddr := "127.0.0.1:" + freeLoopbackPort(t)
			probeAddr := "127.0.0.1:" + freeLoopbackPort(t)
			pprofAddr := "127.0.0.1:" + freeLoopbackPort(t)

			proc := startManagerProcess(
				t, binPath,
				scrubbedKubeEnv("KUBECONFIG="+kubeconfig),
				"-metrics-bind-address="+metricsAddr,
				"-health-probe-bind-address="+probeAddr,
				"-pprof-bind-address="+pprofAddr,
				"-modules=evicted-pod-janitor",
			)
			waitHTTP200(t, "http://"+probeAddr+"/readyz", 20*time.Second, proc)

			if c, _, err := httpGetBody("http://" + metricsAddr + "/debug/pprof/"); err != nil {
				t.Fatalf("GET metrics /debug/pprof/: %v", err)
			} else if c != http.StatusNotFound {
				t.Fatalf("metrics /debug/pprof/ status = %d, want 404", c)
			}

			if c, body, err := httpGetBody("http://" + pprofAddr + "/debug/pprof/heap?debug=1"); err != nil {
				t.Fatalf("GET pprof /debug/pprof/heap?debug=1: %v", err)
			} else if c != http.StatusOK || !strings.Contains(body, "heap profile:") {
				t.Fatalf("pprof /debug/pprof/heap?debug=1 status=%d body=%.120q", c, body)
			}

			if c, _, err := httpGetBody("http://" + pprofAddr + "/debug/pprof/cmdline"); err != nil {
				t.Fatalf("GET pprof /debug/pprof/cmdline: %v", err)
			} else if c != http.StatusOK {
				t.Fatalf("pprof /debug/pprof/cmdline status = %d, want 200", c)
			}

			proc.stopWithSIGINTAndAssertZero(t, 20*time.Second)
		})

		t.Run("serves loopback via env override", func(t *testing.T) {
			metricsAddr := "127.0.0.1:" + freeLoopbackPort(t)
			probeAddr := "127.0.0.1:" + freeLoopbackPort(t)
			pprofAddr := "127.0.0.1:" + freeLoopbackPort(t)

			proc := startManagerProcess(
				t, binPath,
				scrubbedKubeEnv(
					"KUBECONFIG="+kubeconfig,
					"NODE_AUTOMATION_PPROF_BIND_ADDRESS="+pprofAddr,
				),
				"-metrics-bind-address="+metricsAddr,
				"-health-probe-bind-address="+probeAddr,
				"-modules=evicted-pod-janitor",
			)
			waitHTTP200(t, "http://"+probeAddr+"/readyz", 20*time.Second, proc)

			if c, _, err := httpGetBody("http://" + metricsAddr + "/debug/pprof/"); err != nil {
				t.Fatalf("GET metrics /debug/pprof/: %v", err)
			} else if c != http.StatusNotFound {
				t.Fatalf("metrics /debug/pprof/ status = %d, want 404", c)
			}

			if c, body, err := httpGetBody("http://" + pprofAddr + "/debug/pprof/heap?debug=1"); err != nil {
				t.Fatalf("GET pprof /debug/pprof/heap?debug=1: %v", err)
			} else if c != http.StatusOK || !strings.Contains(body, "heap profile:") {
				t.Fatalf("pprof /debug/pprof/heap?debug=1 status=%d body=%.120q", c, body)
			}

			if c, _, err := httpGetBody("http://" + pprofAddr + "/debug/pprof/cmdline"); err != nil {
				t.Fatalf("GET pprof /debug/pprof/cmdline: %v", err)
			} else if c != http.StatusOK {
				t.Fatalf("pprof /debug/pprof/cmdline status = %d, want 200", c)
			}

			proc.stopWithSIGINTAndAssertZero(t, 20*time.Second)
		})
	})

	t.Run("LeaderElection/AcquireAndGracefulRelease", func(t *testing.T) {
		srv := newFakeE2EAPIServer(t)
		kubeconfig := writeE2EKubeconfig(t, srv.URL())
		metricsAddr := "127.0.0.1:" + freeLoopbackPort(t)
		probeAddr := "127.0.0.1:" + freeLoopbackPort(t)
		pprofAddr := "127.0.0.1:" + freeLoopbackPort(t)

		proc := startManagerProcess(
			t, binPath,
			scrubbedKubeEnv(
				"KUBECONFIG="+kubeconfig,
				"POD_NAME=nac-e2e-pod-a",
				"NODE_AUTOMATION_PPROF_BIND_ADDRESS="+pprofAddr,
			),
			"-leader-elect=true",
			"-leader-elect-lease-duration=15s",
			"-leader-elect-renew-deadline=10s",
			"-leader-elect-retry-period=500ms",
			"-metrics-bind-address="+metricsAddr,
			"-health-probe-bind-address="+probeAddr,
			"-modules=evicted-pod-janitor",
		)

		lease := waitForLeaseHolderPrefix(t, srv, "nac-e2e-pod-a_", 20*time.Second, proc)
		if lease.Spec.LeaseDurationSeconds == nil || *lease.Spec.LeaseDurationSeconds != 15 {
			t.Fatalf("acquired lease duration = %v, want 15", lease.Spec.LeaseDurationSeconds)
		}
		waitHTTP200(t, "http://"+probeAddr+"/readyz", 20*time.Second, proc)

		proc.stopWithSIGINTAndAssertZero(t, 20*time.Second)

		released := srv.getLease()
		if released == nil {
			t.Fatal("expected Lease object to remain after graceful release")
		}
		if released.Spec.HolderIdentity != nil && *released.Spec.HolderIdentity != "" {
			t.Fatalf("Lease HolderIdentity after graceful SIGINT = %q, want empty", *released.Spec.HolderIdentity)
		}
	})

	t.Run("LeaderElection/ForeignHolderWatchdogNoClobber", func(t *testing.T) {
		srv := newFakeE2EAPIServer(t)
		kubeconfig := writeE2EKubeconfig(t, srv.URL())
		metricsAddr := "127.0.0.1:" + freeLoopbackPort(t)
		probeAddr := "127.0.0.1:" + freeLoopbackPort(t)
		pprofAddr := "127.0.0.1:" + freeLoopbackPort(t)

		// RenewDeadline (15s) > leaseWatchInterval (5s) so leaseLossWatchdog
		// detects the foreign holder and cancels workCtx cleanly (exit 0)
		// before client-go's RenewDeadline triggers a fatal election loss (exit 1).
		proc := startManagerProcess(
			t, binPath,
			scrubbedKubeEnv(
				"KUBECONFIG="+kubeconfig,
				"POD_NAME=nac-e2e-pod-a",
				"NODE_AUTOMATION_PPROF_BIND_ADDRESS="+pprofAddr,
			),
			"-leader-elect=true",
			"-leader-elect-lease-duration=30s",
			"-leader-elect-renew-deadline=15s",
			"-leader-elect-retry-period=1s",
			"-metrics-bind-address="+metricsAddr,
			"-health-probe-bind-address="+probeAddr,
			"-modules=evicted-pod-janitor",
		)

		waitForLeaseHolderPrefix(t, srv, "nac-e2e-pod-a_", 20*time.Second, proc)
		waitHTTP200(t, "http://"+probeAddr+"/readyz", 20*time.Second, proc)

		const foreignHolder = "nac-e2e-pod-b_9999"
		srv.setLeaseHolder(foreignHolder)

		proc.waitExitZero(t, 15*time.Second)

		after := srv.getLease()
		if after == nil || after.Spec.HolderIdentity == nil {
			t.Fatalf("Lease missing after watchdog exit: %+v", after)
		}
		if *after.Spec.HolderIdentity != foreignHolder {
			t.Fatalf("Lease HolderIdentity = %q, want %q (watchdog release clobbered foreign holder)",
				*after.Spec.HolderIdentity, foreignHolder)
		}
	})
}

// ---- process and HTTP helpers ----------------------------------------------

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type managerProcess struct {
	cmd     *exec.Cmd
	stdout  *lockedBuf
	stderr  *lockedBuf
	done    chan struct{}
	waitErr error
}

func startManagerProcess(t *testing.T, binPath string, env []string, args ...string) *managerProcess {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	if env != nil {
		cmd.Env = env
	} else {
		cmd.Env = scrubbedKubeEnv()
	}
	outBuf := &lockedBuf{}
	errBuf := &lockedBuf{}
	cmd.Stdout = outBuf
	cmd.Stderr = errBuf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", binPath, err)
	}
	p := &managerProcess{
		cmd:    cmd,
		stdout: outBuf,
		stderr: errBuf,
		done:   make(chan struct{}),
	}
	go func() {
		p.waitErr = cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(func() {
		select {
		case <-p.done:
		default:
			_ = p.cmd.Process.Kill()
			<-p.done
		}
	})
	return p
}

func (p *managerProcess) stopWithSIGINTAndAssertZero(t *testing.T, timeout time.Duration) {
	t.Helper()
	if err := p.cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("send SIGINT: %v", err)
	}
	p.waitExitZero(t, timeout)
}

func (p *managerProcess) waitExitZero(t *testing.T, timeout time.Duration) {
	t.Helper()
	select {
	case <-p.done:
		if p.waitErr != nil {
			t.Fatalf("manager exited with %v, want exit 0\nstdout:\n%s\nstderr:\n%s",
				p.waitErr, p.stdout.String(), p.stderr.String())
		}
	case <-time.After(timeout):
		_ = p.cmd.Process.Kill()
		<-p.done
		t.Fatalf("timed out after %s waiting for manager exit\nstdout:\n%s\nstderr:\n%s",
			timeout, p.stdout.String(), p.stderr.String())
	}
}

func runManagerOnce(t *testing.T, binPath string, timeout time.Duration, env []string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, args...)
	if env != nil {
		cmd.Env = env
	} else {
		cmd.Env = scrubbedKubeEnv()
	}
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("command %v timed out after %s: %v\nstdout:\n%s\nstderr:\n%s",
			args, timeout, ctx.Err(), outBuf.String(), errBuf.String())
	}
	if err == nil {
		return outBuf.String(), errBuf.String(), 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("exec %v failed: %v", args, err)
	}
	return outBuf.String(), errBuf.String(), exitErr.ExitCode()
}

func scrubbedKubeEnv(extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		switch key {
		case "KUBECONFIG", "KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT",
			"POD_NAME", "NODE_AUTOMATION_PPROF_BIND_ADDRESS":
			continue
		}
		env = append(env, kv)
	}
	return append(env, extra...)
}

func writeE2EKubeconfig(t *testing.T, serverURL string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubeconfig")
	content := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: e2e
  cluster:
    server: %s
contexts:
- name: e2e
  context:
    cluster: e2e
    user: e2e
current-context: e2e
users:
- name: e2e
  user:
    token: e2e-fake-token
`, serverURL)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	return path
}

func freeLoopbackPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate loopback port: %v", err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	_ = ln.Close()
	if err != nil {
		t.Fatalf("split port from %q: %v", ln.Addr().String(), err)
	}
	return port
}

func httpGetBody(rawURL string) (int, string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(body), nil
}

func waitHTTP200(t *testing.T, rawURL string, timeout time.Duration, proc *managerProcess) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	var lastCode int
	for time.Now().Before(deadline) {
		select {
		case <-proc.done:
			t.Fatalf("manager exited prematurely (%v) while waiting for %s\nstdout:\n%s\nstderr:\n%s",
				proc.waitErr, rawURL, proc.stdout.String(), proc.stderr.String())
		default:
		}
		code, _, err := httpGetBody(rawURL)
		if err == nil && code == http.StatusOK {
			return
		}
		lastErr = err
		lastCode = code
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for 200 from %s (lastCode=%d lastErr=%v)\nstdout:\n%s\nstderr:\n%s",
		rawURL, lastCode, lastErr, proc.stdout.String(), proc.stderr.String())
}

func waitForLeaseHolderPrefix(t *testing.T, srv *fakeE2EAPIServer, prefix string, timeout time.Duration, proc *managerProcess) *coordinationv1.Lease {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-proc.done:
			t.Fatalf("manager exited prematurely (%v) while waiting for Lease holder %q\nstdout:\n%s\nstderr:\n%s",
				proc.waitErr, prefix, proc.stdout.String(), proc.stderr.String())
		default:
		}
		lease := srv.getLease()
		if lease != nil && lease.Spec.HolderIdentity != nil && strings.HasPrefix(*lease.Spec.HolderIdentity, prefix) {
			return lease
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for Lease holder prefix %q (got=%+v)\nstdout:\n%s\nstderr:\n%s",
		prefix, srv.getLease(), proc.stdout.String(), proc.stderr.String())
	return nil
}

// ---- fakeE2EAPIServer (protobuf + JSON) ------------------------------------

type fakeE2EAPIServer struct {
	srv    *httptest.Server
	scheme *runtime.Scheme
	codecs serializer.CodecFactory

	mu      sync.Mutex
	lease   *coordinationv1.Lease
	nextRV  atomic.Int64
	events  []*corev1.Event
	watchCh chan struct{}
}

func newFakeE2EAPIServer(t *testing.T) *fakeE2EAPIServer {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(apiextensionsv1.AddToScheme(s))

	f := &fakeE2EAPIServer{
		scheme:  s,
		codecs:  serializer.NewCodecFactory(s),
		watchCh: make(chan struct{}),
	}
	f.nextRV.Store(1)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api", f.handleAPIVersions)
	mux.HandleFunc("GET /apis", f.handleAPIGroupList)
	mux.HandleFunc("GET /api/v1", f.handleCoreV1Discovery)
	mux.HandleFunc("GET /apis/apps/v1", f.handleAppsV1Discovery)
	mux.HandleFunc("GET /apis/apiextensions.k8s.io/v1", f.handleCRDDiscovery)
	mux.HandleFunc("GET /apis/coordination.k8s.io/v1", f.handleCoordinationDiscovery)
	mux.HandleFunc("GET /apis/authorization.k8s.io/v1", f.handleAuthDiscovery)
	mux.HandleFunc("POST /apis/authorization.k8s.io/v1/selfsubjectaccessreviews", f.handleSSARCreate)
	mux.HandleFunc("/", f.handleResource)

	f.srv = httptest.NewServer(mux)
	t.Cleanup(func() {
		close(f.watchCh)
		f.srv.Close()
	})
	return f
}

func (f *fakeE2EAPIServer) URL() string {
	return f.srv.URL
}

func (f *fakeE2EAPIServer) getLease() *coordinationv1.Lease {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lease == nil {
		return nil
	}
	return f.lease.DeepCopy()
}

func (f *fakeE2EAPIServer) setLeaseHolder(holder string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := metav1.NewMicroTime(time.Now())
	rv := fmt.Sprintf("%d", f.nextRV.Add(1))
	if f.lease == nil {
		dur := int32(30)
		f.lease = &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{
				Name:            e2eLeaseName,
				Namespace:       e2eLeaseNamespace,
				ResourceVersion: rv,
			},
			Spec: coordinationv1.LeaseSpec{
				HolderIdentity:       &holder,
				LeaseDurationSeconds: &dur,
				AcquireTime:          &now,
				RenewTime:            &now,
			},
		}
		return
	}
	f.lease.ResourceVersion = rv
	f.lease.Spec.HolderIdentity = &holder
	f.lease.Spec.RenewTime = &now
}

func (f *fakeE2EAPIServer) handleAPIVersions(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprint(w, `{"kind":"APIVersions","apiVersion":"v1","versions":["v1"]}`)
}

func (f *fakeE2EAPIServer) handleAPIGroupList(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprint(w, `{"kind":"APIGroupList","apiVersion":"v1","groups":[`+
		`{"name":"apps","versions":[{"groupVersion":"apps/v1","version":"v1"}],`+
		`"preferredVersion":{"groupVersion":"apps/v1","version":"v1"}},`+
		`{"name":"apiextensions.k8s.io","versions":[{"groupVersion":"apiextensions.k8s.io/v1","version":"v1"}],`+
		`"preferredVersion":{"groupVersion":"apiextensions.k8s.io/v1","version":"v1"}},`+
		`{"name":"coordination.k8s.io","versions":[{"groupVersion":"coordination.k8s.io/v1","version":"v1"}],`+
		`"preferredVersion":{"groupVersion":"coordination.k8s.io/v1","version":"v1"}},`+
		`{"name":"authorization.k8s.io","versions":[{"groupVersion":"authorization.k8s.io/v1","version":"v1"}],`+
		`"preferredVersion":{"groupVersion":"authorization.k8s.io/v1","version":"v1"}}]}`)
}

func (f *fakeE2EAPIServer) handleCoreV1Discovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprint(w, `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"v1","resources":[`+
		`{"name":"configmaps","singularName":"","namespaced":true,"kind":"ConfigMap","verbs":["get","list","watch"]},`+
		`{"name":"endpoints","singularName":"","namespaced":true,"kind":"Endpoints","verbs":["get","list","watch"]},`+
		`{"name":"events","singularName":"","namespaced":true,"kind":"Event","verbs":["create","patch","update"]},`+
		`{"name":"nodes","singularName":"","namespaced":false,"kind":"Node","verbs":["get","list","watch"]},`+
		`{"name":"pods","singularName":"","namespaced":true,"kind":"Pod","verbs":["get","list","watch"]},`+
		`{"name":"secrets","singularName":"","namespaced":true,"kind":"Secret","verbs":["get","list","watch"]}]}`)
}

func (f *fakeE2EAPIServer) handleAppsV1Discovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprint(w, `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"apps/v1","resources":[`+
		`{"name":"daemonsets","singularName":"","namespaced":true,"kind":"DaemonSet","verbs":["get","list","watch"]},`+
		`{"name":"deployments","singularName":"","namespaced":true,"kind":"Deployment","verbs":["get","list","watch"]}]}`)
}

func (f *fakeE2EAPIServer) handleCRDDiscovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprint(w, `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"apiextensions.k8s.io/v1","resources":[`+
		`{"name":"customresourcedefinitions","singularName":"","namespaced":false,"kind":"CustomResourceDefinition","verbs":["get","list","watch"]}]}`)
}

func (f *fakeE2EAPIServer) handleCoordinationDiscovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprint(w, `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"coordination.k8s.io/v1","resources":[`+
		`{"name":"leases","singularName":"","namespaced":true,"kind":"Lease","verbs":["get","list","watch","create","update","patch"]}]}`)
}

func (f *fakeE2EAPIServer) handleAuthDiscovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprint(w, `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"authorization.k8s.io/v1","resources":[`+
		`{"name":"selfsubjectaccessreviews","singularName":"","namespaced":false,"kind":"SelfSubjectAccessReview","verbs":["create"]}]}`)
}

func (f *fakeE2EAPIServer) handleSSARCreate(w http.ResponseWriter, r *http.Request) {
	var sar authv1.SelfSubjectAccessReview
	if err := f.decodeRequest(r, &sar); err != nil {
		f.writeStatus(w, r, http.StatusBadRequest, metav1.StatusReasonBadRequest, err.Error())
		return
	}
	sar.Status.Allowed = true
	f.writeObject(w, r, http.StatusCreated, authv1.SchemeGroupVersion, &sar)
}

func (f *fakeE2EAPIServer) handleResource(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	leaseCollection := "/apis/coordination.k8s.io/v1/namespaces/" + e2eLeaseNamespace + "/leases"
	leaseItem := leaseCollection + "/" + e2eLeaseName

	switch {
	case path == leaseItem:
		f.handleLeaseItem(w, r)
		return
	case path == leaseCollection && r.Method == http.MethodPost:
		f.handleLeaseCreate(w, r)
		return
	case r.Method == http.MethodPost && strings.HasPrefix(path, "/api/v1/namespaces/") && strings.HasSuffix(path, "/events"):
		f.handleEventCreate(w, r)
		return
	}

	var gv schema.GroupVersion
	var itemKind string
	var list runtime.Object
	switch {
	case strings.HasSuffix(path, "/daemonsets"):
		gv = appsv1.SchemeGroupVersion
		itemKind = "DaemonSet"
		list = &appsv1.DaemonSetList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}}
	case strings.HasSuffix(path, "/deployments"):
		gv = appsv1.SchemeGroupVersion
		itemKind = "Deployment"
		list = &appsv1.DeploymentList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}}
	case strings.HasSuffix(path, "/customresourcedefinitions"):
		gv = apiextensionsv1.SchemeGroupVersion
		itemKind = "CustomResourceDefinition"
		list = &apiextensionsv1.CustomResourceDefinitionList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}}
	case strings.HasSuffix(path, "/secrets"):
		gv = corev1.SchemeGroupVersion
		itemKind = "Secret"
		list = &corev1.SecretList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}}
	case strings.HasSuffix(path, "/configmaps"):
		gv = corev1.SchemeGroupVersion
		itemKind = "ConfigMap"
		list = &corev1.ConfigMapList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}}
	case strings.HasSuffix(path, "/nodes"):
		gv = corev1.SchemeGroupVersion
		itemKind = "Node"
		list = &corev1.NodeList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}}
	case strings.HasSuffix(path, "/pods"):
		gv = corev1.SchemeGroupVersion
		itemKind = "Pod"
		list = &corev1.PodList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}}
	case strings.HasSuffix(path, "/leases"):
		gv = coordinationv1.SchemeGroupVersion
		itemKind = "Lease"
		f.mu.Lock()
		var items []coordinationv1.Lease
		if f.lease != nil {
			items = append(items, *f.lease.DeepCopy())
		}
		f.mu.Unlock()
		list = &coordinationv1.LeaseList{
			ListMeta: metav1.ListMeta{ResourceVersion: fmt.Sprintf("%d", f.nextRV.Load())},
			Items:    items,
		}
	default:
		f.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, "not found: "+path)
		return
	}

	if r.URL.Query().Get("watch") == "true" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.URL.Query().Get("sendInitialEvents") == "true" {
			// client-go v0.37+ enables WatchListClient by default; reflectors wait
			// for a BOOKMARK carrying k8s.io/initial-events-end="true" before
			// reporting the informer cache synced.
			bookmarkRV := "1"
			if li, ok := list.(metav1.ListInterface); ok && li.GetResourceVersion() != "" {
				bookmarkRV = li.GetResourceVersion()
			}
			_, _ = fmt.Fprintf(w,
				`{"type":"BOOKMARK","object":{"apiVersion":%q,"kind":%q,"metadata":{"resourceVersion":%q,"annotations":{"k8s.io/initial-events-end":"true"}}}}`+"\n",
				gv.String(), itemKind, bookmarkRV)
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		select {
		case <-r.Context().Done():
		case <-f.watchCh:
		}
		return
	}

	f.writeObject(w, r, http.StatusOK, gv, list)
}

func (f *fakeE2EAPIServer) handleLeaseItem(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		f.mu.Lock()
		var cur *coordinationv1.Lease
		if f.lease != nil {
			cur = f.lease.DeepCopy()
		}
		f.mu.Unlock()
		if cur == nil {
			f.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound,
				fmt.Sprintf("leases.coordination.k8s.io %q not found", e2eLeaseName))
			return
		}
		f.writeObject(w, r, http.StatusOK, coordinationv1.SchemeGroupVersion, cur)
	case http.MethodPut:
		var incoming coordinationv1.Lease
		if err := f.decodeRequest(r, &incoming); err != nil {
			f.writeStatus(w, r, http.StatusBadRequest, metav1.StatusReasonBadRequest, err.Error())
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.lease == nil {
			f.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound,
				fmt.Sprintf("leases.coordination.k8s.io %q not found", e2eLeaseName))
			return
		}
		if incoming.ResourceVersion != f.lease.ResourceVersion {
			f.writeStatus(w, r, http.StatusConflict, metav1.StatusReasonConflict,
				fmt.Sprintf("Operation cannot be fulfilled on leases.coordination.k8s.io %q: resourceVersion mismatch (%s != %s)",
					e2eLeaseName, incoming.ResourceVersion, f.lease.ResourceVersion))
			return
		}
		updated := incoming.DeepCopy()
		updated.Namespace = e2eLeaseNamespace
		updated.Name = e2eLeaseName
		updated.ResourceVersion = fmt.Sprintf("%d", f.nextRV.Add(1))
		f.lease = updated
		f.writeObject(w, r, http.StatusOK, coordinationv1.SchemeGroupVersion, updated.DeepCopy())
	default:
		f.writeStatus(w, r, http.StatusMethodNotAllowed, metav1.StatusReasonMethodNotAllowed, "method not allowed")
	}
}

func (f *fakeE2EAPIServer) handleLeaseCreate(w http.ResponseWriter, r *http.Request) {
	var incoming coordinationv1.Lease
	if err := f.decodeRequest(r, &incoming); err != nil {
		f.writeStatus(w, r, http.StatusBadRequest, metav1.StatusReasonBadRequest, err.Error())
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lease != nil {
		f.writeStatus(w, r, http.StatusConflict, metav1.StatusReasonAlreadyExists,
			fmt.Sprintf("leases.coordination.k8s.io %q already exists", e2eLeaseName))
		return
	}
	created := incoming.DeepCopy()
	created.Namespace = e2eLeaseNamespace
	if created.Name == "" {
		created.Name = e2eLeaseName
	}
	created.ResourceVersion = fmt.Sprintf("%d", f.nextRV.Add(1))
	f.lease = created
	f.writeObject(w, r, http.StatusCreated, coordinationv1.SchemeGroupVersion, created.DeepCopy())
}

func (f *fakeE2EAPIServer) handleEventCreate(w http.ResponseWriter, r *http.Request) {
	var ev corev1.Event
	if err := f.decodeRequest(r, &ev); err != nil {
		f.writeStatus(w, r, http.StatusBadRequest, metav1.StatusReasonBadRequest, err.Error())
		return
	}
	ev.ResourceVersion = fmt.Sprintf("%d", f.nextRV.Add(1))
	f.mu.Lock()
	f.events = append(f.events, ev.DeepCopy())
	f.mu.Unlock()
	f.writeObject(w, r, http.StatusCreated, corev1.SchemeGroupVersion, &ev)
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

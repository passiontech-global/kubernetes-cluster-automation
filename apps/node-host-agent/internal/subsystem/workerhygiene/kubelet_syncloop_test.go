// kubelet_syncloop_test.go — A4 syncloop probe (PLEG freeze
// detection, auth-inconclusive handling) and the containerd
// unix-socket liveness check.
package workerhygiene

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- Wave-2 tests: A4 syncloop + containerd-sock ---

func TestSyncloopDownLatchesOnPLEGFreeze(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.status["https://127.0.0.1:10250/healthz/syncloop"] = 500
	for i := 0; i < 2; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.h.State.Exists("kubelet-syncloop-down") {
		t.Fatal("state-kubelet-syncloop-down should latch after 2 failed syncloop probes")
	}
	e.status["https://127.0.0.1:10250/healthz/syncloop"] = 200
	e.h.Cycle(context.Background())
	if e.h.State.Exists("kubelet-syncloop-down") {
		t.Fatal("recovery should clear the syncloop latch")
	}
}

// TestSyncloopNon200LogsStatusCode: a non-200 answer carries no Go
// error — the suspect/latch lines must still record the code, not
// "last_err=<nil>".
func TestSyncloopNon200LogsStatusCode(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.status["https://127.0.0.1:10250/healthz/syncloop"] = 500
	e.h.Cycle(context.Background()) // streak 1 → suspect line
	if got := logLines(t, e); !strings.Contains(got, "status 500") {
		t.Fatalf("suspect line must carry the HTTP code, got:\n%s", got)
	}
	e.h.Cycle(context.Background()) // streak 2 → latch
	if !e.h.State.Exists("kubelet-syncloop-down") {
		t.Fatal("latch expected after ConsecNeeded failed probes")
	}
	if got := logLines(t, e); strings.Contains(got, "last_err=<nil>") {
		t.Fatalf("latch extra must record the code, got:\n%s", got)
	}
}

func TestSyncloopFailClosedWhenActiveCheckErrors(t *testing.T) {
	e := fixture(t)
	// Force the Active() error path: no is-active reply leaves the
	// fake answering ENOENT — the gate is wired but unverifiable,
	// so worker checks must gate off (fail closed). The syncloop
	// probe is ALSO failing — if the gate didn't hold, two cycles
	// would latch kubelet-syncloop-down.
	delete(e.sdReply, "systemctl is-active k0sworker.service")
	e.status["https://127.0.0.1:10250/healthz/syncloop"] = 500
	for i := 0; i < 2; i++ {
		e.h.Cycle(context.Background())
	}
	if e.h.State.Exists("kubelet-syncloop-down") {
		t.Fatal("no latch may be written while the unit state is unknown")
	}
}

// TestSyncloopUnauthorizedIsInconclusive: a 401/403 answer means
// kubelet is alive but won't divulge the syncloop verdict — the
// check must neither latch nor count failures, and the notice is
// logged once per unauth streak, not every cycle.
func TestSyncloopUnauthorizedIsInconclusive(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.status["https://127.0.0.1:10250/healthz/syncloop"] = 401
	for i := 0; i < 3; i++ {
		e.h.Cycle(context.Background())
	}
	if e.h.State.Exists("kubelet-syncloop-down") {
		t.Fatal("401 must not latch kubelet-syncloop-down")
	}
	got := logLines(t, e)
	if !strings.Contains(got, "probe unauthorized") {
		t.Fatalf("expected an unauthorized/inconclusive log line, got:\n%s", got)
	}
	if n := strings.Count(got, "probe unauthorized"); n != 1 {
		t.Fatalf("unauthorized should log once per streak, got %d lines:\n%s", n, got)
	}
	// A real verdict ends the streak — a later unauth stretch logs
	// again.
	e.status["https://127.0.0.1:10250/healthz/syncloop"] = 200
	e.h.Cycle(context.Background())
	e.status["https://127.0.0.1:10250/healthz/syncloop"] = 401
	e.h.Cycle(context.Background())
	if n := strings.Count(logLines(t, e), "probe unauthorized"); n != 2 {
		t.Fatalf("unauth after a healthy verdict must re-log, got %d lines", n)
	}
}

// TestSyncloopProbeSendsBearerToken: kubelet :10250 denies anonymous
// /healthz — the SA token from KubeletTokenPath must ride the probe.
func TestSyncloopProbeSendsBearerToken(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	tok := filepath.Join(e.state, "sa-token")
	writeFile(t, tok, "tok-abc-123\n")
	e.h.Cfg.Kubelet.TokenPath = tok
	e.h.Cycle(context.Background())
	if got := e.bearer["https://127.0.0.1:10250/healthz/syncloop"]; got != "tok-abc-123" {
		t.Fatalf("syncloop probe bearer = %q, want the SA token", got)
	}
}

func TestContainerdSockDownLatches(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.sockErrs[e.h.Cfg.Ctr.Socket] = errors.New("connection refused")
	for i := 0; i < 2; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.h.State.Exists("containerd-sock-down") {
		t.Fatal("state-containerd-sock-down should latch after 2 socket failures")
	}
	e.sockErrs[e.h.Cfg.Ctr.Socket] = nil
	e.h.Cycle(context.Background())
	if e.h.State.Exists("containerd-sock-down") {
		t.Fatal("recovery should clear the containerd-sock latch")
	}
}

// TestContainerdSocketDefaultPinsK0sPath: k0s puts the containerd
// socket at /run/k0s/containerd.sock — the nested
// /run/k0s/containerd/ dir is containerd's state root, NOT the
// socket. Probing inside it is a permanent ENOENT that latches
// containerd-sock-down on every agent start (the A4 bug this
// pins).
func TestContainerdSocketDefaultPinsK0sPath(t *testing.T) {
	c := Config{}
	c.ApplyDefaults()
	if c.Ctr.Socket != "/host/run/k0s/containerd.sock" {
		t.Fatalf("default ContainerdSocket=%q, want /host/run/k0s/containerd.sock",
			c.Ctr.Socket)
	}
	if c.Kubelet.TokenPath != "/var/run/secrets/kubernetes.io/serviceaccount/token" {
		t.Fatalf("default KubeletTokenPath=%q, want the pod SA token path",
			c.Kubelet.TokenPath)
	}
}

// TestProbeUnixSockDefaultReturnsNilOnConnect: a successful dial IS
// the verdict — conn.Close()'s error must not leak into the result.
func TestProbeUnixSockDefaultReturnsNilOnConnect(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "probe.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	c := Config{}
	c.ApplyDefaults()
	if err := c.Seams.ProbeUnixSock(context.Background(), sock, time.Second); err != nil {
		t.Fatalf("successful unix dial want nil, got %v", err)
	}
}

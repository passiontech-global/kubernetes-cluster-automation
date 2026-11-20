package kubelet_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/kubelet"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestStallCheckCancelledCtxAbortsWithoutLatchOrRestart(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Seams.Probe.ProbeHTTPStatus = func(context.Context, string, string, time.Duration) (int, error) {
		return 0, context.Canceled
	}
	e.H.Cfg.Seams.Host.JournalFn = func(context.Context) (string, error) { return "", nil }
	chk := wdepstest.Check[*kubelet.StallCheck](e.H, wdeps.CheckStall)
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true}

	// Pre-cancelled context across 2 cycles.
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	chk.Run(cctx, ce)
	chk.Run(cctx, ce)

	// Also test cancellation occurring mid-probe.
	e.H.Cfg.Seams.Probe.ProbeHTTPStatus = func(pctx context.Context, _ string, _ string, _ time.Duration) (int, error) {
		return 0, errors.New("aborted")
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	e.H.Cfg.Seams.Host.JournalFn = func(context.Context) (string, error) {
		cancel2()
		return "", context.Canceled
	}
	chk.Run(ctx2, ce)

	if chk.Fails != 0 {
		t.Fatalf("Fails=%d want 0 on cancelled ctx", chk.Fails)
	}
	if e.H.State.Exists(latchdefs.LatchKubeletRuntimeStall) {
		t.Fatal("LatchKubeletRuntimeStall armed on cancelled ctx")
	}
	if e.SDRan("restart") {
		t.Fatalf("k0sworker restarted on cancelled ctx: %v", e.SDCmds)
	}
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckStall, "abort")); got != 3 {
		t.Fatalf("abort=%v want 3", got)
	}
}

func TestCtrsockCheckCancelledCtxAbortsWithoutLatchOrRestart(t *testing.T) {
	e := fixture(t)
	chk := wdepstest.Check[*kubelet.CtrsockCheck](e.H, wdeps.CheckCtrSock)
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true}

	// Pre-cancelled ctx.
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.H.Cfg.Seams.Probe.ProbeUnixSock = func(context.Context, string, time.Duration) error {
		return context.Canceled
	}
	chk.Run(cctx, ce)
	chk.Run(cctx, ce)

	// Cancelled during probe.
	ctx2, cancel2 := context.WithCancel(context.Background())
	e.H.Cfg.Seams.Probe.ProbeUnixSock = func(context.Context, string, time.Duration) error {
		cancel2()
		return errors.New("context canceled")
	}
	chk.Run(ctx2, ce)

	if e.H.State.Exists(latchdefs.LatchContainerdSockDown) {
		t.Fatal("LatchContainerdSockDown armed on cancelled ctx")
	}
	if e.SDRan("restart") {
		t.Fatalf("k0sworker restarted on cancelled ctx: %v", e.SDCmds)
	}
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCtrSock, "abort")); got != 3 {
		t.Fatalf("abort=%v want 3", got)
	}
}

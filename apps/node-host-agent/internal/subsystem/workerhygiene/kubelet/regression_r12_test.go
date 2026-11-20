package kubelet_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/kubelet"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestR12KubeletStallCtrTaskRoot0000AbortsWithoutPhantomRestart(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	e := fixture(t)
	for i := 0; i < kubelet.PoddirThreshold; i++ {
		if err := os.MkdirAll(filepath.Join(e.KubepodsDir, fmt.Sprintf("pod%d", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e.MkProc(t, 9001, "S", "", "")
	e.MkTask(t, wdepstest.UIDA, "app", 9001)
	e.SDReply["restart k0sworker.service"] = ""

	if err := os.Chmod(e.CtrDir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(e.CtrDir, 0o755) })

	chk := e.H.Check(wdeps.CheckStall)
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true}
	chk.Run(context.Background(), ce)
	chk.Run(context.Background(), ce)

	if e.SDRan("restart k0sworker.service") {
		t.Fatal("falsely restarted k0sworker on CtrTaskRoot EACCES")
	}
	if e.H.State.Exists(latchdefs.LatchKubeletRuntimeStall) {
		t.Fatal("LatchKubeletRuntimeStall falsely armed on CtrTaskRoot EACCES")
	}
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckStall, "abort")); got != 2 {
		t.Fatalf("abort=%v want 2", got)
	}

	// Restore permissions with live task -> clears cleanly (ok).
	if err := os.Chmod(e.CtrDir, 0o755); err != nil {
		t.Fatal(err)
	}
	chk.Run(context.Background(), ce)
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckStall, "ok")); got != 1 {
		t.Fatalf("ok=%v want 1 after recovery", got)
	}

	// Genuine ENOENT on CtrTaskRoot still triggers phantom-pods ctr=unreachable + restart.
	if err := os.RemoveAll(e.CtrDir); err != nil {
		t.Fatal(err)
	}
	chk.Run(context.Background(), ce)
	chk.Run(context.Background(), ce)
	if !e.H.State.Exists(latchdefs.LatchKubeletRuntimeStall) {
		t.Fatal("LatchKubeletRuntimeStall did not arm on genuine CtrTaskRoot ENOENT")
	}
	if !e.SDRan("restart k0sworker.service") {
		t.Fatal("expected k0sworker restart on genuine CtrTaskRoot ENOENT")
	}
	if !strings.Contains(e.LogLines(t), "ctr=unreachable") {
		t.Fatalf("missing ctr=unreachable log:\n%s", e.LogLines(t))
	}
}

func TestR12KubeletFeederUptimeEACCESFailsClosedAndENOENTPasses(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	e := fixture(t)
	e.SDReply["restart k0sworker.service"] = ""
	e.SDReply["reset-failed k0sworker.service"] = ""
	e.Probes[e.H.Cfg.Kubelet.WdProbeURL] = fmt.Errorf("timeout")
	uptimePath := filepath.Join(e.ProcDir, "uptime")
	wdepstest.WriteFile(t, uptimePath, "7200.5 0\n")
	if err := os.Chmod(uptimePath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(uptimePath, 0o644) })

	f := e.H.Feeder()
	for range wdeps.DefaultKubeletWdMaxFail {
		f.Tick(context.Background())
	}
	if e.SDRan("restart k0sworker.service") {
		t.Fatal("restarted k0sworker when /proc/uptime returned EACCES")
	}
	if !strings.Contains(e.LogLines(t), "SKIP(G1-uptime)") {
		t.Fatalf("expected SKIP(G1-uptime) log, got:\n%s", e.LogLines(t))
	}

	// Restore /proc/uptime permissions -> restart succeeds cleanly.
	if err := os.Chmod(uptimePath, 0o644); err != nil {
		t.Fatal(err)
	}
	e.Now = e.Now.Add(time.Minute)
	for range wdeps.DefaultKubeletWdMaxFail {
		f.Tick(context.Background())
	}
	if !e.SDRan("restart k0sworker.service") {
		t.Fatal("expected restart after /proc/uptime permissions restored")
	}
}

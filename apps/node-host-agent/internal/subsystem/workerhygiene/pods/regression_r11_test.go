package pods_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/pods"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestR11KonnectivityProcUnreadablePreservesLatchAndFails(t *testing.T) {
	t.Run("environ_0000_without_cmdline_agent_id_aborts_and_recovers", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		// proxy-agent cmdline WITHOUT --agent-identifiers=host=, relies on environ NODE_IP.
		e.MkProc(t, 6001, "S", "/proxy-agent\x00--proxy-server-host=1.2.3.4\x00", "NODE_IP=10.9.9.9\x00")
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "6001", "stat"),
			"6001 (proxy-agent) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n")

		e.H.Cycle(context.Background())
		if !e.H.State.Exists(latchdefs.LatchKonnectivityIPMismatch) {
			t.Fatal("setup: LatchKonnectivityIPMismatch not armed")
		}
		chk := wdepstest.Check[*pods.KonnCheck](e.H, wdeps.CheckKonn)
		if chk.Fails != 1 {
			t.Fatalf("setup Fails=%d want 1", chk.Fails)
		}

		envPath := filepath.Join(e.ProcDir, "6001", "environ")
		if err := os.Chmod(envPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(envPath, 0o644) })

		e.H.Cycle(context.Background())
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckKonn, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if !e.H.State.Exists(latchdefs.LatchKonnectivityIPMismatch) {
			t.Fatal("LatchKonnectivityIPMismatch falsely exited when /proc/6001/environ returned 0o000")
		}
		if chk.Fails != 1 {
			t.Fatalf("Fails=%d want preserved 1", chk.Fails)
		}

		// Restore environ with matching nodeIP -> exits latch cleanly.
		if err := os.Chmod(envPath, 0o644); err != nil {
			t.Fatal(err)
		}
		wdepstest.WriteFile(t, envPath, "NODE_IP=10.1.2.3\x00")
		e.H.Cycle(context.Background())
		if e.H.State.Exists(latchdefs.LatchKonnectivityIPMismatch) {
			t.Fatal("LatchKonnectivityIPMismatch did not exit after environ recovery")
		}
	})

	t.Run("cmdline_0000_on_proxy_agent_comm_aborts_and_enoent_clears", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		e.MkProc(t, 6002, "S", "/proxy-agent\x00--proxy-server-host=1.2.3.4\x00", "NODE_IP=10.9.9.9\x00")
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "6002", "stat"),
			"6002 (proxy-agent) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n")

		e.H.Cycle(context.Background())
		if !e.H.State.Exists(latchdefs.LatchKonnectivityIPMismatch) {
			t.Fatal("setup: LatchKonnectivityIPMismatch not armed")
		}
		chk := wdepstest.Check[*pods.KonnCheck](e.H, wdeps.CheckKonn)

		cmdPath := filepath.Join(e.ProcDir, "6002", "cmdline")
		if err := os.Chmod(cmdPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(cmdPath, 0o644) })

		e.H.Cycle(context.Background())
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckKonn, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if !e.H.State.Exists(latchdefs.LatchKonnectivityIPMismatch) {
			t.Fatal("LatchKonnectivityIPMismatch falsely exited when /proc/6002/cmdline returned 0o000")
		}
		if chk.Fails != 1 {
			t.Fatalf("Fails=%d want preserved 1", chk.Fails)
		}

		// Exited PID (ENOENT) exits latch cleanly.
		_ = os.Chmod(cmdPath, 0o644)
		_ = os.RemoveAll(filepath.Join(e.ProcDir, "6002"))
		e.H.Cycle(context.Background())
		if e.H.State.Exists(latchdefs.LatchKonnectivityIPMismatch) {
			t.Fatal("LatchKonnectivityIPMismatch did not exit after PID exited (ENOENT)")
		}
	})
}

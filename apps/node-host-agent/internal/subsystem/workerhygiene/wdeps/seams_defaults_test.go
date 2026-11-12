// seams_defaults_test.go — the nil → production wiring inside
// Seams.applyDefaults: every systemd/kube-dependent default must
// fail cleanly ("no client wired") when Config carries neither,
// and delegate to the REAL client (argv shape verified through the
// exec fake) when one is wired.
package wdeps_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// TestApplyDefaultsNilClients: a zero Config wires every seam to a
// production default that reports "no client wired" instead of
// nil-panicking — the degrade-to-keep contract the checks rely on.
func TestApplyDefaultsNilClients(t *testing.T) {
	var cfg wdeps.Config
	cfg.ApplyDefaults()
	ctx := context.Background()

	for name, call := range map[string]func() error{
		"Ctr.Exec": func() error {
			return cfg.Seams.Ctr.Exec(ctx, "k0s", "ctr")
		},
		"Ctr.ExecOut": func() error {
			_, err := cfg.Seams.Ctr.ExecOut(ctx, "k0s", "ctr")
			return err
		},
		"Host.JournalFn": func() error {
			_, err := cfg.Seams.Host.JournalFn(ctx)
			return err
		},
		"Host.JournalAnyFn": func() error {
			_, err := cfg.Seams.Host.JournalAnyFn(ctx)
			return err
		},
		"Cilium.WGDump": func() error {
			_, err := cfg.Seams.Cilium.WGDump(ctx, nil)
			return err
		},
		"Probe.PodLogFn": func() error {
			_, err := cfg.Seams.Probe.PodLogFn(ctx, "ns", "pod", 1)
			return err
		},
	} {
		err := call()
		if err == nil ||
			!strings.Contains(err.Error(), "no ") ||
			!strings.Contains(err.Error(), "wired") {
			t.Fatalf("%s err=%v want a 'no client wired' failure", name, err)
		}
	}
}

// TestApplyDefaultsSystemdDelegation: with a real systemd.Client
// behind the exec fake, the defaulted seams hand it the argv their
// old hardcoded defaults carried — Ctr's passthrough, the journal
// reads, and the WG dump.
func TestApplyDefaultsSystemdDelegation(t *testing.T) {
	f := testutil.NewFakeExec()
	f.On("leases ls", "LEASE-TABLE\n")
	f.On("journalctl", "JOURNAL-OUT\n")
	f.On("wg show", "WG-DUMP\n")
	sd := systemd.New(systemd.Config{
		HostRoot:       "/",
		RunCmd:         f.Run,
		RunCmdCombined: f.Run,
	})
	var cfg wdeps.Config
	cfg.Systemd = sd
	cfg.ApplyDefaults()
	ctx := context.Background()

	// Ctr.Exec drops stdout; Ctr.ExecOut returns it — both reach
	// sd.Exec as argv[0]+argv[1:].
	if err := cfg.Seams.Ctr.Exec(ctx,
		"k0s", "ctr", "-n", "k8s.io", "leases", "ls"); err != nil {
		t.Fatalf("Ctr.Exec: %v", err)
	}
	if !f.Ran("k0s ctr -n k8s.io leases ls") {
		t.Fatalf("exec log missing ctr argv: %s", f.Joined())
	}
	out, err := cfg.Seams.Ctr.ExecOut(ctx,
		"k0s", "ctr", "-n", "k8s.io", "leases", "ls")
	if err != nil || out != "LEASE-TABLE\n" {
		t.Fatalf("Ctr.ExecOut = %q,%v want canned table", out, err)
	}

	// Host.JournalFn → sd.Journal (unit + -10min window); the
	// AnyFn variant → ExecCombined's journalctl -n 1.
	if out, err = cfg.Seams.Host.JournalFn(ctx); err != nil ||
		out != "JOURNAL-OUT\n" {
		t.Fatalf("JournalFn = %q,%v", out, err)
	}
	if !f.Ran("journalctl -u k0sworker.service") {
		t.Fatalf("journal argv missing unit: %s", f.Joined())
	}
	if out, err = cfg.Seams.Host.JournalAnyFn(ctx); err != nil ||
		out != "JOURNAL-OUT\n" {
		t.Fatalf("JournalAnyFn = %q,%v", out, err)
	}
	if !f.Ran("journalctl -n 1 --no-pager") {
		t.Fatalf("journal-any argv wrong: %s", f.Joined())
	}

	// Cilium.WGDump → sd.Exec("wg","show","cilium_wg0","dump").
	if out, err = cfg.Seams.Cilium.WGDump(ctx, sd); err != nil ||
		out != "WG-DUMP\n" {
		t.Fatalf("WGDump = %q,%v", out, err)
	}
	if !f.Ran("wg show cilium_wg0 dump") {
		t.Fatalf("wg argv wrong: %s", f.Joined())
	}
}

// TestApplyDefaultsPodLogFnDelegation: with a kube client wired the
// PodLogFn default runs the real GetLogs path — the fake clientset
// answers "fake logs" for any pod.
func TestApplyDefaultsPodLogFnDelegation(t *testing.T) {
	var cfg wdeps.Config
	cfg.Client = fake.NewSimpleClientset()
	cfg.ApplyDefaults()
	out, err := cfg.Seams.Probe.PodLogFn(
		context.Background(), "ns", "pod", 5)
	if err != nil {
		t.Fatalf("PodLogFn: %v", err)
	}
	if out != "fake logs" {
		t.Fatalf("PodLogFn = %q want the fake clientset's canned logs", out)
	}
}

// TestTeardownApplyDefaults: the per-domain knob group defaults
// fill zero values and preserve explicit ones — ApplyDefaults is
// the only caller, so drive it through Config.
func TestTeardownApplyDefaults(t *testing.T) {
	var cfg wdeps.Config
	cfg.ApplyDefaults()
	if cfg.Teardown.StuckDeleteAge != 20*time.Minute ||
		cfg.Teardown.StuckWedgeAge != 30*time.Minute ||
		cfg.Teardown.MaxForceDelete != 5 {
		t.Fatalf("teardown defaults = %+v", cfg.Teardown)
	}

	explicit := wdeps.Config{
		Teardown: wdeps.TeardownConfig{
			StuckDeleteAge: time.Hour,
			StuckWedgeAge:  2 * time.Hour,
			MaxForceDelete: 9,
		},
	}
	explicit.ApplyDefaults()
	if explicit.Teardown.StuckDeleteAge != time.Hour ||
		explicit.Teardown.StuckWedgeAge != 2*time.Hour ||
		explicit.Teardown.MaxForceDelete != 9 {
		t.Fatalf("explicit teardown knobs clobbered: %+v",
			explicit.Teardown)
	}
}

// orchestrator_test.go — the remaining orchestrator-surface pieces
// the other parent suites don't drive: the Name/Check/Feeder
// accessors, the feederActive gate, Run's feeder spawn + cycle
// until ctx cancel, and the ConfigFromEnv forwarding alias.
package controllerhygiene

import (
	"context"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

func TestHygieneName(t *testing.T) {
	e := fixture(t)
	if got := e.H.Name(); got != "controllerhygiene" {
		t.Fatalf("Name=%q", got)
	}
}

func TestHygieneCheckLookup(t *testing.T) {
	e := fixture(t)
	if c := e.H.Check(cdeps.CheckOOMLoop); c == nil || c.Name() != "oomloop" {
		t.Fatalf("Check(oomloop)=%v", c)
	}
	if c := e.H.Check(cdeps.CheckKineStorage); c == nil ||
		c.Name() != cdeps.CheckKineStorage {
		t.Fatalf("Check(kine-storage)=%v", c)
	}
	if c := e.H.Check("no-such-check"); c != nil {
		t.Fatalf("unknown name returned %v", c)
	}
}

func TestHygieneFeederAccessor(t *testing.T) {
	e := fixture(t)
	if e.H.Feeder() == nil {
		t.Fatal("Feeder()=nil after New")
	}
}

func TestFeederActiveGate(t *testing.T) {
	e := fixture(t)
	fn := func(string) error { return nil }

	e.H.Cfg.Feeder.Enabled = false
	e.H.Cfg.NotifyFn = nil
	if e.H.feederActive() {
		t.Fatal("active with feeder disabled and no notify seam")
	}
	e.H.Cfg.Feeder.Enabled = true
	if e.H.feederActive() {
		t.Fatal("active without any notify path")
	}
	e.H.Cfg.NotifyFn = fn
	if !e.H.feederActive() {
		t.Fatal("inactive with feeder enabled and a notify seam")
	}
	e.H.Cfg.Feeder.Enabled = false
	if e.H.feederActive() {
		t.Fatal("active with only a notify seam")
	}
}

// Run starts the feeder goroutine (feeds WATCHDOG=1 while the
// apiserver probe answers) and cycles until ctx cancel.
func TestRunFeedsAndCyclesUntilCancel(t *testing.T) {
	e := fixture(t)
	e.Props["k0scontroller.service:MainPID"] = "123"
	e.Alive["https://127.0.0.1:6443/readyz"] = true
	e.H.Cfg.Feeder.Enabled = true // NotifyFn is already bound by Bind

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		e.H.Run(ctx)
		close(done)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && e.NotifN() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if e.NotifN() == 0 {
		t.Fatal("feeder never fed WATCHDOG=1")
	}
	if got := e.NotifAt(0); got != "WATCHDOG=1" {
		t.Fatalf("notify=%q want WATCHDOG=1", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

func TestConfigFromEnvForwarding(t *testing.T) {
	cfg := ConfigFromEnv(EnvDeps{})
	if cfg.Interval != 60*time.Second {
		t.Fatalf("Interval=%s want the 60s default", cfg.Interval)
	}
	if cfg.K0sControllerUnitFile != "/etc/systemd/system/k0scontroller.service" {
		t.Fatalf("K0sControllerUnitFile=%s want the identity-joined default",
			cfg.K0sControllerUnitFile)
	}
}

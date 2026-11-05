package testutil

import (
	"context"
	"errors"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

// periodicSetup is a minimal well-behaved module Setup — registers
// one Periodic under d.Name when enabled, no-ops when Disabled. The
// shape PeriodicContract exists to verify.
func periodicSetup(d shared.Deps) error {
	if d.Disabled {
		return nil
	}
	return shared.AddPeriodic(d.Mgr, d.Name, time.Minute,
		func(context.Context) error { return nil })
}

// A conforming Setup passes the full contract with base Deps
// carrying only the name — no client fakes needed when the module
// doesn't touch them.
func TestPeriodicContract(t *testing.T) {
	PeriodicContract(t, periodicSetup,
		shared.Deps{Name: "test-mod"}, "test-mod", time.Minute)
}

// The same conforming Setup's disabled half passes DisabledNoop
// standalone.
func TestDisabledNoop(t *testing.T) {
	DisabledNoop(t, periodicSetup, shared.Deps{Name: "test-mod"})
}

// csSetup proves the helpers forward base Deps fields they don't
// own (CS here) — the module only registers when the clientset the
// caller threaded through base actually arrives.
func csSetup(d shared.Deps) error {
	if d.Disabled {
		return nil
	}
	if d.CS == nil {
		return errors.New("setup saw nil clientset")
	}
	return shared.AddPeriodic(d.Mgr, d.Name, 5*time.Minute,
		func(context.Context) error { return nil })
}

func TestPeriodicContractForwardsBaseDeps(t *testing.T) {
	PeriodicContract(t, csSetup, shared.Deps{
		Name: "cs-mod",
		CS:   fake.NewSimpleClientset(),
	}, "cs-mod", 5*time.Minute)
}

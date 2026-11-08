// harness.go — the shared test prober every check-domain package's
// harness_test.go wraps: Prober (the shared Deps plus the package's
// check instances built once against them — mirroring the root
// prober's one-instance-per-check construction so per-check state
// persists across driven runs exactly as in production), the
// MustCheck registry lookup and the FirstSeenLedger keyspace dump.
package probetest

import (
	"testing"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// Prober is the test-side prober stand-in: the shared Deps plus the
// check instances built once against them. Field accesses on the
// embedded Deps (p.Cfg, p.Now, p.Dyn, ...) keep working exactly like
// the per-package prober structs it replaces.
type Prober struct {
	*probefw.Deps
	Checks []probefw.Check
}

// NewCheckProber builds the shared Deps (via NewDeps, with a nil dyn
// defaulting to the OpDyn fake — the shape testProber always
// hand-rolled), then constructs one check per factory against them —
// the same func(*Deps) Check shape the registry's CheckReg rows
// carry, so each domain package passes its own NewXxxCheck
// constructors verbatim.
func NewCheckProber(cs kubernetes.Interface, dyn dynamic.Interface,
	factories ...func(*probefw.Deps) probefw.Check) *Prober {
	if dyn == nil {
		dyn = OpDyn()
	}
	d := NewDeps(cs, dyn)
	p := &Prober{Deps: d}
	for _, f := range factories {
		p.Checks = append(p.Checks, f(d))
	}
	return p
}

// MustCheck locates the registered check instance of type T — tests
// that drive one check directly or poke its state ledgers look the
// instance up here (exactly one check of each type is registered).
func MustCheck[T probefw.Check](t *testing.T, p *Prober) T {
	t.Helper()
	for _, c := range p.Checks {
		if chk, ok := c.(T); ok {
			return chk
		}
	}
	t.Fatalf("no registered check of the wanted type")
	var zero T
	return zero
}

// LedgerKeys reports the keys a FirstSeenLedger currently holds —
// the ledger's keyspace is intentionally unexported, so tests read
// membership through a keep-all Prune.
func LedgerKeys(l *state.FirstSeenLedger) []string {
	var keys []string
	l.Prune(func(k string) bool { keys = append(keys, k); return true })
	return keys
}

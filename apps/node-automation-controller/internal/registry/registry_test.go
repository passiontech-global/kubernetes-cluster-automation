package registry

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---- ProbeClients routing --------------------------------------------
//
// Latency-sensitive probe rows (Module.ProbeClients) swap the boot
// Deps' ProbeCS/ProbeDyn in as CS/Dyn before Setup runs — the module
// code still reads d.CS/d.Dyn, it just draws from the probe token
// bucket. Rows without the flag keep the shared clients; a Deps
// without ProbeCS (tests, StubManager wiring) leaves everything
// shared.
func TestSetupModulesProbeClientRouting(t *testing.T) {
	probeCS := fake.NewSimpleClientset()
	probeDyn := testutil.StubDyn()
	sharedCS := fake.NewSimpleClientset()

	type captured struct{ cs, dyn any }
	got := map[string]captured{}
	capture := func(name string) func(shared.Deps) error {
		return func(d shared.Deps) error {
			got[name] = captured{d.CS, d.Dyn}
			return nil
		}
	}
	deps := testDeps(testutil.NewStubManager())
	deps.CS, deps.ProbeCS, deps.ProbeDyn = sharedCS, probeCS, probeDyn

	if err := SetupModules(deps, []shared.Module{
		{Name: "kubelet-liveness-reaper", ProbeClients: true,
			Setup: capture("kubelet-liveness-reaper")},
		{Name: "partition-pod-evictor", Setup: capture("partition-pod-evictor")},
	}); err != nil {
		t.Fatalf("SetupModules: %v", err)
	}
	if got["kubelet-liveness-reaper"].cs != probeCS ||
		got["kubelet-liveness-reaper"].dyn != probeDyn {
		t.Fatalf("probe row got CS=%T Dyn=%T — SetupModules must hand "+
			"the probe clients in as CS/Dyn",
			got["kubelet-liveness-reaper"].cs, got["kubelet-liveness-reaper"].dyn)
	}
	if got["partition-pod-evictor"].cs != sharedCS {
		t.Fatalf("plain row got CS=%T — non-probe rows must keep the shared clientset",
			got["partition-pod-evictor"].cs)
	}

	// Nil ProbeCS (literal test Deps) leaves the shared clients.
	deps.ProbeCS, deps.ProbeDyn = nil, nil
	clear(got)
	if err := SetupModules(deps, []shared.Module{
		{Name: "dead-node-sweeper", ProbeClients: true,
			Setup: capture("dead-node-sweeper")},
	}); err != nil {
		t.Fatalf("SetupModules: %v", err)
	}
	if got["dead-node-sweeper"].cs != sharedCS {
		t.Fatalf("probe row with nil ProbeCS got CS=%T, want the shared fallback",
			got["dead-node-sweeper"].cs)
	}
}

// ---- SetupModules ----------------------------------------------------
//
// Registration gates live on the shared.Module rows — SetupModules
// resolves each GateEnv and stamps Deps.Disabled before calling Setup,
// so these tests drive the whole fleet through t.Setenv + a
// shared.Deps exactly like boot does.

// moduleGateEnvs derives the registration-gate env vars from the
// registry itself — a hand-maintained list could drift from modules
// silently. Setting every GateEnv "true" enables every gate (opt-in
// and default-on alike); "false" disables them all. Sub-feature gates
// (CSR_APPROVER_ENABLED, HELM_STALL_UNWEDGE_ENABLED, ...) are
// deliberately absent — they alter run behavior, not runnable counts.
func moduleGateEnvs() []string {
	var envs []string
	for _, m := range Modules {
		if m.GateEnv != "" {
			envs = append(envs, m.GateEnv)
		}
	}
	return envs
}

// The registry is the contract every other piece keys on: names must
// be non-empty and unique (they label metric series and boot logs —
// a dup would merge two modules' error accounting), every row must
// carry a known Group (a typo'd group string would silently shrink a
// `-modules @group` expansion — the constants are unexported so only
// this file can mint one) and every row must carry a Setup or a
// CheckReg — a row with neither would be dead weight at boot. The
// exactly-one-of-the-two shape is asserted in
// checkreg_contract_test.go.
func TestModuleRegistry(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range Modules {
		if m.Name == "" {
			t.Fatal("module row with empty Name")
		}
		if seen[m.Name] {
			t.Fatalf("duplicate module name %q", m.Name)
		}
		seen[m.Name] = true
		switch m.Group {
		case groupSystem, groupNode, groupAPIServer,
			groupJanitors, groupIntegration, groupHealth:
		default:
			t.Fatalf("module %q has unknown Group %q", m.Name, m.Group)
		}
		if m.Setup == nil && m.CheckReg == nil {
			t.Fatalf("module %q has neither Setup nor CheckReg", m.Name)
		}
	}
}

func testDeps(m *testutil.StubManager) shared.Deps {
	return shared.Deps{
		Mgr: m,
		CS:  fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn(),
		Log: m.GetLogger(),
	}
}

// FilterModules is the -modules allowlist: unset means the full
// registry; a set value returns exactly the selected modules in
// registry order regardless of argv order — entries are ops names or
// "@<group>" selectors that expand to a whole registry section;
// an unknown name or @group is an error that names the offender plus
// the valid names and groups (fail fast — a silently skipped typo
// would run the wrong subset).
func TestFilterModules(t *testing.T) {
	moduleNames := func(mods []shared.Module) []string {
		var names []string
		for _, m := range mods {
			names = append(names, m.Name)
		}
		return names
	}

	t.Run("empty means full registry", func(t *testing.T) {
		got, err := FilterModules(nil)
		if err != nil {
			t.Fatalf("FilterModules(nil): %v", err)
		}
		if len(got) != len(Modules) {
			t.Fatalf("got %d modules, want all %d", len(got), len(Modules))
		}
		for i := range got {
			if got[i].Name != Modules[i].Name {
				t.Fatalf("got[%d] = %q, want %q", i, got[i].Name, Modules[i].Name)
			}
		}
	})

	t.Run("subset keeps registry order", func(t *testing.T) {
		// argv order reversed vs the registry — the result must still
		// follow the registry so boot order stays deterministic.
		got, err := FilterModules([]string{"csr-watcher", "node-labeler"})
		if err != nil {
			t.Fatalf("FilterModules: %v", err)
		}
		if want := []string{"node-labeler", "csr-watcher"}; !slices.Equal(moduleNames(got), want) {
			t.Fatalf("names = %v, want %v", moduleNames(got), want)
		}
	})

	t.Run("@group expands in registry order", func(t *testing.T) {
		got, err := FilterModules([]string{"@apiserver"})
		if err != nil {
			t.Fatalf("FilterModules: %v", err)
		}
		want := []string{
			"admission-webhook-guard",
			"apiserver-endpoint-guard",
			"apiservice-guard",
		}
		if !slices.Equal(moduleNames(got), want) {
			t.Fatalf("names = %v, want %v", moduleNames(got), want)
		}
	})

	t.Run("mixed names and @groups dedupe", func(t *testing.T) {
		// "@apiserver" already covers apiservice-guard and the argv
		// repeats it by name plus the group itself — the result must
		// hold each module exactly once, in registry order.
		got, err := FilterModules([]string{
			"cluster-health-probes", "@apiserver",
			"apiservice-guard", "@apiserver",
		})
		if err != nil {
			t.Fatalf("FilterModules: %v", err)
		}
		want := []string{
			"admission-webhook-guard",
			"apiserver-endpoint-guard",
			"apiservice-guard",
			"cluster-health-probes",
		}
		if !slices.Equal(moduleNames(got), want) {
			t.Fatalf("names = %v, want %v", moduleNames(got), want)
		}
	})

	t.Run("every group expands to its stamped rows", func(t *testing.T) {
		// Cross-check the @-selectors against the Group stamps: each
		// group's expansion must be exactly the rows carrying it.
		for _, g := range []string{
			"system", "node", "apiserver", "janitors", "integration", "health",
		} {
			got, err := FilterModules([]string{"@" + g})
			if err != nil {
				t.Fatalf("FilterModules(@%s): %v", g, err)
			}
			var want []string
			for _, m := range Modules {
				if m.Group == g {
					want = append(want, m.Name)
				}
			}
			if !slices.Equal(moduleNames(got), want) {
				t.Fatalf("@%s = %v, want %v", g, moduleNames(got), want)
			}
		}
	})

	t.Run("unknown name fails", func(t *testing.T) {
		_, err := FilterModules([]string{"node-labeler", "no-such-module"})
		if err == nil {
			t.Fatal("FilterModules accepted an unknown name")
		}
		if !strings.Contains(err.Error(), "no-such-module") {
			t.Fatalf("error missing the bad name: %v", err)
		}
		if !strings.Contains(err.Error(), "node-labeler") {
			t.Fatalf("error missing the valid-name list: %v", err)
		}
	})

	t.Run("unknown @group fails and lists valid groups", func(t *testing.T) {
		_, err := FilterModules([]string{"node-labeler", "@bogus"})
		if err == nil {
			t.Fatal("FilterModules accepted an unknown @group")
		}
		if !strings.Contains(err.Error(), "@bogus") {
			t.Fatalf("error missing the bad @group: %v", err)
		}
		for _, g := range []string{
			"@system", "@node", "@apiserver",
			"@janitors", "@integration", "@health",
		} {
			if !strings.Contains(err.Error(), g) {
				t.Fatalf("error missing valid group %q: %v", g, err)
			}
		}
	})

	t.Run("bare @ matches nothing", func(t *testing.T) {
		// "@" is the empty-group lookup — no module may carry it, so
		// it must surface as an offender like any other typo.
		_, err := FilterModules([]string{"@"})
		if err == nil {
			t.Fatal("FilterModules accepted a bare @")
		}
		if !strings.Contains(err.Error(), "@") {
			t.Fatalf("error missing the bad entry: %v", err)
		}
	})
}

// ParseModulesFlag is whitespace-tolerant and drops empty entries —
// " a, ,b " is exactly ["a","b"], and an all-whitespace value is
// "unset" rather than a bogus name.
func TestParseModulesFlag(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"  ", nil},
		{"a", []string{"a"}},
		{"a,b", []string{"a", "b"}},
		{" a , b,", []string{"a", "b"}},
	} {
		if got := ParseModulesFlag(tc.in); !slices.Equal(got, tc.want) {
			t.Fatalf("ParseModulesFlag(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// Every runnable module registers exactly one runnable on the
// manager — 32 runnable rows in the 84-row registry (the 52 health
// CheckReg rows contribute checks to the sweep roster, not
// runnables) — except the gate-skippers, which SetupModules hands
// Deps.Disabled and which then skip mgr.Add entirely. Modules whose
// flag only gates the tick body (csr-watcher approve mode,
// helmrelease-unlocker stall-unwedge,
// webhookguard, and the no-gate always-on modules) still register.
func TestSetupModules(t *testing.T) {
	t.Run("all gates enabled", func(t *testing.T) {
		for _, k := range moduleGateEnvs() {
			t.Setenv(k, "true")
		}
		t.Setenv("NODE_LABELER_CONFIG_PATH",
			filepath.Join(t.TempDir(), "labels.txt"))
		m := testutil.NewStubManager()
		if err := SetupModules(testDeps(m), Modules); err != nil {
			t.Fatalf("SetupModules: %v", err)
		}
		if len(m.Added) != 32 {
			t.Fatalf("registered %d runnables, want 32", len(m.Added))
		}
		for i, r := range m.Added {
			if r == nil {
				t.Fatalf("runnable %d is nil", i)
			}
		}
	})

	t.Run("all gates disabled", func(t *testing.T) {
		for _, k := range moduleGateEnvs() {
			t.Setenv(k, "false")
		}
		m := testutil.NewStubManager()
		if err := SetupModules(testDeps(m), Modules); err != nil {
			t.Fatalf("SetupModules: %v", err)
		}
		// 32 runnable rows minus the 18 gate-skippers = 14 runnables
		// (the 52 CheckReg rows register nothing regardless).
		if len(m.Added) != 14 {
			t.Fatalf("registered %d runnables, want 14", len(m.Added))
		}
	})

	// The -modules allowlist narrows what Setup runs: two gateless
	// always-on modules → exactly two runnables, no matter what the
	// gate envs say.
	t.Run("allowlist subset", func(t *testing.T) {
		mods, err := FilterModules([]string{"node-labeler", "csr-watcher"})
		if err != nil {
			t.Fatalf("FilterModules: %v", err)
		}
		m := testutil.NewStubManager()
		if err := SetupModules(testDeps(m), mods); err != nil {
			t.Fatalf("SetupModules: %v", err)
		}
		if len(m.Added) != 2 {
			t.Fatalf("registered %d runnables, want 2", len(m.Added))
		}
	})
}

// A manager.Add failure must abort boot — SetupModules propagates the
// first setup error instead of silently losing a module.
func TestSetupModulesErrorPropagates(t *testing.T) {
	want := errors.New("manager rejected runnable")
	m := testutil.NewStubManager()
	m.AddErr = want
	err := SetupModules(testDeps(m), Modules)
	if !errors.Is(err, want) {
		t.Fatalf("SetupModules error = %v, want %v", err, want)
	}
	if len(m.Added) != 0 {
		t.Fatalf("registered %d runnables, want 0", len(m.Added))
	}
}

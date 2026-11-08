// checkreg_contract_test.go — the CheckReg row contract, proven
// against the live Modules table rather than a hand-maintained list:
// every row carries exactly one of Setup/CheckReg, every CheckReg has
// a non-empty Name (it becomes the kuberhealthy_check label value —
// ops contract) and a New that type-asserts to the sweep's
// constructor shape. shared stores New as `any` because it cannot
// name internal/health/probefw (import cycle + depguard) — this test
// is the compile-time-shape stand-in, so a mistyped registration
// fails HERE, at test time, instead of at some later boot.
package registry

import (
	"slices"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// TestCheckRegContract walks every registry row: exactly one of
// Setup/CheckReg is set, and CheckReg rows are well-formed for the
// sweep that consumes them.
func TestCheckRegContract(t *testing.T) {
	for _, m := range Modules {
		t.Run(m.Name, func(t *testing.T) {
			switch {
			case m.Setup == nil && m.CheckReg == nil:
				t.Fatal("row has neither Setup nor CheckReg")
			case m.Setup != nil && m.CheckReg != nil:
				t.Fatal("row has both Setup and CheckReg — exactly one allowed")
			}
			if m.CheckReg == nil {
				return
			}
			if m.CheckReg.Name == "" {
				t.Fatal("CheckReg.Name is empty — it becomes the kuberhealthy_check label value")
			}
			// The row's module name doubles as the check name:
			// -modules selects checks by their kuberhealthy_check
			// label value and the predeclared queue series labels
			// match what an operator greps for — a row named
			// differently from its check would split that identity
			// for no gain.
			if m.Name != m.CheckReg.Name {
				t.Fatalf("module name %q != CheckReg.Name %q — check rows are named after the check",
					m.Name, m.CheckReg.Name)
			}
			if _, ok := m.CheckReg.New.(func(*probefw.Deps) probefw.Check); !ok {
				t.Fatalf("CheckReg.New is %T, want func(*probefw.Deps) probefw.Check",
					m.CheckReg.New)
			}
		})
	}
}

// TestCheckRegSweepOrder pins the check roster order — the relative
// order of the health section's CheckReg rows in Modules is the
// cluster-health-probes sweep order verbatim (SetupModules collects
// in registry order), and that order is the ops contract the
// kuberhealthy checker Pods established. A reorder here reorders
// the sweep; this list is the migration-time checkDefs sequence
// kept as the explicit contract.
func TestCheckRegSweepOrder(t *testing.T) {
	want := []string{
		"dns-status-internal",
		"http-content-check",
		"pod-restarts",
		"pod-status-check",
		"resource-quota-check",
		"kcm-workqueue-watchdog",
		"operator-workqueue-watchdog",
		"stateful-masterless-services",
		"rabbitmq-suspended-listener",
		"localpv-stranded-pods",
		"olm-subscription-health",
		"scheduler-watchdog",
		"mesh-controlplane-watchdog",
		"node-hang-precordon",
		"linkerd-endpoint-sync",
		"scylla-cluster-health",
		"flux-helmrelease-retries",
		"percona-cluster-quorum",
		"cilium-bpf-map-pressure",
		"linkerd-protocol-detection-stall",
		"coredns-upstream",
		"cilium-node-ipam-exhaustion",
		"namespace-terminating-wedged",
		"argocd-app-stuck",
		"kargo-promotion-health",
		"rabbitmq-quorum-health",
		"dragonfly-replica-sync-storm",
		"image-pull-storm",
		"api-object-sprawl-report-gc",
		"cpu-steal-taint-sync",
		"cilium-missing-endpoint",
		"linkerd-h2-stream-guard",
		"cloudflared-tunnel-health",
		"liqo-tunnel-health",
		"konnectivity-tunnel-health",
		"postgres-wal-archive-guard",
		"scylla-compaction-schema-guard",
		"nats-jetstream-health",
		"keda-scaledobject-guard",
		"gateway-route-health",
		"controller-lease-guard",
		"pvc-resize-stall-guard",
		"endpointslice-zone-starvation",
		"linkerd-outlier-guard",
		"node-condition-sweeper",
		"onepassword-connect-sync-probe",
		"linkerd-sidecar-oom-guard",
		"cilium-datapath-map-guard",
		"cilium-l2-lease-guard",
		"observability-pipeline-guard",
		// The three gated gitops rows close out the roster —
		// they landed after the always-on sequence when checks first
		// became registry rows, so they stay last.
		"flux-kustomization-health",
		"workload-scale-flapping",
		"imagepull-secret-auditor",
		// W16-G3 — the argocd-agent spin healer is the newest row.
		"argocd-agent-spin",
	}
	var got []string
	for _, m := range Modules {
		if m.CheckReg != nil {
			got = append(got, m.CheckReg.Name)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("CheckReg sweep order = %v,\nwant %v", got, want)
	}
}

// TestSetupModulesCheckRegGate drives SetupModules over a synthetic
// CheckReg row plus a spy module that captures the Deps it was
// handed: a gated-off check row contributes nothing to
// Deps.CheckRegs (the roster never sees the check), an enabled one
// contributes exactly its registration.
func TestSetupModulesCheckRegGate(t *testing.T) {
	checkRow := shared.Module{
		Name:      "spy-check",
		GateEnv:   "TEST_CHECKREG_GATE",
		DefaultOn: true,
		CheckReg: &shared.CheckReg{
			Name: "spy-check",
			New:  func(*probefw.Deps) probefw.Check { return nil },
		},
	}
	var got []shared.CheckReg
	spy := shared.Module{
		Name: "checkreg-spy",
		Setup: func(d shared.Deps) error {
			got = d.CheckRegs
			return nil
		},
	}

	t.Run("gated off contributes nothing", func(t *testing.T) {
		t.Setenv("TEST_CHECKREG_GATE", "false")
		got = nil
		m := testutil.NewStubManager()
		if err := SetupModules(testDeps(m), []shared.Module{checkRow, spy}); err != nil {
			t.Fatalf("SetupModules: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("gated-off check row contributed %d regs, want 0", len(got))
		}
	})

	t.Run("enabled contributes its reg", func(t *testing.T) {
		t.Setenv("TEST_CHECKREG_GATE", "true")
		got = nil
		m := testutil.NewStubManager()
		if err := SetupModules(testDeps(m), []shared.Module{checkRow, spy}); err != nil {
			t.Fatalf("SetupModules: %v", err)
		}
		if len(got) != 1 || got[0].Name != "spy-check" {
			t.Fatalf("CheckRegs = %+v, want exactly the spy-check reg", got)
		}
	})
}
